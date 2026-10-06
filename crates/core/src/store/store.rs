use std::collections::HashMap;
use std::sync::Arc;
use roaring::RoaringBitmap;
use crate::model::IndexedRecord;
use crate::store::blob_store::BlobStore;
use crate::s3::S3EventData;
use rayon::prelude::*;
use crate::ingest::{decompress::{read_log_file, for_each_zip_entry}, parser::parse_records};
use crate::error::{CoreError, IngestWarning};
use std::path::Path;

/// Progress event emitted during ingestion
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressEvent {
    pub files_total: usize,
    pub files_done: usize,
    pub records_total: usize,
}

/// String pool for deduplicating repeated field values across all records.
/// Instead of storing "us-east-1" 500_000 times, we store one Arc<str> shared by all.
/// pub(crate) so model.rs can call intern() on CloudTrailRecord fields.
pub(crate) struct StringPool {
    pool: HashMap<Box<str>, Arc<str>>,
}

impl StringPool {
    pub(crate) fn new() -> Self { Self { pool: HashMap::new() } }

    pub(crate) fn intern(&mut self, s: &str) -> Arc<str> {
        if let Some(arc) = self.pool.get(s) {
            return Arc::clone(arc);
        }
        let arc: Arc<str> = Arc::from(s);
        self.pool.insert(s.into(), Arc::clone(&arc));
        arc
    }
}

/// The two requestParameters fields ingestion needs for S3 events. Everything else is ignored.
#[derive(serde::Deserialize)]
struct S3Params<'a> {
    #[serde(rename = "bucketName", borrow, default)]
    bucket_name: Option<std::borrow::Cow<'a, str>>,
    #[serde(borrow, default)]
    key: Option<std::borrow::Cow<'a, str>>,
}

/// GetObject's additionalEventData: only the bytes-out count is read.
#[derive(serde::Deserialize)]
struct S3AdditionalData {
    #[serde(rename = "bytesTransferredOut", default)]
    bytes_transferred_out: Option<serde_json::Number>,
}

pub struct Store {
    pub records: Vec<IndexedRecord>,
    pub file_paths: Vec<String>,

    // Inverted indexes: interned field_value → RoaringBitmap of record ids.
    // Compressed bitmaps shrink dense/high-cardinality posting lists vs Vec<u32>
    // and give native SIMD AND/OR/NOT for the query engine.
    pub idx_event_name: HashMap<Arc<str>, RoaringBitmap>,
    pub idx_event_source: HashMap<Arc<str>, RoaringBitmap>,
    pub idx_region: HashMap<Arc<str>, RoaringBitmap>,
    pub idx_source_ip: HashMap<Arc<str>, RoaringBitmap>,
    pub idx_user_arn: HashMap<Arc<str>, RoaringBitmap>,
    pub idx_user_name: HashMap<Arc<str>, RoaringBitmap>,
    pub idx_account_id: HashMap<Arc<str>, RoaringBitmap>,
    pub idx_error_code: HashMap<Arc<str>, RoaringBitmap>,
    pub idx_identity_type: HashMap<Arc<str>, RoaringBitmap>,
    pub idx_user_agent: HashMap<Arc<str>, RoaringBitmap>,
    pub idx_bucket_name: HashMap<Arc<str>, RoaringBitmap>,

    /// Per-event S3 data extracted at ingestion time (GetObject events only).
    /// Keyed by record ID. Enables zero-blob-read aggregation in get_s3_summary.
    pub s3_event_index: HashMap<u32, S3EventData>,

    // Sorted by timestamp for range queries
    pub time_sorted_ids: Vec<u32>,

    /// JSON blob storage — requestParameters, responseElements, additionalEventData
    /// are offloaded here during ingestion to save ~1.8 GB RAM for 5M events.
    pub blob_store: BlobStore,
}

impl Store {
    pub fn new() -> Self {
        Store {
            records: Vec::new(),
            file_paths: Vec::new(),
            idx_event_name: HashMap::new(),
            idx_event_source: HashMap::new(),
            idx_region: HashMap::new(),
            idx_source_ip: HashMap::new(),
            idx_user_arn: HashMap::new(),
            idx_user_name: HashMap::new(),
            idx_account_id: HashMap::new(),
            idx_error_code: HashMap::new(),
            idx_identity_type: HashMap::new(),
            idx_user_agent: HashMap::new(),
            idx_bucket_name: HashMap::new(),
            s3_event_index: HashMap::new(),
            time_sorted_ids: Vec::new(),
            blob_store: BlobStore::new().expect("failed to create blob store temp file"),
        }
    }

    /// Insert a record ID into an inverted index under the given interned key.
    fn index_push_arc(idx: &mut HashMap<Arc<str>, RoaringBitmap>, key: Arc<str>, id: u32) {
        idx.entry(key).or_default().insert(id);
    }

    /// Load all log files from a directory, processing in parallel.
    /// Calls `on_progress` callback after each file is processed.
    /// Returns `(records_loaded, warnings)` — file-level errors are collected as
    /// non-fatal warnings so a single corrupt file does not abort the whole batch.
    pub fn load_directory<F>(
        &mut self,
        root: &Path,
        on_progress: F,
    ) -> Result<(usize, Vec<IngestWarning>), CoreError>
    where
        F: Fn(ProgressEvent) + Send + Sync,
    {
        let paths = crate::ingest::discovery::find_log_files(root);
        let files_total = paths.len();

        // Producer/consumer pipeline. Files are parsed in parallel and streamed
        // through a bounded channel; only ~`bound` in-flight batches (with their
        // still-inline JSON blobs) are resident at once. This caps peak RAM
        // instead of collecting every parsed record — blobs and all — into one
        // giant Vec before the blob-draining ingest phase even begins.
        //
        // Each message carries: (path_str, source_file_idx, records, optional "records skipped" note).
        // ZIP files produce multiple batches — one per inner entry — all
        // attributed to the same source file index so the path table stays compact.
        // The error side carries the source file index so a failure is attributed to its file even
        // when that file (a ZIP) has already produced other messages.
        type IngestMsg = Result<(String, u32, Vec<IndexedRecord>, Option<String>), (u32, CoreError)>;
        let bound = (rayon::current_num_threads() * 4).max(8);
        let (tx, rx) = std::sync::mpsc::sync_channel::<IngestMsg>(bound);

        // Sequential ingest into store (indexes must be built single-threaded)
        let mut pool = StringPool::new();
        let mut total_records = 0usize;
        let mut files_done = 0usize;
        // A ZIP sends one message per inner entry; a file counts as done once, on its first message.
        let mut files_seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
        let mut warnings: Vec<IngestWarning> = Vec::new();

        std::thread::scope(|scope| {
            // Producer: parse files in parallel, stream batches into the channel.
            scope.spawn(move || {
                paths.par_iter().enumerate().for_each(|(file_idx, path)| {
                    let path_str = path.to_string_lossy().into_owned();
                    let src_idx = file_idx as u32;

                    let is_zip = path
                        .extension()
                        .and_then(|e| e.to_str())
                        .map(|e| e.eq_ignore_ascii_case("zip"))
                        .unwrap_or(false);

                    if is_zip {
                        // Entries are inflated and sent one at a time, so memory is bounded by
                        // the largest entry and the bounded channel actually applies back-pressure.
                        let visited = for_each_zip_entry(path, |bytes| {
                            let msg = parse_records(&bytes, path, src_idx, 0)
                                .map(|p| { let note = p.skip_note(); (path_str.clone(), src_idx, p.records, note) })
                                .map_err(|e| (src_idx, e));
                            if tx.send(msg).is_err() {
                                std::ops::ControlFlow::Break(())
                            } else {
                                std::ops::ControlFlow::Continue(())
                            }
                        });
                        if let Err(e) = visited {
                            let _ = tx.send(Err((src_idx, e)));
                        }
                        // A zip with no matching entries sends nothing above, so without this the
                        // file would never be counted and the bar would stall short of 100%.
                        let _ = tx.send(Ok((path_str.clone(), src_idx, Vec::new(), None)));
                    } else {
                        match read_log_file(path) {
                            Ok(bytes) => {
                                let _ = tx.send(
                                    parse_records(&bytes, path, src_idx, 0)
                                        .map(|p| { let note = p.skip_note(); (path_str, src_idx, p.records, note) })
                                        .map_err(|e| (src_idx, e)),
                                );
                            }
                            Err(e) => {
                                let _ = tx.send(Err((src_idx, e)));
                            }
                        }
                    }
                });
                // `tx` is dropped here → the consumer's `rx` loop terminates.
            });

            // Consumer (this thread): single-threaded ingest keeps ids monotonic,
            // so every posting list stays sorted ascending by id.
            for result in rx {
            let (path_str, src_idx, mut batch, skip_note) = match result {
                Ok(v) => v,
                Err((err_idx, e)) => {
                    // Extract the file path from the error for the warning message
                    let file = match &e {
                        CoreError::Io { path, .. } => Some(path.clone()),
                        CoreError::PermissionDenied { path } => Some(path.clone()),
                        CoreError::Json { path, .. } => Some(path.clone()),
                        CoreError::CorruptGzip { path, .. } => Some(path.clone()),
                        _ => None,
                    };
                    warnings.push(IngestWarning { message: e.to_string(), file });
                    if files_seen.insert(err_idx) {
                        files_done += 1;
                    }
                    on_progress(ProgressEvent { files_total, files_done, records_total: total_records });
                    continue;
                }
            };
            let file_idx = src_idx as usize;

            // Ensure file path is registered
            while self.file_paths.len() <= file_idx {
                self.file_paths.push(String::new());
            }
            if let Some(message) = skip_note {
                warnings.push(IngestWarning { message, file: Some(path_str.clone()) });
            }
            self.file_paths[file_idx] = path_str;

            // Reassign IDs sequentially
            let base_id = self.records.len() as u32;
            for (i, rec) in batch.iter_mut().enumerate() {
                rec.id = base_id + i as u32;
            }

            // Intern record string fields, drain blob fields to BlobStore, and build indexes.
            // After interning, the record's Arc<str> fields and the index keys
            // share the same Arc heap allocation — one alloc per unique value.
            for rec in batch.iter_mut() {
                // Intern all Arc<str> fields on the record (replaces with pooled Arcs)
                rec.record.intern(&mut pool);

                // Extract bucket name BEFORE draining request_parameters to blob store,
                // so we avoid a disk read-back during ingestion.
                // For GetObject events also extract the object key and bytes transferred out.
                // Only S3 events carry a bucket, so only they are parsed. This loop is the serial
                // bottleneck of ingestion; building a full `serde_json::Value` tree for every
                // record's requestParameters (200 B to 2 KB each) cost more than the interning and
                // indexing combined. Two borrowed fields are enough, and `Cow` keeps strings with
                // escape sequences working.
                let s3_params: Option<S3Params> = if rec.record.event_source.as_ref() == "s3.amazonaws.com" {
                    rec.record.request_parameters
                        .as_ref()
                        .and_then(|rp| serde_json::from_str::<S3Params>(rp.get()).ok())
                } else {
                    None
                };

                let bucket_name: Option<String> = s3_params
                    .as_ref()
                    .and_then(|p| p.bucket_name.as_deref().map(str::to_owned));

                // S3 enrichment: extract key + bytesTransferredOut for GetObject events
                if rec.record.event_name.as_ref() == "GetObject" {
                    if let Some(ref bname) = bucket_name {
                        let key: Arc<str> = s3_params
                            .as_ref()
                            .and_then(|p| p.key.as_deref())
                            .map(|s| pool.intern(s))
                            .unwrap_or_else(|| Arc::from(""));

                        let bytes_out: u64 = rec.record.additional_event_data
                            .as_ref()
                            .and_then(|ae| serde_json::from_str::<S3AdditionalData>(ae.get()).ok())
                            .and_then(|d| d.bytes_transferred_out)
                            .and_then(|n| n.as_u64().or_else(|| n.as_f64().map(|f| f as u64)))
                            .unwrap_or(0);

                        let identity: Arc<str> = rec.record.user_identity.arn
                            .as_deref()
                            .or_else(|| rec.record.user_identity.user_name.as_deref())
                            .map(|s| pool.intern(s))
                            .unwrap_or_else(|| Arc::from("unknown"));

                        let source_ip: Arc<str> = rec.record.source_ip_address
                            .as_deref()
                            .map(|s| pool.intern(s))
                            .unwrap_or_else(|| Arc::from(""));

                        self.s3_event_index.insert(rec.id, crate::s3::S3EventData {
                            bucket: pool.intern(bname),
                            key,
                            bytes_out,
                            identity,
                            source_ip,
                            timestamp: rec.timestamp,
                        });
                    }
                }

                // Drain JSON blobs to disk — frees ~200-800 bytes heap per event.
                // (S3/bucket extraction above already read request_parameters.)
                self.drain_blobs(rec);

                let id = rec.id;

                // Build indexes using the now-interned Arc<str> values (Arc::clone is O(1))
                Self::index_push_arc(&mut self.idx_event_name, Arc::clone(&rec.record.event_name), id);
                Self::index_push_arc(&mut self.idx_event_source, Arc::clone(&rec.record.event_source), id);
                Self::index_push_arc(&mut self.idx_region, Arc::clone(&rec.record.aws_region), id);
                if let Some(ip) = &rec.record.source_ip_address {
                    Self::index_push_arc(&mut self.idx_source_ip, Arc::clone(ip), id);
                }
                if let Some(arn) = &rec.record.user_identity.arn {
                    Self::index_push_arc(&mut self.idx_user_arn, Arc::clone(arn), id);
                }
                if let Some(name) = &rec.record.user_identity.user_name {
                    Self::index_push_arc(&mut self.idx_user_name, Arc::clone(name), id);
                }
                if let Some(acct) = &rec.record.user_identity.account_id {
                    Self::index_push_arc(&mut self.idx_account_id, Arc::clone(acct), id);
                }
                if let Some(err) = &rec.record.error_code {
                    Self::index_push_arc(&mut self.idx_error_code, Arc::clone(err), id);
                }
                if let Some(t) = &rec.record.user_identity.identity_type {
                    Self::index_push_arc(&mut self.idx_identity_type, Arc::clone(t), id);
                }
                if let Some(ua) = &rec.record.user_agent {
                    Self::index_push_arc(&mut self.idx_user_agent, Arc::clone(ua), id);
                }
                // Bucket name index: use the value extracted before draining (no disk read-back)
                if let Some(bucket) = &bucket_name {
                    Self::index_push_arc(&mut self.idx_bucket_name, pool.intern(bucket), id);
                }
            }

            total_records += batch.len();
            self.records.extend(batch);
            if files_seen.insert(src_idx) {
                files_done += 1;
            }

            on_progress(ProgressEvent {
                files_total,
                files_done,
                records_total: total_records,
            });
            }
        });

        // Flush BlobStore write buffer and memory-map the file for fast reads.
        // All subsequent blob access (detection rules, event detail) will use
        // lock-free pointer arithmetic instead of seek+read_exact.
        if let Err(e) = self.blob_store.seal() {
            // Non-fatal: blob reads will return None, detection rules degrade gracefully.
            eprintln!("BlobStore seal failed: {e}");
        }

        // Build time-sorted index
        let mut pairs: Vec<(i64, u32)> = self.records.iter().map(|r| (r.timestamp, r.id)).collect();
        pairs.sort_unstable();
        self.time_sorted_ids = pairs.into_iter().map(|(_, id)| id).collect();

        Ok((total_records, warnings))
    }

    /// Get a record by ID
    pub fn get_record(&self, id: u32) -> Option<&IndexedRecord> {
        // IDs are sequential from 0, so index directly
        self.records.get(id as usize)
    }

    /// Single source of truth: map a canonical camelCase field name to its
    /// inverted index. Every field→index lookup (query engine, aggregation
    /// commands) goes through here, so adding a field means editing one match.
    pub fn index_for(&self, field: &str) -> Option<&HashMap<Arc<str>, RoaringBitmap>> {
        Some(match field {
            "eventName" => &self.idx_event_name,
            "eventSource" => &self.idx_event_source,
            "awsRegion" => &self.idx_region,
            "sourceIPAddress" => &self.idx_source_ip,
            "userArn" => &self.idx_user_arn,
            "userName" => &self.idx_user_name,
            "accountId" => &self.idx_account_id,
            "errorCode" => &self.idx_error_code,
            "identityType" => &self.idx_identity_type,
            "userAgent" => &self.idx_user_agent,
            "bucketName" => &self.idx_bucket_name,
            _ => return None,
        })
    }

    /// Read a record's value for a canonical field name (in-memory fields only;
    /// `bucketName` lives in the request-parameters blob and is not covered here).
    pub fn field_str<'a>(rec: &'a IndexedRecord, field: &str) -> Option<&'a str> {
        match field {
            "eventName" => Some(&rec.record.event_name),
            "eventSource" => Some(&rec.record.event_source),
            "awsRegion" => Some(&rec.record.aws_region),
            "sourceIPAddress" => rec.record.source_ip_address.as_deref(),
            "userArn" => rec.record.user_identity.arn.as_deref(),
            "userName" => rec.record.user_identity.user_name.as_deref(),
            "accountId" => rec.record.user_identity.account_id.as_deref(),
            "errorCode" => rec.record.error_code.as_deref(),
            "identityType" => rec.record.user_identity.identity_type.as_deref(),
            "userAgent" => rec.record.user_agent.as_deref(),
            _ => None,
        }
    }

    /// Half-open index range `[lo, hi)` into `time_sorted_ids` whose records fall
    /// within `[start_ms, end_ms]` (inclusive). Binary search — O(log n).
    /// Shared by `get_ids_in_range` and the query engine's time filter.
    pub fn time_range_bounds(&self, start_ms: i64, end_ms: i64) -> (usize, usize) {
        let lo = self.time_sorted_ids.partition_point(|&id| {
            self.get_record(id).map(|r| r.timestamp).unwrap_or(i64::MAX) < start_ms
        });
        let hi = self.time_sorted_ids.partition_point(|&id| {
            self.get_record(id).map(|r| r.timestamp).unwrap_or(i64::MAX) <= end_ms
        });
        (lo, hi)
    }

    /// Return all record IDs whose timestamp falls within [start_ms, end_ms] (inclusive).
    pub fn get_ids_in_range(&self, start_ms: i64, end_ms: i64) -> Vec<u32> {
        let (lo, hi) = self.time_range_bounds(start_ms, end_ms);
        self.time_sorted_ids[lo..hi].to_vec()
    }

    /// Total record count
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    // -----------------------------------------------------------------------
    // Blob access helpers — load JSON blobs on demand from disk
    // -----------------------------------------------------------------------

    /// Load requestParameters for a record as a raw JSON string.
    pub fn get_request_parameters_str(&self, id: u32) -> Option<String> {
        let rec = self.get_record(id)?;
        // Check in-memory first (test records may have blob set directly)
        if let Some(rp) = &rec.record.request_parameters {
            return Some(rp.get().to_string());
        }
        rec.request_params_ref.and_then(|br| self.blob_store.load_str(br).map(str::to_owned))
    }

    /// Parse requestParameters on demand as a `serde_json::Value`.
    pub fn parse_request_parameters(&self, id: u32) -> Option<serde_json::Value> {
        let rec = self.get_record(id)?;
        if let Some(rp) = &rec.record.request_parameters {
            return serde_json::from_str(rp.get()).ok();
        }
        rec.request_params_ref.and_then(|br| self.blob_store.parse_value(br))
    }

    /// Parse responseElements on demand.
    pub fn parse_response_elements(&self, id: u32) -> Option<serde_json::Value> {
        let rec = self.get_record(id)?;
        if let Some(re) = &rec.record.response_elements {
            return serde_json::from_str(re.get()).ok();
        }
        rec.response_elements_ref.and_then(|br| self.blob_store.parse_value(br))
    }

    /// Parse additionalEventData on demand.
    pub fn parse_additional_event_data(&self, id: u32) -> Option<serde_json::Value> {
        let rec = self.get_record(id)?;
        if let Some(ae) = &rec.record.additional_event_data {
            return serde_json::from_str(ae.get()).ok();
        }
        rec.additional_event_data_ref.and_then(|br| self.blob_store.parse_value(br))
    }

    /// Load requestParameters as Box<RawValue> (for IPC/serde re-serialisation).
    pub fn load_raw_request_parameters(&self, id: u32) -> Option<Box<serde_json::value::RawValue>> {
        let rec = self.get_record(id)?;
        if let Some(rp) = &rec.record.request_parameters {
            return Some(rp.clone());
        }
        rec.request_params_ref.and_then(|br| self.blob_store.load_raw_value(br))
    }

    /// Load responseElements as Box<RawValue>.
    pub fn load_raw_response_elements(&self, id: u32) -> Option<Box<serde_json::value::RawValue>> {
        let rec = self.get_record(id)?;
        if let Some(re) = &rec.record.response_elements {
            return Some(re.clone());
        }
        rec.response_elements_ref.and_then(|br| self.blob_store.load_raw_value(br))
    }

    /// Load additionalEventData as Box<RawValue>.
    pub fn load_raw_additional_event_data(&self, id: u32) -> Option<Box<serde_json::value::RawValue>> {
        let rec = self.get_record(id)?;
        if let Some(ae) = &rec.record.additional_event_data {
            return Some(ae.clone());
        }
        rec.additional_event_data_ref.and_then(|br| self.blob_store.load_raw_value(br))
    }

    /// Return a clone of the record's CloudTrailRecord with blob fields
    /// populated from the BlobStore — used for IPC responses and JSON export
    /// where the full record (including requestParameters) is needed.
    pub fn get_full_record(&self, id: u32) -> Option<crate::model::CloudTrailRecord> {
        let rec = self.get_record(id)?;
        let mut full = rec.record.clone();
        full.request_parameters = self.load_raw_request_parameters(id);
        full.response_elements = self.load_raw_response_elements(id);
        full.additional_event_data = self.load_raw_additional_event_data(id);
        Some(full)
    }

    /// Drain blob fields from a record into the BlobStore.
    /// Called by test helpers to mirror the ingestion pipeline.
    pub fn drain_blobs(&self, rec: &mut IndexedRecord) {
        if let Some(rp) = rec.record.request_parameters.take() {
            if let Ok(br) = self.blob_store.write(rp.get().as_bytes()) {
                rec.request_params_ref = Some(br);
            }
        }
        if let Some(re) = rec.record.response_elements.take() {
            if let Ok(br) = self.blob_store.write(re.get().as_bytes()) {
                rec.response_elements_ref = Some(br);
            }
        }
        if let Some(ae) = rec.record.additional_event_data.take() {
            if let Ok(br) = self.blob_store.write(ae.get().as_bytes()) {
                rec.additional_event_data_ref = Some(br);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Mutex;

    fn file_json(event_name: &str) -> String {
        format!(
            r#"{{"Records":[{{"eventVersion":"1.08","eventTime":"2024-01-15T10:00:00Z","eventSource":"iam.amazonaws.com","eventName":"{event_name}","awsRegion":"us-east-1","userIdentity":{{"type":"IAMUser","userName":"a"}}}}]}}"#
        )
    }

    fn make_zip(path: &Path, entries: &[(&str, String)]) {
        let mut w = zip::ZipWriter::new(std::fs::File::create(path).unwrap());
        for (name, data) in entries {
            w.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
            w.write_all(data.as_bytes()).unwrap();
        }
        w.finish().unwrap();
    }

    /// Load `dir` and return (final store, every progress event in order).
    fn load(dir: &Path) -> (Store, Vec<ProgressEvent>) {
        let events = Mutex::new(Vec::new());
        let mut store = Store::new();
        store.load_directory(dir, |e| events.lock().unwrap().push(e)).unwrap();
        (store, events.into_inner().unwrap())
    }

    /// A ZIP with N entries used to report N files done against `files_total = 1` (>100%).
    #[test]
    fn multi_entry_zip_counts_as_one_file() {
        let dir = tempfile::TempDir::new().unwrap();
        make_zip(
            &dir.path().join("logs.zip"),
            &[("a.json", file_json("CreateUser")), ("b.json", file_json("DeleteUser")), ("c.json", file_json("ListUsers"))],
        );
        let (store, events) = load(dir.path());
        assert_eq!(store.len(), 3, "all three entries must load");
        assert!(!events.is_empty());
        for e in &events {
            assert!(e.files_done <= e.files_total, "progress overshot: {e:?}");
        }
        let last = events.last().unwrap();
        assert_eq!((last.files_done, last.files_total), (1, 1));
        assert_eq!(last.records_total, 3);
    }

    /// A ZIP whose entries are all filtered out sends no entry messages, so the file was never
    /// counted and the bar stalled below 100%.
    #[test]
    fn zip_with_no_matching_entries_still_completes() {
        let dir = tempfile::TempDir::new().unwrap();
        make_zip(&dir.path().join("docs.zip"), &[("readme.md", "hello".to_string())]);
        let (store, events) = load(dir.path());
        assert_eq!(store.len(), 0);
        let last = events.last().expect("a progress event for the zip");
        assert_eq!((last.files_done, last.files_total), (1, 1));
    }

    #[test]
    fn plain_files_each_count_once() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("a.json"), file_json("A")).unwrap();
        std::fs::write(dir.path().join("b.json"), file_json("B")).unwrap();
        let (store, events) = load(dir.path());
        assert_eq!(store.len(), 2);
        let last = events.last().unwrap();
        assert_eq!((last.files_done, last.files_total), (2, 2));
    }

    /// A corrupt entry is reported once and the file still counts exactly once.
    #[test]
    fn failing_zip_entry_warns_and_counts_the_file_once() {
        let dir = tempfile::TempDir::new().unwrap();
        make_zip(
            &dir.path().join("mixed.zip"),
            &[("good.json", file_json("Good")), ("bad.json", "{not json".to_string())],
        );
        let events = Mutex::new(Vec::new());
        let mut store = Store::new();
        let (loaded, warnings) = store.load_directory(dir.path(), |e| events.lock().unwrap().push(e)).unwrap();
        assert_eq!(loaded, 1);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        let events = events.into_inner().unwrap();
        let last = events.last().unwrap();
        assert_eq!((last.files_done, last.files_total), (1, 1));
        assert!(events.iter().all(|e| e.files_done <= e.files_total));
    }

    /// The ingest consumer only parses requestParameters for S3 events, via a borrowed struct.
    /// Pin what it must still extract: escaped keys, the several shapes of bytesTransferredOut,
    /// and the bucket index.
    #[test]
    fn s3_events_are_indexed_from_borrowed_request_parameters() {
        let rec = |name: &str, source: &str, params: &str, extra: &str| {
            format!(
                r#"{{"eventTime":"2024-01-15T10:00:00Z","eventSource":"{source}","eventName":"{name}","awsRegion":"us-east-1","userIdentity":{{"type":"IAMUser","userName":"a"}},"requestParameters":{params}{extra}}}"#
            )
        };
        let records = [
            rec("GetObject", "s3.amazonaws.com", r#"{"bucketName":"b1","key":"dir/a\"b-\u00e9.json"}"#, r#","additionalEventData":{"bytesTransferredOut":1234}"#),
            rec("GetObject", "s3.amazonaws.com", r#"{"bucketName":"b1","key":"k2"}"#, r#","additionalEventData":{"bytesTransferredOut":12.0}"#),
            rec("GetObject", "s3.amazonaws.com", r#"{"bucketName":"b2","key":"k3"}"#, r#","additionalEventData":{"bytesTransferredOut":"bad"}"#),
            rec("PutObject", "s3.amazonaws.com", r#"{"bucketName":"b1","key":"k4"}"#, ""),
            // Not an S3 event: ingestion no longer parses it, so its bucketName is not indexed.
            rec("DescribeThings", "ec2.amazonaws.com", r#"{"bucketName":"x"}"#, ""),
        ];
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("f.json"), format!(r#"{{"Records":[{}]}}"#, records.join(","))).unwrap();
        let mut store = Store::new();
        store.load_directory(dir.path(), |_| {}).unwrap();

        assert_eq!(store.idx_bucket_name.get("b1").map(|b| b.len()), Some(3));
        assert_eq!(store.idx_bucket_name.get("b2").map(|b| b.len()), Some(1));
        assert!(store.idx_bucket_name.get("x").is_none(), "non-S3 events are not indexed by bucket");

        // GetObject only: three entries, keyed by record id (file order = id order).
        assert_eq!(store.s3_event_index.len(), 3);
        let e0 = &store.s3_event_index[&0];
        assert_eq!((&*e0.bucket, &*e0.key, e0.bytes_out), ("b1", "dir/a\"b-\u{e9}.json", 1234));
        let e1 = &store.s3_event_index[&1];
        assert_eq!((&*e1.key, e1.bytes_out), ("k2", 12));
        let e2 = &store.s3_event_index[&2];
        assert_eq!((&*e2.bucket, e2.bytes_out), ("b2", 0), "a non-numeric byte count reads as 0");
    }

    /// Ingest throughput on synthetic data. Ignored by default (it writes ~100 MB);
    /// run it after touching the ingest consumer:
    /// `cargo test -p trail-inspector-core --release -- --ignored bench_ingest --nocapture`
    #[test]
    #[ignore]
    fn bench_ingest_200k_records() {
        use std::time::Instant;
        let dir = tempfile::TempDir::new().unwrap();
        let files = 20usize;
        let per_file = 10_000usize;
        let names = ["DescribeInstances", "GetObject", "AssumeRole", "PutObject", "ListBuckets", "GetCallerIdentity"];
        for f in 0..files {
            let mut records = Vec::with_capacity(per_file);
            for i in 0..per_file {
                let n = f * per_file + i;
                let name = names[n % names.len()];
                let (source, params, extra) = if name == "GetObject" || name == "PutObject" {
                    (
                        "s3.amazonaws.com",
                        format!(r#"{{"bucketName":"bucket-{}","key":"logs/2024/{}/object-{n}.json","Host":"bucket.s3.amazonaws.com"}}"#, n % 7, n % 31),
                        r#","additionalEventData":{"bytesTransferredOut":1234,"SignatureVersion":"SigV4"}"#.to_string(),
                    )
                } else {
                    (
                        "ec2.amazonaws.com",
                        format!(r#"{{"filterSet":{{"items":[{{"name":"instance-state-name","valueSet":{{"items":[{{"value":"running"}},{{"value":"stopped"}}]}}}}]}},"maxResults":50,"instancesSet":{{"items":[{{"instanceId":"i-{n:017x}"}}]}}}}"#),
                        String::new(),
                    )
                };
                records.push(format!(
                    r#"{{"eventVersion":"1.08","eventTime":"2024-01-15T{:02}:{:02}:{:02}Z","eventSource":"{source}","eventName":"{name}","awsRegion":"us-east-1","sourceIPAddress":"203.0.113.{}","userAgent":"aws-cli/2.15","userIdentity":{{"type":"IAMUser","arn":"arn:aws:iam::123456789012:user/user{}","userName":"user{}","accountId":"123456789012"}},"requestParameters":{params},"responseElements":null,"eventID":"{n:032x}"{extra}}}"#,
                    (n / 3600) % 24, (n / 60) % 60, n % 60, n % 250, n % 40, n % 40,
                ));
            }
            std::fs::write(dir.path().join(format!("f{f:03}.json")), format!(r#"{{"Records":[{}]}}"#, records.join(","))).unwrap();
        }

        let mut store = Store::new();
        let start = Instant::now();
        let (loaded, _) = store.load_directory(dir.path(), |_| {}).unwrap();
        let elapsed = start.elapsed();
        println!("Ingest {loaded} records: {elapsed:?}");
        assert_eq!(loaded, files * per_file);
    }
}
