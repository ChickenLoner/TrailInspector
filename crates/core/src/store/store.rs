use std::collections::HashMap;
use std::sync::Arc;
use crate::model::IndexedRecord;
use crate::store::blob_store::BlobStore;
use rayon::prelude::*;
use crate::ingest::{decompress::{read_log_file, read_zip_entries}, parser::parse_records};
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

pub struct Store {
    pub records: Vec<IndexedRecord>,
    pub file_paths: Vec<String>,

    // Inverted indexes: interned field_value → Vec<record_id>
    // u32 IDs: 4 bytes each vs u64's 8 bytes — saves ~250 MB for 5M events
    pub idx_event_name: HashMap<Arc<str>, Vec<u32>>,
    pub idx_event_source: HashMap<Arc<str>, Vec<u32>>,
    pub idx_region: HashMap<Arc<str>, Vec<u32>>,
    pub idx_source_ip: HashMap<Arc<str>, Vec<u32>>,
    pub idx_user_arn: HashMap<Arc<str>, Vec<u32>>,
    pub idx_user_name: HashMap<Arc<str>, Vec<u32>>,
    pub idx_account_id: HashMap<Arc<str>, Vec<u32>>,
    pub idx_error_code: HashMap<Arc<str>, Vec<u32>>,
    pub idx_identity_type: HashMap<Arc<str>, Vec<u32>>,
    pub idx_user_agent: HashMap<Arc<str>, Vec<u32>>,
    pub idx_bucket_name: HashMap<Arc<str>, Vec<u32>>,

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
            time_sorted_ids: Vec::new(),
            blob_store: BlobStore::new().expect("failed to create blob store temp file"),
        }
    }

    /// Insert a record ID into an inverted index under the given interned key.
    fn index_push_arc(idx: &mut HashMap<Arc<str>, Vec<u32>>, key: Arc<str>, id: u32) {
        idx.entry(key).or_default().push(id);
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

        // Process files in parallel.
        // Each result carries: (path_str, source_file_idx, records).
        // ZIP files produce multiple batches — one per inner entry — all attributed to the
        // same source file index so the path table stays compact.
        let results: Vec<Result<(String, u32, Vec<IndexedRecord>), CoreError>> = paths
            .par_iter()
            .enumerate()
            .flat_map_iter(|(file_idx, path)| {
                let path_str = path.to_string_lossy().into_owned();
                let src_idx = file_idx as u32;

                let is_zip = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.eq_ignore_ascii_case("zip"))
                    .unwrap_or(false);

                if is_zip {
                    match read_zip_entries(path) {
                        Ok(entries) => entries
                            .into_iter()
                            .map(|bytes| {
                                let p = path_str.clone();
                                parse_records(&bytes, path, src_idx, 0)
                                    .map(|r| (p, src_idx, r))
                            })
                            .collect::<Vec<_>>(),
                        Err(e) => vec![Err(e)],
                    }
                } else {
                    match read_log_file(path) {
                        Ok(bytes) => {
                            vec![parse_records(&bytes, path, src_idx, 0)
                                .map(|r| (path_str, src_idx, r))]
                        }
                        Err(e) => vec![Err(e)],
                    }
                }
            })
            .collect();

        // Sequential ingest into store (indexes must be built single-threaded)
        let mut pool = StringPool::new();
        let mut total_records = 0usize;
        let mut files_done = 0usize;
        let mut warnings: Vec<IngestWarning> = Vec::new();

        for result in results {
            let (path_str, src_idx, mut batch) = match result {
                Ok(v) => v,
                Err(e) => {
                    // Extract the file path from the error for the warning message
                    let file = match &e {
                        CoreError::Io { path, .. } => Some(path.clone()),
                        CoreError::PermissionDenied { path } => Some(path.clone()),
                        CoreError::Json { path, .. } => Some(path.clone()),
                        CoreError::CorruptGzip { path, .. } => Some(path.clone()),
                        _ => None,
                    };
                    warnings.push(IngestWarning { message: e.to_string(), file });
                    files_done += 1;
                    on_progress(ProgressEvent { files_total, files_done, records_total: total_records });
                    continue;
                }
            };
            let file_idx = src_idx as usize;

            // Ensure file path is registered
            while self.file_paths.len() <= file_idx {
                self.file_paths.push(String::new());
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
                let bucket_name: Option<String> = rec.record.request_parameters
                    .as_ref()
                    .and_then(|rp| serde_json::from_str::<serde_json::Value>(rp.get()).ok())
                    .and_then(|v| v.get("bucketName").and_then(|v| v.as_str()).map(|s| s.to_owned()));

                // Drain JSON blobs to disk — frees ~200-800 bytes heap per event.
                // take() moves out of the Option, setting it to None in the record.
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
            files_done += 1;

            on_progress(ProgressEvent {
                files_total,
                files_done,
                records_total: total_records,
            });
        }

        // Flush BlobStore write buffer and memory-map the file for fast reads.
        // All subsequent blob access (detection rules, event detail) will use
        // lock-free pointer arithmetic instead of seek+read_exact.
        if let Err(e) = self.blob_store.seal() {
            // Non-fatal: blob reads will return None, detection rules degrade gracefully.
            eprintln!("BlobStore seal failed: {e}");
        }

        // Build time-sorted index
        let mut pairs: Vec<(i64, u32)> = self.records.iter().map(|r| (r.timestamp, r.id)).collect();
        pairs.sort_unstable_by_key(|(ts, _)| *ts);
        self.time_sorted_ids = pairs.into_iter().map(|(_, id)| id).collect();

        Ok((total_records, warnings))
    }

    /// Get a record by ID
    pub fn get_record(&self, id: u32) -> Option<&IndexedRecord> {
        // IDs are sequential from 0, so index directly
        self.records.get(id as usize)
    }

    /// Return all record IDs whose timestamp falls within [start_ms, end_ms] (inclusive).
    /// Uses binary search on the pre-sorted `time_sorted_ids` index — O(log n).
    pub fn get_ids_in_range(&self, start_ms: i64, end_ms: i64) -> Vec<u32> {
        let start_idx = self.time_sorted_ids.partition_point(|&id| {
            self.get_record(id).map(|r| r.timestamp).unwrap_or(i64::MAX) < start_ms
        });
        let end_idx = self.time_sorted_ids.partition_point(|&id| {
            self.get_record(id).map(|r| r.timestamp).unwrap_or(i64::MAX) <= end_ms
        });
        self.time_sorted_ids[start_idx..end_idx].to_vec()
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
