use std::collections::HashMap;
use std::sync::Arc;
use crate::model::IndexedRecord;
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
struct StringPool {
    pool: HashMap<Box<str>, Arc<str>>,
}

impl StringPool {
    fn new() -> Self { Self { pool: HashMap::new() } }

    fn intern(&mut self, s: &str) -> Arc<str> {
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
    pub idx_event_name: HashMap<Arc<str>, Vec<u64>>,
    pub idx_event_source: HashMap<Arc<str>, Vec<u64>>,
    pub idx_region: HashMap<Arc<str>, Vec<u64>>,
    pub idx_source_ip: HashMap<Arc<str>, Vec<u64>>,
    pub idx_user_arn: HashMap<Arc<str>, Vec<u64>>,
    pub idx_user_name: HashMap<Arc<str>, Vec<u64>>,
    pub idx_account_id: HashMap<Arc<str>, Vec<u64>>,
    pub idx_error_code: HashMap<Arc<str>, Vec<u64>>,
    pub idx_identity_type: HashMap<Arc<str>, Vec<u64>>,
    pub idx_user_agent: HashMap<Arc<str>, Vec<u64>>,
    pub idx_bucket_name: HashMap<Arc<str>, Vec<u64>>,

    // Sorted by timestamp for range queries
    pub time_sorted_ids: Vec<u64>,
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
        }
    }

    /// Insert a record ID into an inverted index under the given interned key.
    fn index_push_arc(idx: &mut HashMap<Arc<str>, Vec<u64>>, key: Arc<str>, id: u64) {
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
            let base_id = self.records.len() as u64;
            for (i, rec) in batch.iter_mut().enumerate() {
                rec.id = base_id + i as u64;
            }

            // Build indexes using interned strings to avoid duplicating high-repetition values
            for rec in &batch {
                let id = rec.id;
                Self::index_push_arc(&mut self.idx_event_name, pool.intern(&rec.record.event_name), id);
                Self::index_push_arc(&mut self.idx_event_source, pool.intern(&rec.record.event_source), id);
                Self::index_push_arc(&mut self.idx_region, pool.intern(&rec.record.aws_region), id);
                if let Some(ip) = &rec.record.source_ip_address {
                    Self::index_push_arc(&mut self.idx_source_ip, pool.intern(ip), id);
                }
                if let Some(arn) = &rec.record.user_identity.arn {
                    Self::index_push_arc(&mut self.idx_user_arn, pool.intern(arn), id);
                }
                if let Some(name) = &rec.record.user_identity.user_name {
                    Self::index_push_arc(&mut self.idx_user_name, pool.intern(name), id);
                }
                if let Some(acct) = &rec.record.user_identity.account_id {
                    Self::index_push_arc(&mut self.idx_account_id, pool.intern(acct), id);
                }
                if let Some(err) = &rec.record.error_code {
                    Self::index_push_arc(&mut self.idx_error_code, pool.intern(err), id);
                }
                if let Some(t) = &rec.record.user_identity.identity_type {
                    Self::index_push_arc(&mut self.idx_identity_type, pool.intern(t), id);
                }
                if let Some(ua) = &rec.record.user_agent {
                    Self::index_push_arc(&mut self.idx_user_agent, pool.intern(ua), id);
                }
                if let Some(params) = &rec.record.request_parameters {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(params.get()) {
                        if let Some(bucket) = v.get("bucketName").and_then(|v| v.as_str()) {
                            Self::index_push_arc(&mut self.idx_bucket_name, pool.intern(bucket), id);
                        }
                    }
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

        // Build time-sorted index
        let mut pairs: Vec<(i64, u64)> = self.records.iter().map(|r| (r.timestamp, r.id)).collect();
        pairs.sort_unstable_by_key(|(ts, _)| *ts);
        self.time_sorted_ids = pairs.into_iter().map(|(_, id)| id).collect();

        Ok((total_records, warnings))
    }

    /// Get a record by ID
    pub fn get_record(&self, id: u64) -> Option<&IndexedRecord> {
        // IDs are sequential from 0, so index directly
        self.records.get(id as usize)
    }

    /// Return all record IDs whose timestamp falls within [start_ms, end_ms] (inclusive).
    /// Uses binary search on the pre-sorted `time_sorted_ids` index — O(log n).
    pub fn get_ids_in_range(&self, start_ms: i64, end_ms: i64) -> Vec<u64> {
        // Find the slice of IDs whose timestamps are in [start_ms, end_ms]
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
}
