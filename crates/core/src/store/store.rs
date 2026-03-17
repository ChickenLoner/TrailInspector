use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use crate::model::IndexedRecord;
use rayon::prelude::*;
use crate::ingest::{decompress::read_log_file, parser::parse_records};
use crate::error::CoreError;
use std::path::Path;

/// Progress event emitted during ingestion
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressEvent {
    pub files_total: usize,
    pub files_done: usize,
    pub records_total: usize,
}

pub struct Store {
    pub records: Vec<IndexedRecord>,
    pub file_paths: Vec<String>,

    // Inverted indexes: field_value → Vec<record_id>
    pub idx_event_name: HashMap<String, Vec<u64>>,
    pub idx_event_source: HashMap<String, Vec<u64>>,
    pub idx_region: HashMap<String, Vec<u64>>,
    pub idx_source_ip: HashMap<String, Vec<u64>>,
    pub idx_user_arn: HashMap<String, Vec<u64>>,
    pub idx_user_name: HashMap<String, Vec<u64>>,
    pub idx_account_id: HashMap<String, Vec<u64>>,
    pub idx_error_code: HashMap<String, Vec<u64>>,
    pub idx_identity_type: HashMap<String, Vec<u64>>,
    pub idx_user_agent: HashMap<String, Vec<u64>>,

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
            time_sorted_ids: Vec::new(),
        }
    }

    /// Load all log files from a directory, processing in parallel.
    /// Calls `on_progress` callback after each file is processed.
    pub fn load_directory<F>(
        &mut self,
        root: &Path,
        on_progress: F,
    ) -> Result<usize, CoreError>
    where
        F: Fn(ProgressEvent) + Send + Sync,
    {
        let paths = crate::ingest::discovery::find_log_files(root);
        let files_total = paths.len();

        // Process files in parallel, collect (file_idx, records) pairs
        let counter = AtomicU64::new(0);
        let results: Vec<Result<(usize, Vec<IndexedRecord>), CoreError>> = paths
            .par_iter()
            .enumerate()
            .map(|(file_idx, path)| {
                let bytes = read_log_file(path)?;
                let start_id = counter.fetch_add(0, Ordering::Relaxed); // placeholder; reassign below
                let records = parse_records(&bytes, path, file_idx as u32, start_id)?;
                Ok((file_idx, records))
            })
            .collect();

        // Sequential ingest into store (indexes must be built single-threaded)
        let mut total_records = 0usize;
        let mut files_done = 0usize;

        for result in results {
            let (file_idx, mut batch) = result?;
            let path_str = paths[file_idx].to_string_lossy().to_string();

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

            // Build indexes
            for rec in &batch {
                let id = rec.id;
                Self::index_push(&mut self.idx_event_name, &rec.record.event_name, id);
                Self::index_push(&mut self.idx_event_source, &rec.record.event_source, id);
                Self::index_push(&mut self.idx_region, &rec.record.aws_region, id);
                if let Some(ip) = &rec.record.source_ip_address {
                    Self::index_push(&mut self.idx_source_ip, ip, id);
                }
                if let Some(arn) = &rec.record.user_identity.arn {
                    Self::index_push(&mut self.idx_user_arn, arn, id);
                }
                if let Some(name) = &rec.record.user_identity.user_name {
                    Self::index_push(&mut self.idx_user_name, name, id);
                }
                if let Some(acct) = &rec.record.user_identity.account_id {
                    Self::index_push(&mut self.idx_account_id, acct, id);
                }
                if let Some(err) = &rec.record.error_code {
                    Self::index_push(&mut self.idx_error_code, err, id);
                }
                if let Some(t) = &rec.record.user_identity.identity_type {
                    Self::index_push(&mut self.idx_identity_type, t, id);
                }
                if let Some(ua) = &rec.record.user_agent {
                    Self::index_push(&mut self.idx_user_agent, ua, id);
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

        Ok(total_records)
    }

    fn index_push(idx: &mut HashMap<String, Vec<u64>>, key: &str, id: u64) {
        idx.entry(key.to_string()).or_default().push(id);
    }

    /// Get a record by ID
    pub fn get_record(&self, id: u64) -> Option<&IndexedRecord> {
        // IDs are sequential from 0, so index directly
        self.records.get(id as usize)
    }

    /// Total record count
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}
