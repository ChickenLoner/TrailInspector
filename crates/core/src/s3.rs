use std::collections::HashMap;
use std::sync::Arc;
use serde::Serialize;
use crate::store::Store;

// ---------------------------------------------------------------------------
// Per-event data extracted at ingestion time (zero blob reads at query time)
// ---------------------------------------------------------------------------

pub struct S3EventData {
    pub bucket: Arc<str>,
    pub key: Arc<str>,
    pub bytes_out: u64,
    pub identity: Arc<str>,
    pub source_ip: Arc<str>,
    pub timestamp: i64,
}

// ---------------------------------------------------------------------------
// Return types for get_s3_summary
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct S3Summary {
    pub total_bytes_out: u64,
    pub total_get_objects: usize,
    pub unique_objects: usize,
    pub available_buckets: Vec<String>,
    pub available_ips: Vec<String>,
    pub available_identities: Vec<String>,
    pub buckets: Vec<BucketStat>,
    pub top_objects: Vec<ObjectStat>,
    pub identities: Vec<IdentityStat>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketStat {
    pub bucket: String,
    pub bytes_out: u64,
    pub object_count: usize,
    pub top_identity: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectStat {
    pub bucket: String,
    pub key: String,
    pub bytes_out: u64,
    pub access_count: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityStat {
    pub identity: String,
    pub bytes_out: u64,
    pub object_count: usize,
    pub unique_buckets: usize,
}

// ---------------------------------------------------------------------------
// Accumulator types (not serialized — internal only)
// ---------------------------------------------------------------------------

struct BucketAcc {
    bytes_out: u64,
    object_count: usize,
    identity_bytes: HashMap<String, u64>,
}

struct ObjectAcc {
    bucket: String,
    bytes_out: u64,
    access_count: usize,
}

struct IdentityAcc {
    bytes_out: u64,
    object_count: usize,
    buckets: std::collections::HashSet<String>,
}

// ---------------------------------------------------------------------------
// Query function
// ---------------------------------------------------------------------------

/// Return an S3Summary aggregated over all GetObject events that match the
/// optional time range, bucket, IP, and identity filters.
pub fn get_s3_summary(
    store: &Store,
    start_ms: Option<i64>,
    end_ms: Option<i64>,
    bucket_filter: Option<&str>,
    ip_filter: Option<&str>,
    identity_filter: Option<&str>,
) -> S3Summary {
    // Collect available dropdown values from s3_event_index (all GetObject events, unfiltered)
    let (available_buckets, available_ips, available_identities) = available_filter_values(store);

    // 1. Start with all GetObject IDs
    let candidate_ids: Vec<u32> = match store.idx_event_name.get("GetObject") {
        Some(ids) => ids.clone(),
        None => {
            return S3Summary {
                total_bytes_out: 0,
                total_get_objects: 0,
                unique_objects: 0,
                available_buckets,
                available_ips,
                available_identities,
                buckets: vec![],
                top_objects: vec![],
                identities: vec![],
            };
        }
    };

    // 2. Apply time range filter
    let time_filtered: Vec<u32> = if start_ms.is_some() || end_ms.is_some() {
        let lo = start_ms.unwrap_or(i64::MIN);
        let hi = end_ms.unwrap_or(i64::MAX);
        candidate_ids
            .into_iter()
            .filter(|&id| {
                store
                    .get_record(id)
                    .map(|r| r.timestamp >= lo && r.timestamp <= hi)
                    .unwrap_or(false)
            })
            .collect()
    } else {
        candidate_ids
    };

    // 3. Apply bucket filter
    let bucket_filtered: Vec<u32> = if let Some(bucket) = bucket_filter {
        if let Some(bucket_ids) = store.idx_bucket_name.get(bucket) {
            let bucket_set: std::collections::HashSet<u32> = bucket_ids.iter().copied().collect();
            time_filtered
                .into_iter()
                .filter(|id| bucket_set.contains(id))
                .collect()
        } else {
            vec![]
        }
    } else {
        time_filtered
    };

    // 4. Apply IP filter (using s3_event_index — no blob reads)
    let ip_filtered: Vec<u32> = if let Some(ip) = ip_filter {
        bucket_filtered
            .into_iter()
            .filter(|id| {
                store.s3_event_index.get(id)
                    .map(|d| d.source_ip.as_ref() == ip)
                    .unwrap_or(false)
            })
            .collect()
    } else {
        bucket_filtered
    };

    // 5. Apply identity filter
    let filtered: Vec<u32> = if let Some(identity) = identity_filter {
        ip_filtered
            .into_iter()
            .filter(|id| {
                store.s3_event_index.get(id)
                    .map(|d| d.identity.as_ref() == identity)
                    .unwrap_or(false)
            })
            .collect()
    } else {
        ip_filtered
    };

    // 4 + 5. Aggregate
    let mut bucket_acc: HashMap<String, BucketAcc> = HashMap::new();
    let mut object_acc: HashMap<(String, String), ObjectAcc> = HashMap::new();
    let mut identity_acc: HashMap<String, IdentityAcc> = HashMap::new();
    let mut total_bytes_out: u64 = 0;

    for id in &filtered {
        let data = match store.s3_event_index.get(id) {
            Some(d) => d,
            None => continue,
        };

        let bucket = data.bucket.as_ref().to_owned();
        let key = data.key.as_ref().to_owned();
        let identity = data.identity.as_ref().to_owned();
        let bytes = data.bytes_out;

        total_bytes_out += bytes;

        // Bucket accumulator
        let ba = bucket_acc.entry(bucket.clone()).or_insert(BucketAcc {
            bytes_out: 0,
            object_count: 0,
            identity_bytes: HashMap::new(),
        });
        ba.bytes_out += bytes;
        ba.object_count += 1;
        *ba.identity_bytes.entry(identity.clone()).or_insert(0) += bytes;

        // Object accumulator (bucket + key composite key)
        let oa = object_acc
            .entry((bucket.clone(), key.clone()))
            .or_insert(ObjectAcc {
                bucket: bucket.clone(),
                bytes_out: 0,
                access_count: 0,
            });
        oa.bytes_out += bytes;
        oa.access_count += 1;

        // Identity accumulator
        let ia = identity_acc.entry(identity.clone()).or_insert(IdentityAcc {
            bytes_out: 0,
            object_count: 0,
            buckets: std::collections::HashSet::new(),
        });
        ia.bytes_out += bytes;
        ia.object_count += 1;
        ia.buckets.insert(bucket.clone());
    }

    // 6. Build BucketStat list
    let mut buckets: Vec<BucketStat> = bucket_acc
        .into_iter()
        .map(|(bucket, acc)| {
            let top_identity = acc
                .identity_bytes
                .into_iter()
                .max_by_key(|(_, b)| *b)
                .map(|(id, _)| id)
                .unwrap_or_default();
            BucketStat {
                bucket,
                bytes_out: acc.bytes_out,
                object_count: acc.object_count,
                top_identity,
            }
        })
        .collect();
    buckets.sort_unstable_by(|a, b| b.bytes_out.cmp(&a.bytes_out));

    // Build ObjectStat list, cap at 100
    let unique_objects = object_acc.len();
    let mut top_objects: Vec<ObjectStat> = object_acc
        .into_iter()
        .map(|((_, key), acc)| ObjectStat {
            bucket: acc.bucket,
            key,
            bytes_out: acc.bytes_out,
            access_count: acc.access_count,
        })
        .collect();
    top_objects.sort_unstable_by(|a, b| b.bytes_out.cmp(&a.bytes_out));
    top_objects.truncate(100);

    // Build IdentityStat list
    let mut identities: Vec<IdentityStat> = identity_acc
        .into_iter()
        .map(|(identity, acc)| IdentityStat {
            identity,
            bytes_out: acc.bytes_out,
            object_count: acc.object_count,
            unique_buckets: acc.buckets.len(),
        })
        .collect();
    identities.sort_unstable_by(|a, b| b.bytes_out.cmp(&a.bytes_out));

    S3Summary {
        total_bytes_out,
        total_get_objects: filtered.len(),
        unique_objects,
        available_buckets,
        available_ips,
        available_identities,
        buckets,
        top_objects,
        identities,
    }
}

/// Collect sorted unique buckets, IPs, and identities from s3_event_index (unfiltered).
fn available_filter_values(store: &Store) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut buckets: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut ips: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut identities: std::collections::HashSet<String> = std::collections::HashSet::new();

    for data in store.s3_event_index.values() {
        buckets.insert(data.bucket.as_ref().to_owned());
        if !data.source_ip.is_empty() {
            ips.insert(data.source_ip.as_ref().to_owned());
        }
        identities.insert(data.identity.as_ref().to_owned());
    }

    let mut bv: Vec<String> = buckets.into_iter().collect(); bv.sort();
    let mut iv: Vec<String> = ips.into_iter().collect(); iv.sort();
    let mut idv: Vec<String> = identities.into_iter().collect(); idv.sort();
    (bv, iv, idv)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::store::Store;
    use crate::model::{CloudTrailRecord, IndexedRecord, UserIdentity};

    fn default_identity_with_arn(arn: &str) -> UserIdentity {
        UserIdentity {
            identity_type: Some(Arc::from("IAMUser")),
            principal_id: Some(Arc::from("AIDAEXAMPLE")),
            arn: Some(Arc::from(arn)),
            account_id: Some(Arc::from("123456789012")),
            access_key_id: None,
            user_name: None,
            session_context: None,
            invoked_by: None,
        }
    }

    fn make_getobject_record(id: u32, ts_ms: i64, arn: &str) -> IndexedRecord {
        IndexedRecord {
            id,
            timestamp: ts_ms,
            source_file: 0,
            record: CloudTrailRecord {
                event_time: Arc::from("2024-01-15T10:00:00Z"),
                event_source: Arc::from("s3.amazonaws.com"),
                event_name: Arc::from("GetObject"),
                aws_region: Arc::from("us-east-1"),
                source_ip_address: Some(Arc::from("1.2.3.4")),
                user_agent: None,
                user_identity: default_identity_with_arn(arn),
                request_parameters: None,
                response_elements: None,
                additional_event_data: None,
                error_code: None,
                error_message: None,
                request_id: None,
                event_id: None,
                event_type: None,
                read_only: None,
                management_event: None,
                recipient_account_id: None,
                event_category: None,
                shared_event_id: None,
                session_credential_from_console: None,
                resources: vec![],
            },
            request_params_ref: None,
            response_elements_ref: None,
            additional_event_data_ref: None,
        }
    }

    /// Build a store with GetObject records and pre-populated s3_event_index
    fn build_s3_store(entries: Vec<(u32, i64, &str, &str, &str, u64)>) -> Store {
        // entries: (id, ts_ms, arn, bucket, key, bytes_out)
        let mut records: Vec<IndexedRecord> = entries
            .iter()
            .map(|(id, ts, arn, _, _, _)| make_getobject_record(*id, *ts, arn))
            .collect();
        records.sort_by_key(|r| r.id);

        let mut store = Store::new();

        // Seal blob store (no blobs in these test records)
        store.blob_store.seal().expect("BlobStore seal failed");

        for rec in &records {
            let id = rec.id;
            store.idx_event_name
                .entry(rec.record.event_name.clone())
                .or_default()
                .push(id);
        }

        // Insert s3_event_index entries and bucket index
        for (id, ts, arn, bucket, key, bytes_out) in &entries {
            let bucket_arc: Arc<str> = Arc::from(*bucket);
            store.idx_bucket_name
                .entry(bucket_arc.clone())
                .or_default()
                .push(*id);
            store.s3_event_index.insert(
                *id,
                S3EventData {
                    bucket: bucket_arc,
                    key: Arc::from(*key),
                    bytes_out: *bytes_out,
                    identity: Arc::from(*arn),
                    source_ip: Arc::from("1.2.3.4"),
                    timestamp: *ts,
                },
            );
        }

        let mut sorted: Vec<(i64, u32)> = records.iter().map(|r| (r.timestamp, r.id)).collect();
        sorted.sort_unstable_by_key(|(ts, _)| *ts);
        store.time_sorted_ids = sorted.into_iter().map(|(_, id)| id).collect();
        store.records = records;
        store
    }

    #[test]
    fn test_s3_summary_bytes_sum() {
        // 3 GetObject events with known bytes_out
        let store = build_s3_store(vec![
            (0, 1000, "arn:aws:iam::123:user/alice", "my-bucket", "file1.txt", 1_000_000),
            (1, 2000, "arn:aws:iam::123:user/alice", "my-bucket", "file2.txt", 2_000_000),
            (2, 3000, "arn:aws:iam::123:user/bob",   "my-bucket", "file3.txt",   500_000),
        ]);

        let summary = get_s3_summary(&store, None, None, None, None, None);
        assert_eq!(summary.total_bytes_out, 3_500_000);
        assert_eq!(summary.total_get_objects, 3);
        assert_eq!(summary.unique_objects, 3);
    }

    #[test]
    fn test_s3_summary_time_filter() {
        let store = build_s3_store(vec![
            (0,  1_000, "arn:aws:iam::123:user/alice", "bucket-a", "k1", 100),
            (1, 10_000, "arn:aws:iam::123:user/alice", "bucket-a", "k2", 200),
            (2, 20_000, "arn:aws:iam::123:user/alice", "bucket-a", "k3", 400),
        ]);

        // Filter: only timestamps in [5000, 15000]
        let summary = get_s3_summary(&store, Some(5_000), Some(15_000), None, None, None);
        assert_eq!(summary.total_get_objects, 1);
        assert_eq!(summary.total_bytes_out, 200);
    }

    #[test]
    fn test_s3_summary_bucket_filter() {
        let store = build_s3_store(vec![
            (0, 1000, "arn:aws:iam::123:user/alice", "bucket-a", "k1", 100),
            (1, 2000, "arn:aws:iam::123:user/alice", "bucket-b", "k2", 200),
            (2, 3000, "arn:aws:iam::123:user/alice", "bucket-a", "k3", 300),
        ]);

        let summary = get_s3_summary(&store, None, None, Some("bucket-a"), None, None);
        assert_eq!(summary.total_get_objects, 2);
        assert_eq!(summary.total_bytes_out, 400);
        // bucket-b events should not appear
        assert!(summary.buckets.iter().all(|b| b.bucket == "bucket-a"));
    }

    #[test]
    fn test_s3_top_objects_capped() {
        // Insert 150 unique objects — build the store manually with unique keys via S3EventData.
        let mut store = Store::new();
        store.blob_store.seal().expect("BlobStore seal failed");

        let bucket_arc: Arc<str> = Arc::from("big-bucket");
        for i in 0u32..150 {
            let rec = make_getobject_record(i, i as i64 * 1000, "arn:aws:iam::123:user/alice");
            store.records.push(rec);
            store.idx_event_name
                .entry(Arc::from("GetObject"))
                .or_default()
                .push(i);
            store.idx_bucket_name
                .entry(bucket_arc.clone())
                .or_default()
                .push(i);
            // unique key per object
            let key = format!("key-{}", i);
            store.s3_event_index.insert(i, S3EventData {
                bucket: bucket_arc.clone(),
                key: Arc::from(key.as_str()),
                bytes_out: i as u64 * 1000,
                identity: Arc::from("arn:aws:iam::123:user/alice"),
                source_ip: Arc::from("1.2.3.4"),
                timestamp: i as i64 * 1000,
            });
        }

        store.time_sorted_ids = (0u32..150).collect();

        let summary = get_s3_summary(&store, None, None, None, None, None);
        assert_eq!(summary.unique_objects, 150);
        assert_eq!(summary.top_objects.len(), 100, "top_objects must be capped at 100");
        // Highest bytes should be first
        assert!(summary.top_objects[0].bytes_out >= summary.top_objects[99].bytes_out);
    }

    #[test]
    fn test_s3_empty_store() {
        let store = Store::new();
        let summary = get_s3_summary(&store, None, None, None, None, None);
        assert_eq!(summary.total_get_objects, 0);
        assert_eq!(summary.total_bytes_out, 0);
        assert!(summary.buckets.is_empty());
    }
}
