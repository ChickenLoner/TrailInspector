use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use crate::store::Store;

// ---------------------------------------------------------------------------
// Time bucketing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimeBucket {
    pub start_ms: i64,
    pub end_ms: i64,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineResult {
    pub buckets: Vec<TimeBucket>,
    pub total: usize,
}

/// Build a timeline histogram from a slice of record IDs.
///
/// `bucket_count` is a hint; the actual number is clamped to `1..=100`.
/// If there are no records, returns an empty result.
pub fn build_timeline(store: &Store, ids: &[u32], bucket_count: usize) -> TimelineResult {
    if ids.is_empty() {
        return TimelineResult { buckets: vec![], total: 0 };
    }

    // Find min/max timestamps
    let mut min_ts = i64::MAX;
    let mut max_ts = i64::MIN;
    for &id in ids {
        if let Some(r) = store.get_record(id) {
            if r.timestamp < min_ts { min_ts = r.timestamp; }
            if r.timestamp > max_ts { max_ts = r.timestamp; }
        }
    }

    if min_ts > max_ts {
        return TimelineResult { buckets: vec![], total: 0 };
    }

    let n = bucket_count.clamp(1, 100);

    // If all events are at the same millisecond, use a single bucket
    let span = max_ts - min_ts;
    let bucket_ms = if span == 0 { 1 } else { (span + n as i64 - 1) / n as i64 };

    let actual_n = if span == 0 { 1 } else { ((span + bucket_ms - 1) / bucket_ms) as usize };
    let mut counts = vec![0usize; actual_n];

    for &id in ids {
        if let Some(r) = store.get_record(id) {
            let idx = ((r.timestamp - min_ts) / bucket_ms) as usize;
            let idx = idx.min(actual_n - 1);
            counts[idx] += 1;
        }
    }

    let buckets = counts
        .into_iter()
        .enumerate()
        .map(|(i, count)| {
            let start_ms = min_ts + i as i64 * bucket_ms;
            TimeBucket {
                start_ms,
                end_ms: start_ms + bucket_ms - 1,
                count,
            }
        })
        .collect();

    TimelineResult {
        buckets,
        total: ids.len(),
    }
}

// ---------------------------------------------------------------------------
// Field value aggregation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldValueCount {
    pub value: String,
    pub count: usize,
}

/// Merge counts from `b` into `a` (used as the rayon reduce step).
fn merge_counts<K: std::hash::Hash + Eq>(
    mut a: HashMap<K, usize>,
    b: HashMap<K, usize>,
) -> HashMap<K, usize> {
    for (k, v) in b {
        *a.entry(k).or_insert(0) += v;
    }
    a
}

fn top_n_counts(counts: Vec<FieldValueCount>, top_n: usize) -> Vec<FieldValueCount> {
    let mut result = counts;
    result.sort_unstable_by(|a, b| b.count.cmp(&a.count));
    result.truncate(top_n);
    result
}

/// Top-N values of `field` among the records matching `query`.
///
/// Counts come from intersecting each value's posting list with the query's
/// matching bitmap, so the cost scales with the number of *distinct values* in
/// the field rather than the number of matching records. The previous path
/// executed the query into a time-sorted `Vec<u32>` and then walked every
/// matching record building a hash map — for a filter panel issuing one of
/// these per field on every click, that sort and scan were the bulk of the wait.
///
/// `bucketName` is handled here too: it has an inverted index built during
/// ingestion, so it no longer needs its request-parameters blob parsed per
/// record.
///
/// Returns `None` if `field` has no index.
pub fn top_field_values_for_query(
    store: &Store,
    query: &crate::query::Query,
    field: &str,
    top_n: usize,
) -> Option<Vec<FieldValueCount>> {
    use rayon::prelude::*;

    let idx = store.index_for(field)?;

    // No filters and no time range: every record matches, so the posting list
    // length *is* the count — no intersection needed.
    if query.is_empty() {
        let mut values: Vec<FieldValueCount> = idx
            .iter()
            .map(|(k, v)| FieldValueCount { value: k.to_string(), count: v.len() as usize })
            .collect();
        return Some(top_n_counts(values.drain(..).collect(), top_n));
    }

    let matching = crate::query::matching_bitmap(store, query);
    let values: Vec<FieldValueCount> = idx
        .par_iter()
        .filter_map(|(k, posting)| {
            let count = posting.intersection_len(&matching) as usize;
            (count > 0).then(|| FieldValueCount { value: k.to_string(), count })
        })
        .collect();

    Some(top_n_counts(values, top_n))
}

/// Count field values across a slice of record IDs, return top-N by count.
///
/// Parallelized with rayon (per-thread map, then merge). For in-memory fields
/// the map keys on the interned `&str` — no per-record `String` allocation;
/// owned strings are materialized only for the ≤ unique-value final set.
pub fn top_field_values(
    store: &Store,
    ids: &[u32],
    field: &str,
    top_n: usize,
) -> Vec<FieldValueCount> {
    use rayon::prelude::*;

    // bucketName lives in the requestParameters blob — parse on demand (owned key).
    if field == "bucketName" {
        let counts = ids
            .par_iter()
            .fold(HashMap::<String, usize>::new, |mut m, &id| {
                if let Some(bucket) = store.parse_request_parameters(id).and_then(|p| {
                    p.get("bucketName").and_then(|v| v.as_str()).map(|s| s.to_string())
                }) {
                    *m.entry(bucket).or_insert(0) += 1;
                }
                m
            })
            .reduce(HashMap::new, merge_counts);
        let vec = counts
            .into_iter()
            .map(|(value, count)| FieldValueCount { value, count })
            .collect();
        return top_n_counts(vec, top_n);
    }

    let counts = ids
        .par_iter()
        .fold(HashMap::<&str, usize>::new, |mut m, &id| {
            if let Some(r) = store.get_record(id) {
                if let Some(v) = Store::field_str(r, field) {
                    *m.entry(v).or_insert(0) += 1;
                }
            }
            m
        })
        .reduce(HashMap::new, merge_counts);

    let vec = counts
        .into_iter()
        .map(|(value, count)| FieldValueCount { value: value.to_string(), count })
        .collect();
    top_n_counts(vec, top_n)
}

// ---------------------------------------------------------------------------
// Identity correlation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityEventSummary {
    pub event_name: String,
    pub count: usize,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub error_codes: Vec<String>,
}

/// A single event in the identity timeline (lightweight — no full raw record).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineEvent {
    pub id: u32,
    pub timestamp_ms: i64,
    pub event_time: String,
    pub event_name: String,
    pub aws_region: String,
    pub source_ip: Option<String>,
    pub error_code: Option<String>,
    pub user_agent: Option<String>,
    pub request_parameters: Option<Box<RawValue>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentitySummary {
    pub arn: String,
    pub total_events: usize,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    /// Per-eventName breakdown (sorted by count desc)
    pub by_event: Vec<IdentityEventSummary>,
    /// Chronological event feed (paginated, up to page_size per page)
    pub events: Vec<TimelineEvent>,
    pub page: usize,
    pub page_size: usize,
}

pub fn get_identity_summary(store: &Store, arn: &str, page: usize, page_size: usize, time_range: Option<(i64, i64)>) -> Option<IdentitySummary> {
    let ids = store.idx_user_arn.get(arn)
        .or_else(|| store.idx_user_name.get(arn))?;

    if ids.is_empty() {
        return None;
    }

    // Sort IDs by timestamp, filtering by time range if provided
    let mut timed_ids: Vec<(i64, u32)> = ids
        .iter()
        .filter_map(|id| store.get_record(id).map(|r| (r.timestamp, id)))
        .filter(|(ts, _)| {
            if let Some((start_ms, end_ms)) = time_range {
                *ts >= start_ms && *ts <= end_ms
            } else {
                true
            }
        })
        .collect();
    timed_ids.sort_unstable_by_key(|(ts, _)| *ts);

    let first_seen_ms = timed_ids.first().map(|(ts, _)| *ts).unwrap_or(0);
    let last_seen_ms = timed_ids.last().map(|(ts, _)| *ts).unwrap_or(0);

    // Group by event name
    struct EventAgg {
        count: usize,
        first: i64,
        last: i64,
        errors: std::collections::HashSet<String>,
    }

    let mut by_event: HashMap<String, EventAgg> = HashMap::new();
    for &(ts, id) in &timed_ids {
        if let Some(r) = store.get_record(id) {
            let agg = by_event.entry(r.record.event_name.to_string()).or_insert(EventAgg {
                count: 0,
                first: ts,
                last: ts,
                errors: std::collections::HashSet::new(),
            });
            agg.count += 1;
            if ts < agg.first { agg.first = ts; }
            if ts > agg.last { agg.last = ts; }
            if let Some(e) = &r.record.error_code {
                agg.errors.insert(e.to_string());
            }
        }
    }

    let mut by_event_vec: Vec<IdentityEventSummary> = by_event
        .into_iter()
        .map(|(event_name, agg)| IdentityEventSummary {
            event_name,
            count: agg.count,
            first_seen_ms: agg.first,
            last_seen_ms: agg.last,
            error_codes: agg.errors.into_iter().collect(),
        })
        .collect();
    by_event_vec.sort_unstable_by(|a, b| b.count.cmp(&a.count));

    // Build chronological event feed (paginated)
    let events: Vec<TimelineEvent> = timed_ids
        .iter()
        .skip(page * page_size)
        .take(page_size)
        .filter_map(|&(ts, id)| {
            store.get_record(id).map(|r| TimelineEvent {
                id,
                timestamp_ms: ts,
                event_time: r.record.event_time.to_string(),
                event_name: r.record.event_name.to_string(),
                aws_region: r.record.aws_region.to_string(),
                source_ip: r.record.source_ip_address.as_deref().map(|s| s.to_string()),
                error_code: r.record.error_code.as_deref().map(|s| s.to_string()),
                user_agent: r.record.user_agent.as_deref().map(|s| s.to_string()),
                request_parameters: store.load_raw_request_parameters(id),
            })
        })
        .collect();

    Some(IdentitySummary {
        arn: arn.to_string(),
        total_events: timed_ids.len(),
        first_seen_ms,
        last_seen_ms,
        by_event: by_event_vec,
        page,
        page_size,
        events,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::model::{CloudTrailRecord, IndexedRecord, UserIdentity};
    use crate::query::{execute, parse_query};

    fn rec(id: u32, event: &str, user: &str, region: &str) -> IndexedRecord {
        IndexedRecord {
            id,
            timestamp: id as i64 * 60_000,
            source_file: 0,
            record: CloudTrailRecord {
                event_time: Arc::from("2024-01-15T10:00:00Z"),
                event_source: Arc::from("iam.amazonaws.com"),
                event_name: Arc::from(event),
                aws_region: Arc::from(region),
                source_ip_address: Some(Arc::from("1.2.3.4")),
                user_agent: None,
                user_identity: UserIdentity {
                    identity_type: Some(Arc::from("IAMUser")),
                    principal_id: None,
                    arn: None,
                    account_id: None,
                    access_key_id: None,
                    user_name: Some(Arc::from(user)),
                    session_context: None,
                    invoked_by: None,
                },
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

    fn store_of(records: Vec<IndexedRecord>) -> Store {
        let mut store = Store::new();
        store.blob_store.seal().expect("seal");
        for r in &records {
            store.idx_event_name.entry(r.record.event_name.clone()).or_default().insert(r.id);
            store.idx_region.entry(r.record.aws_region.clone()).or_default().insert(r.id);
            if let Some(u) = &r.record.user_identity.user_name {
                store.idx_user_name.entry(u.clone()).or_default().insert(r.id);
            }
            if let Some(t) = &r.record.user_identity.identity_type {
                store.idx_identity_type.entry(t.clone()).or_default().insert(r.id);
            }
        }
        let mut sorted: Vec<(i64, u32)> = records.iter().map(|r| (r.timestamp, r.id)).collect();
        sorted.sort_unstable_by_key(|(ts, _)| *ts);
        store.time_sorted_ids = sorted.into_iter().map(|(_, id)| id).collect();
        store.records = records;
        store
    }

    fn sample() -> Store {
        store_of(vec![
            rec(0, "CreateUser", "alice", "us-east-1"),
            rec(1, "CreateUser", "bob", "us-east-1"),
            rec(2, "DeleteUser", "alice", "eu-west-1"),
            rec(3, "ListUsers", "carol", "us-east-1"),
            rec(4, "ListUsers", "alice", "eu-west-1"),
        ])
    }

    /// The bitmap-intersection counting path must agree with the old
    /// execute-then-scan path it replaced, filters and negation included.
    #[test]
    fn counting_path_matches_scan_path() {
        let store = sample();
        for q in [
            "eventName=CreateUser",
            "userName=alice",
            "awsRegion=us-east-1",
            "userName!=alice",
            "eventName=ListUsers AND awsRegion=eu-west-1",
            "eventName=CreateUser OR eventName=DeleteUser",
        ] {
            let parsed = parse_query(q).expect("parse");
            for field in ["eventName", "userName", "awsRegion"] {
                let ids = execute(&store, &parsed, 0, usize::MAX).record_ids;
                let mut want = top_field_values(&store, &ids, field, 100);
                let mut got = top_field_values_for_query(&store, &parsed, field, 100).unwrap();
                want.sort_by(|a, b| a.value.cmp(&b.value));
                got.sort_by(|a, b| a.value.cmp(&b.value));
                let want: Vec<_> = want.iter().map(|c| (&c.value, c.count)).collect();
                let got: Vec<_> = got.iter().map(|c| (&c.value, c.count)).collect();
                assert_eq!(got, want, "query {q:?} field {field:?}");
            }
        }
    }

    /// An excluded value keeps a real count when its own clause is not applied —
    /// this is what keeps it clickable in the filter sidebar.
    #[test]
    fn excluded_value_still_counted_when_its_field_is_unscoped() {
        let store = sample();
        // The sidebar counts userName with the userName clause removed, so a
        // user excluded from the results still appears with their true count.
        let parsed = parse_query("awsRegion=us-east-1").expect("parse");
        let counts = top_field_values_for_query(&store, &parsed, "userName", 100).unwrap();
        let alice = counts.iter().find(|c| c.value == "alice").expect("alice listed");
        assert_eq!(alice.count, 1);
    }

    #[test]
    fn empty_query_counts_whole_index() {
        let store = sample();
        let parsed = parse_query("").expect("parse");
        let counts = top_field_values_for_query(&store, &parsed, "eventName", 100).unwrap();
        let total: usize = counts.iter().map(|c| c.count).sum();
        assert_eq!(total, 5);
    }

    #[test]
    fn unknown_field_is_none() {
        let store = sample();
        let parsed = parse_query("").expect("parse");
        assert!(top_field_values_for_query(&store, &parsed, "nope", 10).is_none());
    }
}
