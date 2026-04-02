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
pub fn build_timeline(store: &Store, ids: &[u64], bucket_count: usize) -> TimelineResult {
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

/// Count field values across a slice of record IDs, return top-N by count.
pub fn top_field_values(
    store: &Store,
    ids: &[u64],
    field: &str,
    top_n: usize,
) -> Vec<FieldValueCount> {
    let mut counts: HashMap<String, usize> = HashMap::new();

    for &id in ids {
        if let Some(r) = store.get_record(id) {
            if field == "bucketName" {
                // bucketName is in requestParameters JSON — parse on demand
                if let Some(bucket) = r.record.parse_request_parameters()
                    .and_then(|p| p.get("bucketName").and_then(|v| v.as_str()).map(|s| s.to_string()))
                {
                    *counts.entry(bucket).or_insert(0) += 1;
                }
                continue;
            }
            let val: Option<&str> = match field {
                "eventName" => Some(&r.record.event_name),
                "eventSource" => Some(&r.record.event_source),
                "awsRegion" => Some(&r.record.aws_region),
                "sourceIPAddress" => r.record.source_ip_address.as_deref(),
                "userArn" => r.record.user_identity.arn.as_deref(),
                "userName" => r.record.user_identity.user_name.as_deref(),
                "accountId" => r.record.user_identity.account_id.as_deref(),
                "errorCode" => r.record.error_code.as_deref(),
                "identityType" => r.record.user_identity.identity_type.as_deref(),
                "userAgent" => r.record.user_agent.as_deref(),
                _ => None,
            };
            if let Some(v) = val {
                *counts.entry(v.to_string()).or_insert(0) += 1;
            }
        }
    }

    let mut result: Vec<FieldValueCount> = counts
        .into_iter()
        .map(|(value, count)| FieldValueCount { value, count })
        .collect();

    result.sort_unstable_by(|a, b| b.count.cmp(&a.count));
    result.truncate(top_n);
    result
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
    pub id: u64,
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
    let mut timed_ids: Vec<(i64, u64)> = ids
        .iter()
        .filter_map(|&id| store.get_record(id).map(|r| (r.timestamp, id)))
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
            let agg = by_event.entry(r.record.event_name.clone()).or_insert(EventAgg {
                count: 0,
                first: ts,
                last: ts,
                errors: std::collections::HashSet::new(),
            });
            agg.count += 1;
            if ts < agg.first { agg.first = ts; }
            if ts > agg.last { agg.last = ts; }
            if let Some(e) = &r.record.error_code {
                agg.errors.insert(e.clone());
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
                event_time: r.record.event_time.clone(),
                event_name: r.record.event_name.clone(),
                aws_region: r.record.aws_region.clone(),
                source_ip: r.record.source_ip_address.clone(),
                error_code: r.record.error_code.clone(),
                user_agent: r.record.user_agent.clone(),
                request_parameters: r.record.request_parameters.clone(),
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
