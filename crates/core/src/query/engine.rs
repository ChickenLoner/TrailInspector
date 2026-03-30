use std::collections::HashSet;
use crate::store::Store;
use super::filter::*;

pub struct QueryResult {
    /// Record IDs in time-sorted order for the requested page
    pub record_ids: Vec<u64>,
    /// Total matching records (before pagination)
    pub total: usize,
}

/// Execute a query against the store, returning paginated results sorted by timestamp.
pub fn execute(store: &Store, query: &Query, page: usize, page_size: usize) -> QueryResult {
    let matching = if query.is_empty() {
        store.time_sorted_ids.clone()
    } else {
        compute_matching_ids(store, query)
    };

    let total = matching.len();
    let start = page * page_size;
    let end = (start + page_size).min(total);

    let record_ids = if start < total {
        matching[start..end].to_vec()
    } else {
        vec![]
    };

    QueryResult { record_ids, total }
}

fn compute_matching_ids(store: &Store, query: &Query) -> Vec<u64> {
    // Start from time-filtered candidates for efficiency
    let time_candidates: Vec<u64> = match &query.time_range {
        None => store.time_sorted_ids.clone(),
        Some(tr) => {
            // time_sorted_ids is sorted by timestamp; binary search for the range
            let lo = store.time_sorted_ids.partition_point(|&id| {
                store.get_record(id).map(|r| r.timestamp < tr.start_ms).unwrap_or(false)
            });
            let hi = store.time_sorted_ids.partition_point(|&id| {
                store.get_record(id).map(|r| r.timestamp <= tr.end_ms).unwrap_or(false)
            });
            store.time_sorted_ids[lo..hi].to_vec()
        }
    };

    if query.filter_groups.is_empty() {
        return time_candidates;
    }

    let candidate_set: HashSet<u64> = time_candidates.into_iter().collect();

    // Union over OR-groups: each group is AND'd internally, then the results are OR'd.
    let mut result: HashSet<u64> = HashSet::new();
    for group in &query.filter_groups {
        let group_result = compute_and_group(store, &candidate_set, group);
        result.extend(group_result);
    }

    // Return IDs in time-sorted order
    store
        .time_sorted_ids
        .iter()
        .filter(|id| result.contains(id))
        .cloned()
        .collect()
}

/// Evaluate one AND-group against the candidate set, returning matching IDs.
fn compute_and_group(
    store: &Store,
    candidates: &HashSet<u64>,
    filters: &[crate::query::filter::FieldFilter],
) -> HashSet<u64> {
    let mut pos_sets: Vec<HashSet<u64>> = Vec::new();
    let mut neg_sets: Vec<HashSet<u64>> = Vec::new();

    for filter in filters {
        let ids: HashSet<u64> = match_field_filter(store, filter).into_iter().collect();
        if filter.negated {
            neg_sets.push(ids);
        } else {
            pos_sets.push(ids);
        }
    }

    // Intersect: start with candidates, apply positive filters, subtract negatives
    let mut result = candidates.clone();

    // Sort by size ascending to prune early (cheapest intersections first)
    pos_sets.sort_unstable_by_key(|s| s.len());
    for pos in &pos_sets {
        result.retain(|id| pos.contains(id));
        if result.is_empty() {
            return HashSet::new();
        }
    }

    for neg in &neg_sets {
        result.retain(|id| !neg.contains(id));
    }

    result
}

/// Return the record IDs that match the given field filter (ignoring the `negated` flag —
/// the caller handles negation by using the result as an exclusion set).
fn match_field_filter(store: &Store, filter: &FieldFilter) -> Vec<u64> {
    let idx = match filter.field {
        FieldName::EventName => &store.idx_event_name,
        FieldName::EventSource => &store.idx_event_source,
        FieldName::AwsRegion => &store.idx_region,
        FieldName::SourceIPAddress => &store.idx_source_ip,
        FieldName::UserArn => &store.idx_user_arn,
        FieldName::UserName => &store.idx_user_name,
        FieldName::AccountId => &store.idx_account_id,
        FieldName::ErrorCode => &store.idx_error_code,
        FieldName::IdentityType => &store.idx_identity_type,
        FieldName::UserAgent => &store.idx_user_agent,
        FieldName::BucketName => &store.idx_bucket_name,
    };

    match &filter.mode {
        MatchMode::Exact(val) => idx.get(val.as_str()).cloned().unwrap_or_default(),

        MatchMode::Prefix(prefix) => idx
            .iter()
            .filter(|(k, _)| k.to_lowercase().starts_with(prefix.as_str()))
            .flat_map(|(_, v)| v.iter().cloned())
            .collect(),

        MatchMode::Suffix(suffix) => idx
            .iter()
            .filter(|(k, _)| k.to_lowercase().ends_with(suffix.as_str()))
            .flat_map(|(_, v)| v.iter().cloned())
            .collect(),

        MatchMode::Contains(substr) => idx
            .iter()
            .filter(|(k, _)| k.to_lowercase().contains(substr.as_str()))
            .flat_map(|(_, v)| v.iter().cloned())
            .collect(),

        MatchMode::Exists => idx.values().flat_map(|v| v.iter().cloned()).collect(),
    }
}
