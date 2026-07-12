use crate::store::Store;
use super::filter::*;

pub struct QueryResult {
    /// Record IDs in time-sorted order for the requested page
    pub record_ids: Vec<u32>,
    /// Total matching records (before pagination)
    pub total: usize,
}

/// Execute a query against the store, returning paginated results sorted by timestamp.
pub fn execute(store: &Store, query: &Query, page: usize, page_size: usize) -> QueryResult {
    // Fast path: no filters at all — paginate directly from the sorted index, no allocation
    if query.is_empty() {
        let total = store.time_sorted_ids.len();
        let start = page * page_size;
        let end = (start + page_size).min(total);
        let record_ids = if start < total {
            store.time_sorted_ids[start..end].to_vec()
        } else {
            vec![]
        };
        return QueryResult { record_ids, total };
    }

    let matching = compute_matching_ids(store, query);
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

/// Compute the full matching id set, in time-sorted order.
///
/// Posting lists are stored sorted-ascending by id (ids are assigned
/// sequentially at ingest), so all set algebra here is done with allocation-free
/// sorted-merge over `Vec<u32>` — no per-query `HashSet` of the whole dataset.
fn compute_matching_ids(store: &Store, query: &Query) -> Vec<u32> {
    // Union the OR-groups. `None` means "no field filters → every id".
    let matched: Option<Vec<u32>> = if query.filter_groups.is_empty() {
        None
    } else {
        let mut acc: Vec<u32> = Vec::new();
        for group in &query.filter_groups {
            let g = compute_and_group(store, group);
            acc = union_sorted(&acc, &g);
        }
        Some(acc)
    };

    match (&query.time_range, matched) {
        // No filters, no range — the empty-query fast path in `execute` covers the
        // common case; this arm is only hit when a caller passes usize::MAX paging.
        (None, None) => store.time_sorted_ids.clone(),

        // Time range only — the sorted index slice is already in time order.
        (Some(tr), None) => {
            let (lo, hi) = store.time_range_bounds(tr.start_ms, tr.end_ms);
            store.time_sorted_ids[lo..hi].to_vec()
        }

        // Field filters only — reorder the by-id match set into time order.
        (None, Some(ids)) => reorder_to_time(store, ids),

        // Both — drop ids outside the window, then reorder into time order.
        (Some(tr), Some(ids)) => {
            let filtered: Vec<u32> = ids
                .into_iter()
                .filter(|&id| {
                    store
                        .get_record(id)
                        .map(|r| r.timestamp >= tr.start_ms && r.timestamp <= tr.end_ms)
                        .unwrap_or(false)
                })
                .collect();
            reorder_to_time(store, filtered)
        }
    }
}

/// Reorder a by-id id set into ascending-timestamp order.
/// O(k log k) in the result size — cheaper than scanning the whole time index
/// whenever the result is small relative to the dataset.
fn reorder_to_time(store: &Store, ids: Vec<u32>) -> Vec<u32> {
    let mut timed: Vec<(i64, u32)> = ids
        .into_iter()
        .filter_map(|id| store.get_record(id).map(|r| (r.timestamp, id)))
        .collect();
    timed.sort_unstable_by_key(|(ts, _)| *ts);
    timed.into_iter().map(|(_, id)| id).collect()
}

/// Evaluate one AND-group, returning matching ids sorted ascending by id.
fn compute_and_group(store: &Store, filters: &[FieldFilter]) -> Vec<u32> {
    let mut pos: Vec<Vec<u32>> = Vec::new();
    let mut neg: Vec<Vec<u32>> = Vec::new();

    for filter in filters {
        let ids = match_field_filter(store, filter);
        if filter.negated {
            neg.push(ids);
        } else {
            pos.push(ids);
        }
    }

    // Base set: intersection of positive filters (cheapest first to prune early),
    // or the full id space when the group is negative-only.
    let mut result = if pos.is_empty() {
        (0..store.records.len() as u32).collect::<Vec<u32>>()
    } else {
        pos.sort_unstable_by_key(|s| s.len());
        let mut acc = pos[0].clone();
        for p in &pos[1..] {
            acc = intersect_sorted(&acc, p);
            if acc.is_empty() {
                return Vec::new();
            }
        }
        acc
    };

    for n in &neg {
        result = difference_sorted(&result, n);
    }
    result
}

/// Return ids matching a field filter (ignoring `negated` — the caller subtracts).
/// Result is sorted ascending by id and deduplicated.
fn match_field_filter(store: &Store, filter: &FieldFilter) -> Vec<u32> {
    let idx = match store.index_for(filter.field.as_str()) {
        Some(idx) => idx,
        None => return Vec::new(),
    };

    match &filter.mode {
        // Single posting list — already sorted ascending, no dedup needed.
        MatchMode::Exact(val) => idx.get(val.as_str()).cloned().unwrap_or_default(),

        // Wildcard / Exists modes union several posting lists. Each indexed field
        // is single-valued per record, so the lists are disjoint; we still
        // sort+dedup defensively. Case-insensitive key match is done in place
        // (patterns are pre-lowercased by the parser) — no per-key allocation.
        MatchMode::Prefix(prefix) => collect_keys(idx, |k| ascii_ci_starts_with(k, prefix)),
        MatchMode::Suffix(suffix) => collect_keys(idx, |k| ascii_ci_ends_with(k, suffix)),
        MatchMode::Contains(substr) => collect_keys(idx, |k| ascii_ci_contains(k, substr)),
        MatchMode::Exists => collect_keys(idx, |_| true),
    }
}

/// Collect ids from every posting list whose key satisfies `pred`, sorted+deduped.
fn collect_keys<F>(idx: &std::collections::HashMap<std::sync::Arc<str>, Vec<u32>>, pred: F) -> Vec<u32>
where
    F: Fn(&str) -> bool,
{
    let mut out: Vec<u32> = Vec::new();
    for (k, v) in idx {
        if pred(k) {
            out.extend_from_slice(v);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

// ---------------------------------------------------------------------------
// Sorted-merge set algebra (both inputs sorted ascending, output sorted)
// ---------------------------------------------------------------------------

fn intersect_sorted(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut out = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                out.push(a[i]);
                i += 1;
                j += 1;
            }
        }
    }
    out
}

fn union_sorted(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(a.len() + b.len());
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => {
                out.push(a[i]);
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                out.push(b[j]);
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                out.push(a[i]);
                i += 1;
                j += 1;
            }
        }
    }
    out.extend_from_slice(&a[i..]);
    out.extend_from_slice(&b[j..]);
    out
}

/// `a` minus `b` (elements of `a` not in `b`).
fn difference_sorted(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut out = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => {
                out.push(a[i]);
                i += 1;
            }
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                i += 1;
                j += 1;
            }
        }
    }
    out.extend_from_slice(&a[i..]);
    out
}

// ---------------------------------------------------------------------------
// Allocation-free ASCII case-insensitive matching (patterns pre-lowercased)
// ---------------------------------------------------------------------------

fn ascii_ci_starts_with(hay: &str, needle_lower: &str) -> bool {
    let (h, n) = (hay.as_bytes(), needle_lower.as_bytes());
    h.len() >= n.len() && h[..n.len()].iter().zip(n).all(|(a, b)| a.to_ascii_lowercase() == *b)
}

fn ascii_ci_ends_with(hay: &str, needle_lower: &str) -> bool {
    let (h, n) = (hay.as_bytes(), needle_lower.as_bytes());
    h.len() >= n.len()
        && h[h.len() - n.len()..].iter().zip(n).all(|(a, b)| a.to_ascii_lowercase() == *b)
}

fn ascii_ci_contains(hay: &str, needle_lower: &str) -> bool {
    let (h, n) = (hay.as_bytes(), needle_lower.as_bytes());
    if n.is_empty() {
        return true;
    }
    if h.len() < n.len() {
        return false;
    }
    (0..=h.len() - n.len())
        .any(|i| h[i..i + n.len()].iter().zip(n).all(|(a, b)| a.to_ascii_lowercase() == *b))
}
