use roaring::RoaringBitmap;
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

/// Matching ids as a bitmap, skipping the time-ordering pass.
///
/// Counting callers — facet value counts — do not care about order, and for a
/// large result set the `O(k log k)` sort in [`compute_matching_ids`] dominates
/// the whole call. Keeping the set as a bitmap also lets callers answer "how
/// many of these are also in that posting list?" with a native intersection
/// instead of walking every record.
pub fn matching_bitmap(store: &Store, query: &Query) -> RoaringBitmap {
    let matched: Option<RoaringBitmap> = if query.filter_groups.is_empty() {
        None
    } else {
        let mut acc = RoaringBitmap::new();
        for group in &query.filter_groups {
            acc |= compute_and_group(store, group);
        }
        Some(acc)
    };

    match (&query.time_range, matched) {
        (None, None) => {
            let mut all = RoaringBitmap::new();
            all.insert_range(0..store.records.len() as u32);
            all
        }
        (Some(tr), None) => {
            let (lo, hi) = store.time_range_bounds(tr.start_ms, tr.end_ms);
            store.time_sorted_ids[lo..hi].iter().copied().collect()
        }
        (None, Some(bm)) => bm,
        (Some(tr), Some(bm)) => bm
            .iter()
            .filter(|&id| {
                store
                    .get_record(id)
                    .map(|r| r.timestamp >= tr.start_ms && r.timestamp <= tr.end_ms)
                    .unwrap_or(false)
            })
            .collect(),
    }
}

/// Compute the full matching id set, in time-sorted order.
///
/// Posting lists are `RoaringBitmap`s, so AND/OR/NOT are native compressed-bitmap
/// operations. The bitmap iterates ids in ascending order; the final step
/// reorders the (usually small) match set into timestamp order.
fn compute_matching_ids(store: &Store, query: &Query) -> Vec<u32> {
    // Union the OR-groups. `None` means "no field filters → every id".
    let matched: Option<RoaringBitmap> = if query.filter_groups.is_empty() {
        None
    } else {
        let mut acc = RoaringBitmap::new();
        for group in &query.filter_groups {
            acc |= compute_and_group(store, group);
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
        (None, Some(bm)) => reorder_to_time(store, bm.iter()),

        // Both — drop ids outside the window, then reorder into time order.
        (Some(tr), Some(bm)) => {
            let filtered = bm.iter().filter(|&id| {
                store
                    .get_record(id)
                    .map(|r| r.timestamp >= tr.start_ms && r.timestamp <= tr.end_ms)
                    .unwrap_or(false)
            });
            reorder_to_time(store, filtered)
        }
    }
}

/// Reorder a set of ids into ascending-timestamp order.
/// O(k log k) in the result size — cheaper than scanning the whole time index
/// whenever the result is small relative to the dataset.
fn reorder_to_time(store: &Store, ids: impl Iterator<Item = u32>) -> Vec<u32> {
    let mut timed: Vec<(i64, u32)> = ids
        .filter_map(|id| store.get_record(id).map(|r| (r.timestamp, id)))
        .collect();
    timed.sort_unstable_by_key(|(ts, _)| *ts);
    timed.into_iter().map(|(_, id)| id).collect()
}

/// Evaluate one AND-group, returning the matching id bitmap.
fn compute_and_group(store: &Store, filters: &[FieldFilter]) -> RoaringBitmap {
    let mut pos: Vec<RoaringBitmap> = Vec::new();
    let mut neg: Vec<RoaringBitmap> = Vec::new();

    for filter in filters {
        let bm = match_field_filter(store, filter);
        if filter.negated {
            neg.push(bm);
        } else {
            pos.push(bm);
        }
    }

    // Base set: intersection of positive filters (cheapest first to prune early),
    // or the full id space when the group is negative-only.
    let mut result = if pos.is_empty() {
        let mut all = RoaringBitmap::new();
        all.insert_range(0..store.records.len() as u32);
        all
    } else {
        pos.sort_unstable_by_key(|b| b.len());
        let mut acc = pos[0].clone();
        for p in &pos[1..] {
            acc &= p;
            if acc.is_empty() {
                return RoaringBitmap::new();
            }
        }
        acc
    };

    for n in &neg {
        result -= n;
    }
    result
}

/// Return the id bitmap matching a field filter (ignoring `negated` —
/// the caller subtracts it).
fn match_field_filter(store: &Store, filter: &FieldFilter) -> RoaringBitmap {
    let idx = match store.index_for(filter.field.as_str()) {
        Some(idx) => idx,
        None => return RoaringBitmap::new(),
    };

    match &filter.mode {
        // Single posting list.
        MatchMode::Exact(val) => idx.get(val.as_str()).cloned().unwrap_or_default(),

        // Wildcard / Exists modes union the posting lists of every matching key.
        // Case-insensitive key match is done in place (patterns are pre-lowercased
        // by the parser) — no per-key allocation.
        MatchMode::Prefix(prefix) => union_keys(idx, |k| ascii_ci_starts_with(k, prefix)),
        MatchMode::Suffix(suffix) => union_keys(idx, |k| ascii_ci_ends_with(k, suffix)),
        MatchMode::Contains(substr) => union_keys(idx, |k| ascii_ci_contains(k, substr)),
        MatchMode::Exists => union_keys(idx, |_| true),
    }
}

/// Union the posting lists of every key satisfying `pred`.
fn union_keys<F>(
    idx: &std::collections::HashMap<std::sync::Arc<str>, RoaringBitmap>,
    pred: F,
) -> RoaringBitmap
where
    F: Fn(&str) -> bool,
{
    let mut out = RoaringBitmap::new();
    for (k, v) in idx {
        if pred(k) {
            out |= v;
        }
    }
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
