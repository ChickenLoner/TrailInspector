use tauri::State;
use trail_inspector_core::query::{execute, parse_query_opt};
use trail_inspector_core::stats::{
    build_timeline, get_identity_summary, top_field_values,
    FieldValueCount, IdentitySummary, TimelineResult,
};
use crate::state::AppState;

// Re-export the types so Tauri serialises them directly.
// (TimeBucket, TimelineResult, FieldValueCount, IdentitySummary all derive Serialize)

/// Return a histogram of events over time for the given query.
#[tauri::command]
pub async fn get_timeline(
    query: Option<String>,
    bucket_count: Option<usize>,
    state: State<'_, AppState>,
) -> Result<TimelineResult, String> {
    let bucket_count = bucket_count.unwrap_or(60).clamp(1, 100);

    state.with_store(|store| {
        let parsed = parse_query_opt(query.as_deref()).map_err(|e| format!("Query error: {e}"))?;

        // Fast path for empty query: iterate time_sorted_ids directly — no Vec allocation
        if parsed.is_empty() {
            return Ok(build_timeline(store, &store.time_sorted_ids, bucket_count));
        }

        let result = execute(store, &parsed, 0, usize::MAX);
        Ok(build_timeline(store, &result.record_ids, bucket_count))
    })
}

/// Return top-N values for a single field, optionally scoped to a query.
#[tauri::command]
pub async fn get_top_fields(
    field: String,
    query: Option<String>,
    top_n: Option<usize>,
    state: State<'_, AppState>,
) -> Result<Vec<FieldValueCount>, String> {
    let top_n = top_n.unwrap_or(20).min(100);

    state.with_store(|store| {
        let parsed = parse_query_opt(query.as_deref()).map_err(|e| format!("Query error: {e}"))?;

        // Fast path for empty query: read counts directly from the inverted index —
        // O(unique_values) instead of O(total_records), no Vec allocation
        if parsed.is_empty() {
            let idx = store
                .index_for(field.as_str())
                .ok_or_else(|| format!("Unknown field: {field}"))?;
            let mut values: Vec<FieldValueCount> = idx
                .iter()
                .map(|(k, v)| FieldValueCount { value: k.to_string(), count: v.len() as usize })
                .collect();
            values.sort_unstable_by(|a, b| b.count.cmp(&a.count));
            values.truncate(top_n);
            return Ok(values);
        }

        let result = execute(store, &parsed, 0, usize::MAX);
        Ok(top_field_values(store, &result.record_ids, &field, top_n))
    })
}

/// Return identity timeline for a given ARN.
/// If start_ms/end_ms are provided, only events within that range are included.
#[tauri::command]
pub async fn get_identity_summary_cmd(
    arn: String,
    page: Option<usize>,
    page_size: Option<usize>,
    start_ms: Option<i64>,
    end_ms: Option<i64>,
    state: State<'_, AppState>,
) -> Result<IdentitySummary, String> {
    let page = page.unwrap_or(0);
    let page_size = page_size.unwrap_or(500).min(500);
    let time_range = match (start_ms, end_ms) {
        (Some(s), Some(e)) => Some((s, e)),
        _ => None,
    };
    state.with_store(|store| {
        get_identity_summary(store, &arn, page, page_size, time_range)
            .ok_or_else(|| format!("No events for ARN: {arn}"))
    })
}
