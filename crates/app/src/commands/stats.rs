use tauri::State;
use trail_inspector_core::query::{execute, parse_query, Query};
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

    let guard = state.store.read().map_err(|e| format!("Lock error: {e}"))?;
    let store = guard.as_ref().ok_or("No dataset loaded")?;

    let parsed = match query.as_deref().map(str::trim) {
        Some(q) if !q.is_empty() => {
            parse_query(q).map_err(|e| format!("Query error: {e}"))?
        }
        _ => Query::default(),
    };

    // Get all matching IDs (no pagination — we need the full set for stats)
    let result = execute(store, &parsed, 0, usize::MAX);
    let timeline = build_timeline(store, &result.record_ids, bucket_count);

    Ok(timeline)
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

    let guard = state.store.read().map_err(|e| format!("Lock error: {e}"))?;
    let store = guard.as_ref().ok_or("No dataset loaded")?;

    let parsed = match query.as_deref().map(str::trim) {
        Some(q) if !q.is_empty() => {
            parse_query(q).map_err(|e| format!("Query error: {e}"))?
        }
        _ => Query::default(),
    };

    let result = execute(store, &parsed, 0, usize::MAX);
    let values = top_field_values(store, &result.record_ids, &field, top_n);

    Ok(values)
}

/// Return identity timeline for a given ARN.
#[tauri::command]
pub async fn get_identity_summary_cmd(
    arn: String,
    page: Option<usize>,
    page_size: Option<usize>,
    earliest_ms: Option<i64>,
    latest_ms: Option<i64>,
    state: State<'_, AppState>,
) -> Result<IdentitySummary, String> {
    let guard = state.store.read().map_err(|e| format!("Lock error: {e}"))?;
    let store = guard.as_ref().ok_or("No dataset loaded")?;

    let page = page.unwrap_or(0);
    let page_size = page_size.unwrap_or(500).min(500);
    get_identity_summary(store, &arn, page, page_size, earliest_ms, latest_ms)
        .ok_or_else(|| format!("No events for ARN: {arn}"))
}
