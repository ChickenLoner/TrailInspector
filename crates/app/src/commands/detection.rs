use std::sync::Arc;
use tauri::State;
use trail_inspector_core::detection::{finalize_alerts, Alert};
use crate::state::AppState;

/// Run all detection rules (built-in + user-defined) against the loaded dataset.
/// Includes GEO-01/GEO-02 if a GeoIP engine is loaded.
/// If start_ms/end_ms are provided, alerts are post-filtered to only include
/// matching records within that time range.
/// Returns alerts sorted by severity descending (Critical first).
///
/// This is the IPC boundary, so it owns the id-list cap. Order matters:
/// filter by time on the full id set, then truncate. Capping first would
/// silently drop alerts whose first 100 ids sit outside the window, and would
/// leave custom-rule alerts uncapped entirely.
#[tauri::command]
pub async fn run_detections(
    start_ms: Option<i64>,
    end_ms: Option<i64>,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<Alert>, String> {
    // Running every rule over a large dataset takes seconds; doing it on an async worker would
    // stall every other command (search, timeline) until it finished. The guards are taken
    // inside the blocking task, so nothing is held across an await.
    let state = Arc::clone(state.inner());
    tokio::task::spawn_blocking(move || {
        // Cached across tab visits; only the cheap time filter and id cap run per call.
        let alerts = state.all_alerts()?;
        let time_range = match (start_ms, end_ms) {
            (Some(s), Some(e)) => Some((s, e)),
            _ => None,
        };
        state.with_store(|store| Ok(finalize_alerts(store, alerts, time_range)))
    })
    .await
    .map_err(|e| format!("Task join error: {e}"))?
}
