use tauri::State;
use trail_inspector_core::detection::{run_all_rules, run_geo_rules, filter_alerts_by_time, Alert};
use crate::state::AppState;

/// Run all detection rules against the loaded dataset.
/// Includes GEO-01/GEO-02 if a GeoIP engine has been loaded.
/// If start_ms/end_ms are provided, alerts are post-filtered to only include
/// matching records within that time range.
/// Returns alerts sorted by severity descending (Critical first).
#[tauri::command]
pub async fn run_detections(
    start_ms: Option<i64>,
    end_ms: Option<i64>,
    state: State<'_, AppState>,
) -> Result<Vec<Alert>, String> {
    let store_guard = state.store.read().map_err(|e| format!("Lock error: {e}"))?;
    let store = store_guard.as_ref().ok_or("No dataset loaded")?;

    let mut alerts = run_all_rules(store);

    // Append geo rules if a GeoIP engine is available
    let geoip_guard = state.geoip.read().map_err(|e| format!("Lock error: {e}"))?;
    if let Some(geoip) = geoip_guard.as_ref() {
        let mut geo_alerts = run_geo_rules(store, geoip);
        alerts.append(&mut geo_alerts);
        // Re-sort combined list
        alerts.sort_by(|a, b| b.severity.cmp(&a.severity));
    }

    // Post-filter by time range if specified
    if let (Some(s), Some(e)) = (start_ms, end_ms) {
        alerts = filter_alerts_by_time(store, alerts, s, e);
    }

    Ok(alerts)
}
