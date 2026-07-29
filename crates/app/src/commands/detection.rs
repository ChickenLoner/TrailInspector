use tauri::State;
use trail_inspector_core::detection::{
    run_all_rules, run_geo_rules, filter_alerts_by_time, cap_alert_ids, Alert,
    custom_rules::run_custom_rules,
};
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
    state: State<'_, AppState>,
) -> Result<Vec<Alert>, String> {
    let store_guard = state.store_read()?;
    let store = store_guard.as_ref().ok_or("No dataset loaded")?;

    let mut alerts = run_all_rules(store);

    let geoip_guard = state.geoip_read()?;
    if let Some(geoip) = geoip_guard.as_ref() {
        let mut geo_alerts = run_geo_rules(store, geoip);
        alerts.append(&mut geo_alerts);
    }

    let rules_guard = state.custom_rules_read()?;
    let mut custom_alerts = run_custom_rules(&rules_guard, store);
    alerts.append(&mut custom_alerts);

    if let (Some(s), Some(e)) = (start_ms, end_ms) {
        alerts = filter_alerts_by_time(store, alerts, s, e);
    }

    cap_alert_ids(&mut alerts);
    alerts.sort_by(|a, b| b.severity.cmp(&a.severity));

    Ok(alerts)
}
