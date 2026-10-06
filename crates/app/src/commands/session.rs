use std::sync::Arc;
use tauri::State;
use trail_inspector_core::session::{SessionPage, SessionDetail, AlertStub, SessionSummary};
use trail_inspector_core::detection::{run_all_rules, run_geo_rules, finalize_alerts};
use crate::state::AppState;

/// List sessions with optional filtering and sorting.
/// Builds (and caches) the SessionIndex on first call after ingestion.
#[tauri::command]
pub async fn list_sessions(
    page: usize,
    page_size: usize,
    sort_by: String,
    filter_identity: Option<String>,
    filter_ip: Option<String>,
    start_ms: Option<i64>,
    end_ms: Option<i64>,
    state: State<'_, Arc<AppState>>,
) -> Result<SessionPage, String> {
    // CLAUDE.md: never send >500 records per IPC call.
    let page_size = page_size.clamp(1, 500);
    state.ensure_session_index()?;

    let sidx_guard = state.session_index_read()?;
    let index = sidx_guard.as_ref().ok_or("Session index unavailable")?;

    let time_range = match (start_ms, end_ms) {
        (Some(s), Some(e)) => Some((s, e)),
        _ => None,
    };
    let result = index.list_sessions(
        page,
        page_size,
        &sort_by,
        filter_identity.as_deref(),
        filter_ip.as_deref(),
        time_range,
    );
    Ok(result)
}

/// Get full session detail with paginated events.
#[tauri::command]
pub async fn get_session_detail(
    session_id: u32,
    events_page: usize,
    events_page_size: usize,
    state: State<'_, Arc<AppState>>,
) -> Result<SessionDetail, String> {
    // CLAUDE.md: never send >500 records per IPC call.
    let events_page_size = events_page_size.clamp(1, 500);
    let sidx_guard = state.session_index_read()?;
    let index = sidx_guard.as_ref().ok_or("Session index not built — call list_sessions first")?;

    let store_guard = state.store_read()?;
    let store = store_guard.as_ref().ok_or("No dataset loaded")?;

    index.get_session_detail(store, session_id, events_page, events_page_size)
        .ok_or_else(|| format!("Session {session_id} not found"))
}

/// Get alerts that overlap a specific session's events.
#[tauri::command]
pub async fn get_session_alerts(
    session_id: u32,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<AlertStub>, String> {
    // Full rule pass: keep it off the async workers (see run_detections).
    let state = Arc::clone(state.inner());
    tokio::task::spawn_blocking(move || {
        let sidx_guard = state.session_index_read()?;
        let index = sidx_guard.as_ref().ok_or("Session index not built")?;

        let store_guard = state.store_read()?;
        let store = store_guard.as_ref().ok_or("No dataset loaded")?;

        let mut alerts = run_all_rules(store);
        let geoip_guard = state.geoip_read()?;
        if let Some(geoip) = geoip_guard.as_ref() {
            alerts.extend(run_geo_rules(store, geoip));
        }
        let alerts = finalize_alerts(store, alerts, None);

        Ok(index.get_session_alerts(session_id, &alerts))
    })
    .await
    .map_err(|e| format!("Task join error: {e}"))?
}

/// Get sessions that contain events matching a given alert (by rule_id).
#[tauri::command]
pub async fn get_alert_sessions(
    rule_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<SessionSummary>, String> {
    // Builds the session index (first call) and runs every rule: both are heavy.
    let state = Arc::clone(state.inner());
    tokio::task::spawn_blocking(move || {
        state.ensure_session_index()?;

        let store_guard = state.store_read()?;
        let store = store_guard.as_ref().ok_or("No dataset loaded")?;

        let mut alerts = run_all_rules(store);
        let geoip_guard = state.geoip_read()?;
        if let Some(geoip) = geoip_guard.as_ref() {
            alerts.extend(run_geo_rules(store, geoip));
        }
        let alerts = finalize_alerts(store, alerts, None);

        let alert = alerts.into_iter()
            .find(|a| a.rule_id == rule_id)
            .ok_or_else(|| format!("Alert {rule_id} not found or did not fire"))?;

        let sidx_guard = state.session_index_read()?;
        let index = sidx_guard.as_ref().ok_or("Session index unavailable")?;

        Ok(index.get_alert_sessions(&alert))
    })
    .await
    .map_err(|e| format!("Task join error: {e}"))?
}
