use tauri::State;
use trail_inspector_core::session::{SessionIndex, SessionPage, SessionDetail, AlertStub, SessionSummary};
use trail_inspector_core::detection::{run_all_rules, run_geo_rules};
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
    state: State<'_, AppState>,
) -> Result<SessionPage, String> {
    // Ensure session index exists (build lazily)
    {
        let needs_build = state.session_index.read()
            .map_err(|e| format!("Lock error: {e}"))?
            .is_none();

        if needs_build {
            let store_guard = state.store.read().map_err(|e| format!("Lock error: {e}"))?;
            let store = store_guard.as_ref().ok_or("No dataset loaded")?;
            let index = SessionIndex::build(store);
            let mut sidx = state.session_index.write().map_err(|e| format!("Lock error: {e}"))?;
            *sidx = Some(index);
        }
    }

    let sidx_guard = state.session_index.read().map_err(|e| format!("Lock error: {e}"))?;
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
    state: State<'_, AppState>,
) -> Result<SessionDetail, String> {
    let sidx_guard = state.session_index.read().map_err(|e| format!("Lock error: {e}"))?;
    let index = sidx_guard.as_ref().ok_or("Session index not built — call list_sessions first")?;

    let store_guard = state.store.read().map_err(|e| format!("Lock error: {e}"))?;
    let store = store_guard.as_ref().ok_or("No dataset loaded")?;

    index.get_session_detail(store, session_id, events_page, events_page_size)
        .ok_or_else(|| format!("Session {session_id} not found"))
}

/// Get alerts that overlap a specific session's events.
#[tauri::command]
pub async fn get_session_alerts(
    session_id: u32,
    state: State<'_, AppState>,
) -> Result<Vec<AlertStub>, String> {
    let sidx_guard = state.session_index.read().map_err(|e| format!("Lock error: {e}"))?;
    let index = sidx_guard.as_ref().ok_or("Session index not built")?;

    let store_guard = state.store.read().map_err(|e| format!("Lock error: {e}"))?;
    let store = store_guard.as_ref().ok_or("No dataset loaded")?;

    let mut alerts = run_all_rules(store);
    let geoip_guard = state.geoip.read().map_err(|e| format!("Lock error: {e}"))?;
    if let Some(geoip) = geoip_guard.as_ref() {
        alerts.extend(run_geo_rules(store, geoip));
    }

    Ok(index.get_session_alerts(session_id, &alerts))
}

/// Get sessions that contain events matching a given alert (by rule_id).
#[tauri::command]
pub async fn get_alert_sessions(
    rule_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<SessionSummary>, String> {
    // Ensure session index exists
    {
        let needs_build = state.session_index.read()
            .map_err(|e| format!("Lock error: {e}"))?
            .is_none();
        if needs_build {
            let store_guard = state.store.read().map_err(|e| format!("Lock error: {e}"))?;
            let store = store_guard.as_ref().ok_or("No dataset loaded")?;
            let index = SessionIndex::build(store);
            let mut sidx = state.session_index.write().map_err(|e| format!("Lock error: {e}"))?;
            *sidx = Some(index);
        }
    }

    let store_guard = state.store.read().map_err(|e| format!("Lock error: {e}"))?;
    let store = store_guard.as_ref().ok_or("No dataset loaded")?;

    let mut alerts = run_all_rules(store);
    let geoip_guard = state.geoip.read().map_err(|e| format!("Lock error: {e}"))?;
    if let Some(geoip) = geoip_guard.as_ref() {
        alerts.extend(run_geo_rules(store, geoip));
    }

    let alert = alerts.into_iter()
        .find(|a| a.rule_id == rule_id)
        .ok_or_else(|| format!("Alert {rule_id} not found or did not fire"))?;

    let sidx_guard = state.session_index.read().map_err(|e| format!("Lock error: {e}"))?;
    let index = sidx_guard.as_ref().ok_or("Session index unavailable")?;

    Ok(index.get_alert_sessions(&alert))
}
