use tauri::State;
use trail_inspector_core::session::{SessionIndex, SessionPage, SessionDetail};
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

    let result = index.list_sessions(
        page,
        page_size,
        &sort_by,
        filter_identity.as_deref(),
        filter_ip.as_deref(),
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
