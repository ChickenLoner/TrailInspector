use tauri::State;
use trail_inspector_core::detection::{run_all_rules, Alert};
use crate::state::AppState;

/// Run all detection rules against the loaded dataset.
/// Returns alerts sorted by severity descending (Critical first).
#[tauri::command]
pub async fn run_detections(state: State<'_, AppState>) -> Result<Vec<Alert>, String> {
    let guard = state.store.read().map_err(|e| format!("Lock error: {e}"))?;
    let store = guard.as_ref().ok_or("No dataset loaded")?;

    let alerts = run_all_rules(store);
    Ok(alerts)
}
