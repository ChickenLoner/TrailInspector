use tauri::State;
use trail_inspector_core::s3;
use crate::state::AppState;

#[tauri::command]
pub async fn get_s3_summary(
    start_ms: Option<i64>,
    end_ms: Option<i64>,
    bucket: Option<String>,
    ip: Option<String>,
    identity: Option<String>,
    state: State<'_, AppState>,
) -> Result<s3::S3Summary, String> {
    let guard = state.store.read().map_err(|e| format!("Lock error: {e}"))?;
    let store = guard.as_ref().ok_or("No dataset loaded")?;
    Ok(s3::get_s3_summary(store, start_ms, end_ms, bucket.as_deref(), ip.as_deref(), identity.as_deref()))
}
