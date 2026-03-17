use std::io::Write;
use tauri::State;
use trail_inspector_core::export;
use crate::state::AppState;

/// Export matching records as CSV to the given file path.
/// Returns the number of data rows written (excluding the header).
#[tauri::command]
pub async fn export_csv(
    query: Option<String>,
    path: String,
    state: State<'_, AppState>,
) -> Result<usize, String> {
    let guard = state.store.read().map_err(|e| format!("Lock error: {e}"))?;
    let store = guard.as_ref().ok_or("No dataset loaded")?;

    let bytes = export::export_csv(store, query.as_deref())
        .map_err(|e| format!("Export error: {e}"))?;

    // Count newlines minus 1 (header) to get data row count
    let row_count = bytes.iter().filter(|&&b| b == b'\n').count().saturating_sub(1);

    let mut file = std::fs::File::create(&path)
        .map_err(|e| format!("Failed to create file {path}: {e}"))?;
    file.write_all(&bytes)
        .map_err(|e| format!("Failed to write file {path}: {e}"))?;

    Ok(row_count)
}

/// Export matching records as JSON to the given file path.
/// Returns the number of records written.
#[tauri::command]
pub async fn export_json(
    query: Option<String>,
    path: String,
    state: State<'_, AppState>,
) -> Result<usize, String> {
    let guard = state.store.read().map_err(|e| format!("Lock error: {e}"))?;
    let store = guard.as_ref().ok_or("No dataset loaded")?;

    let bytes = export::export_json(store, query.as_deref())
        .map_err(|e| format!("Export error: {e}"))?;

    // Count records by parsing the JSON array length
    let record_count: usize = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| v.as_array().map(|a| a.len()))
        .unwrap_or(0);

    let mut file = std::fs::File::create(&path)
        .map_err(|e| format!("Failed to create file {path}: {e}"))?;
    file.write_all(&bytes)
        .map_err(|e| format!("Failed to write file {path}: {e}"))?;

    Ok(record_count)
}
