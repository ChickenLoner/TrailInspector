use std::sync::Arc;
use std::io::BufWriter;
use tauri::State;
use trail_inspector_core::export;
use crate::state::AppState;

/// Export matching records as CSV to the given file path.
/// Returns the number of data rows written (excluding the header).
#[tauri::command]
pub async fn export_csv(
    query: Option<String>,
    path: String,
    state: State<'_, Arc<AppState>>,
) -> Result<usize, String> {
    // CPU and disk bound; keep it off the async workers. Rows stream straight to the file.
    let state = Arc::clone(state.inner());
    tokio::task::spawn_blocking(move || {
        state.with_store(|store| {
            let file = std::fs::File::create(&path)
                .map_err(|e| format!("Failed to create file {path}: {e}"))?;
            let mut w = BufWriter::new(file);
            export::export_csv_to(store, query.as_deref(), &mut w)
                .map_err(|e| format!("Export error: {e}"))
        })
    })
    .await
    .map_err(|e| format!("Task join error: {e}"))?
}

/// Export matching records as JSON to the given file path.
/// Returns the number of records written.
#[tauri::command]
pub async fn export_json(
    query: Option<String>,
    path: String,
    state: State<'_, Arc<AppState>>,
) -> Result<usize, String> {
    let state = Arc::clone(state.inner());
    tokio::task::spawn_blocking(move || {
        state.with_store(|store| {
            let file = std::fs::File::create(&path)
                .map_err(|e| format!("Failed to create file {path}: {e}"))?;
            let mut w = BufWriter::new(file);
            export::export_json_to(store, query.as_deref(), &mut w)
                .map_err(|e| format!("Export error: {e}"))
        })
    })
    .await
    .map_err(|e| format!("Task join error: {e}"))?
}
