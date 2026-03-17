use tauri::ipc::Channel;
use tauri::State;
use trail_inspector_core::store::{ProgressEvent, Store, IngestWarning};
use crate::state::AppState;
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum IngestProgress {
    Progress(ProgressEvent),
    Complete { records_total: usize, warnings: Vec<IngestWarning> },
    #[allow(dead_code)]
    Error { message: String },
}

#[tauri::command]
pub async fn load_directory(
    path: String,
    on_progress: Channel<IngestProgress>,
    state: State<'_, AppState>,
) -> Result<usize, String> {
    let root = Path::new(&path).to_path_buf();

    // Run blocking IO in a spawn_blocking thread so we don't block the async runtime
    let result = tokio::task::spawn_blocking(move || {
        let mut store = Store::new();
        let on_prog = on_progress.clone();
        let (total, warnings) = store.load_directory(&root, move |evt| {
            let _ = on_prog.send(IngestProgress::Progress(evt));
        })?;
        Ok::<(Store, usize, Vec<IngestWarning>, Channel<IngestProgress>), trail_inspector_core::error::CoreError>(
            (store, total, warnings, on_progress)
        )
    })
    .await
    .map_err(|e| format!("Task join error: {e}"))?
    .map_err(|e| format!("Ingest error: {e}"))?;

    let (new_store, total, warnings, on_progress) = result;

    {
        let mut guard = state.store.write().map_err(|e| format!("Lock error: {e}"))?;
        *guard = Some(new_store);
    }

    let _ = on_progress.send(IngestProgress::Complete {
        records_total: total,
        warnings,
    });

    Ok(total)
}
