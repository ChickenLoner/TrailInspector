use tauri::ipc::Channel;
use tauri::State;
use trail_inspector_core::store::{ProgressEvent, Store, IngestWarning};
use trail_inspector_core::fetch::FetchProgress;
use crate::state::AppState;
use std::path::PathBuf;

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum IngestProgress {
    /// Download phase — only emitted by the AWS fetch commands.
    Fetch(FetchProgress),
    Progress(ProgressEvent),
    Complete { records_total: usize, warnings: Vec<IngestWarning> },
    #[allow(dead_code)]
    Error { message: String },
}

/// Load a directory (or single file) into the app state, streaming progress.
///
/// Shared by `load_directory` and the AWS fetch command so the store swap and the
/// session-index invalidation below live in exactly one place — those two must
/// always happen together, and a duplicated copy is the kind of thing that rots.
pub(crate) async fn ingest_path_into_state(
    root: PathBuf,
    on_progress: Channel<IngestProgress>,
    state: &AppState,
) -> Result<usize, String> {
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
        // Invalidate cached session index so it is rebuilt on next access
        let mut sidx = state.session_index.write().map_err(|e| format!("Lock error: {e}"))?;
        *sidx = None;
    }

    let _ = on_progress.send(IngestProgress::Complete {
        records_total: total,
        warnings,
    });

    Ok(total)
}

#[tauri::command]
pub async fn load_directory(
    path: String,
    on_progress: Channel<IngestProgress>,
    state: State<'_, AppState>,
) -> Result<usize, String> {
    ingest_path_into_state(PathBuf::from(&path), on_progress, &state).await
}
