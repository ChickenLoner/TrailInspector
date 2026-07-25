use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, State};
use trail_inspector_core::fetch::{
    self, AwsCredentials, FetchRequest, FetchSource, FetchSummary, ProfileInfo,
};

use crate::commands::ingest::{ingest_path_into_state, IngestProgress};
use crate::state::{AppState, StagedFetch};

/// List named AWS profiles for the picker.
///
/// Returns profile names and regions only — never credential values. See
/// `trail_inspector_core::fetch::profiles` for why that is structural rather
/// than a convention.
#[tauri::command]
pub async fn list_aws_profiles() -> Result<Vec<ProfileInfo>, String> {
    Ok(fetch::list_profiles())
}

/// List S3 buckets the credentials can see.
///
/// Exists because `DescribeTrails` is a separate permission that a read-only S3
/// role may lack, and emulated AWS often implements S3 without the CloudTrail
/// management API. Falls back to cached credentials like `check_aws` does.
#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn list_s3_buckets(
    profile: Option<String>,
    credentials: Option<AwsCredentials>,
    region: String,
    endpoint_url: Option<String>,
    state: State<'_, AppState>,
) -> Result<Vec<String>, String> {
    let credentials = match credentials {
        Some(c) => Some(c),
        None => state
            .aws_credentials
            .read()
            .map_err(|e| format!("Lock error: {e}"))?
            .clone(),
    };

    let req = FetchRequest {
        profile,
        credentials,
        region,
        source: FetchSource::TrailBucket,
        start_ms: None,
        end_ms: None,
        bucket: None,
        prefix: None,
        endpoint_url,
    };

    fetch::list_buckets(&req).await.map_err(|e| e.to_string())
}

/// Keep a path segment to characters that are safe on every platform.
fn sanitize(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect();
    if cleaned.is_empty() { "unknown".to_string() } else { cleaned }
}

/// Delete a previously staged download, ignoring failures.
///
/// Best-effort on purpose: a locked or already-removed directory must not turn
/// into an error the user has to think about.
fn discard_staged(staged: Option<StagedFetch>) {
    if let Some(s) = staged {
        let _ = std::fs::remove_dir_all(&s.dir);
    }
}

/// Check what a set of credentials can actually see, and stage it.
///
/// This performs the **full** download — paging through every event — so the count
/// reported is exact rather than an estimate. The bytes are kept on disk so
/// `pull_staged` is instant instead of paying the LookupEvents rate limit twice.
///
/// Credentials, when supplied, are cached in memory for the session so Pull and
/// repeat Checks don't need them retyped. Nothing is written to `~/.aws`.
#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn check_aws(
    profile: Option<String>,
    credentials: Option<AwsCredentials>,
    region: String,
    source: FetchSource,
    start_ms: Option<i64>,
    end_ms: Option<i64>,
    bucket: Option<String>,
    prefix: Option<String>,
    endpoint_url: Option<String>,
    on_progress: Channel<IngestProgress>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<FetchSummary, String> {
    if let (Some(s), Some(e)) = (start_ms, end_ms) {
        if s >= e {
            return Err("Start time must be before end time".into());
        }
    }

    // Fall back to cached credentials so a second Check doesn't need retyping.
    let credentials = match credentials {
        Some(c) => Some(c),
        None => state
            .aws_credentials
            .read()
            .map_err(|e| format!("Lock error: {e}"))?
            .clone(),
    };

    // A fresh Check supersedes any earlier one; drop those bytes now rather than
    // letting the cache dir accumulate a directory per attempt.
    let previous = state
        .aws_staged
        .write()
        .map_err(|e| format!("Lock error: {e}"))?
        .take();
    discard_staged(previous);

    let req = FetchRequest {
        profile,
        credentials: credentials.clone(),
        region,
        source,
        start_ms,
        end_ms,
        bucket,
        prefix,
        endpoint_url,
    };

    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);

    // Directory name identifies the run without embedding key material — a manual
    // credential fetch is labelled "manual", never by its access key id.
    let who = match (&req.credentials, &req.profile) {
        (Some(_), _) => "manual".to_string(),
        (None, Some(p)) if !p.trim().is_empty() => sanitize(p),
        _ => "default".to_string(),
    };
    let cache_root: PathBuf = app
        .path()
        .app_cache_dir()
        .map_err(|e| format!("Could not resolve cache directory: {e}"))?;
    let dest = cache_root
        .join("fetches")
        .join(format!("{stamp}-{who}-{}", sanitize(&req.region)));

    let prog = on_progress.clone();
    let on_fetch_progress = move |p| {
        let _ = prog.send(IngestProgress::Fetch(p));
    };

    let outcome = match req.source {
        FetchSource::LookupEvents => {
            fetch::fetch_lookup_events(&req, &dest, on_fetch_progress).await
        }
        FetchSource::TrailBucket => {
            fetch::fetch_trail_bucket(&req, &dest, on_fetch_progress).await
        }
    }
    .map_err(|e| {
        // Don't leave a half-written directory behind on failure.
        let _ = std::fs::remove_dir_all(&dest);
        e.to_string()
    })?;

    // Count via the real ingest parser, so the number shown is the number that
    // will actually load — not the fetcher's own tally.
    let dir = dest.clone();
    let mut summary = tokio::task::spawn_blocking(move || fetch::summarize_staged(&dir))
        .await
        .map_err(|e| format!("Task join error: {e}"))?;
    summary.trails = outcome.trails;
    summary.bucket = outcome.bucket;

    // Only cache credentials once they have been proven to work.
    if let Some(c) = credentials {
        *state
            .aws_credentials
            .write()
            .map_err(|e| format!("Lock error: {e}"))? = Some(c);
    }

    *state.aws_staged.write().map_err(|e| format!("Lock error: {e}"))? =
        Some(StagedFetch { dir: dest });

    Ok(summary)
}

/// Load the staged download into the analysis views.
///
/// No network access — the bytes were already fetched by `check_aws`.
#[tauri::command]
pub async fn pull_staged(
    on_progress: Channel<IngestProgress>,
    state: State<'_, AppState>,
) -> Result<usize, String> {
    let dir = {
        let guard = state.aws_staged.read().map_err(|e| format!("Lock error: {e}"))?;
        match guard.as_ref() {
            Some(s) => s.dir.clone(),
            None => return Err("Nothing staged — run Check first".into()),
        }
    };

    ingest_path_into_state(dir, on_progress, &state).await
}

/// Forget cached credentials and delete any staged download.
#[tauri::command]
pub async fn clear_aws_cache(state: State<'_, AppState>) -> Result<(), String> {
    *state
        .aws_credentials
        .write()
        .map_err(|e| format!("Lock error: {e}"))? = None;

    let staged = state
        .aws_staged
        .write()
        .map_err(|e| format!("Lock error: {e}"))?
        .take();
    discard_staged(staged);

    Ok(())
}

/// Whether credentials are currently cached, for the panel's indicator.
///
/// Returns a bool, never the values themselves.
#[tauri::command]
pub async fn has_cached_aws_credentials(state: State<'_, AppState>) -> Result<bool, String> {
    Ok(state
        .aws_credentials
        .read()
        .map_err(|e| format!("Lock error: {e}"))?
        .is_some())
}
