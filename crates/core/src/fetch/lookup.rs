//! Pull events via `cloudtrail:LookupEvents`.
//!
//! Needs only the `LookupEvents` permission — no S3 access — which is often all a
//! CTF or a locked-down audit role grants. Two limits are inherent to the API and
//! are surfaced rather than hidden: history is capped at 90 days, and the endpoint
//! is rate limited (~2 requests/second), so a wide window is genuinely slow.
//!
//! Each page is written verbatim as `{"Events":[{"CloudTrailEvent":"..."}]}`, the
//! exact shape `aws cloudtrail lookup-events` emits and that
//! [`crate::ingest::parser::parse_records`] already understands. No translation
//! step, so there is nothing here that can drift from the file-based path.

use std::path::Path;
use std::time::Duration;

use aws_sdk_cloudtrail::primitives::DateTime;

use crate::error::CoreError;
use crate::fetch::{
    aws_message, cloudtrail_client, sdk_config, FetchOutcome, FetchPhase, FetchProgress,
    FetchRequest,
};

/// Max events per page the API allows.
const PAGE_SIZE: i32 = 50;

/// Delay between pages. LookupEvents is throttled at roughly 2 TPS; pacing
/// ourselves is cheaper than eating `ThrottlingException` and retrying.
const PAGE_DELAY: Duration = Duration::from_millis(500);

/// Fetch every event in the request window into `dest`, one JSON file per page.
pub async fn fetch_lookup_events<F>(
    req: &FetchRequest,
    dest: &Path,
    on_progress: F,
) -> Result<FetchOutcome, CoreError>
where
    F: Fn(FetchProgress) + Send + Sync,
{
    on_progress(FetchProgress {
        phase: FetchPhase::Connecting,
        items_done: 0,
        items_total: None,
        message: format!("Resolving {} in {}", req.identity_label(), req.region),
    });

    let cfg = sdk_config(req).await;
    let client = cloudtrail_client(&cfg);

    std::fs::create_dir_all(dest).map_err(|e| CoreError::Io {
        path: dest.to_string_lossy().to_string(),
        source: e,
    })?;

    let mut token: Option<String> = None;
    let mut page_no: usize = 0;
    let mut events_total: usize = 0;
    let mut files_written: usize = 0;

    loop {
        // Bounds are optional: omitting them lets the API apply its own default
        // window (last 90 days) rather than us inventing one.
        let mut call = client.lookup_events().max_results(PAGE_SIZE);
        if let Some(start) = req.start_ms {
            call = call.start_time(DateTime::from_millis(start));
        }
        if let Some(end) = req.end_ms {
            call = call.end_time(DateTime::from_millis(end));
        }

        if let Some(t) = &token {
            call = call.next_token(t);
        }

        let resp = call
            .send()
            .await
            .map_err(|e| CoreError::aws("LookupEvents", aws_message(&e)))?;

        // `cloud_trail_event` is the escaped-JSON payload; everything else on the
        // Event struct duplicates fields already inside it, so only this is kept.
        let payloads: Vec<&str> = resp
            .events()
            .iter()
            .filter_map(|e| e.cloud_trail_event())
            .collect();

        if !payloads.is_empty() {
            let body = serde_json::json!({
                "Events": payloads
                    .iter()
                    .map(|p| serde_json::json!({ "CloudTrailEvent": p }))
                    .collect::<Vec<_>>()
            });

            let path = dest.join(format!("page-{page_no:05}.json"));
            let bytes = serde_json::to_vec(&body).map_err(|e| CoreError::Json {
                path: path.to_string_lossy().to_string(),
                source: e,
            })?;
            std::fs::write(&path, bytes).map_err(|e| CoreError::Io {
                path: path.to_string_lossy().to_string(),
                source: e,
            })?;

            files_written += 1;
            events_total += payloads.len();
        }

        page_no += 1;
        on_progress(FetchProgress {
            phase: FetchPhase::Downloading,
            items_done: events_total,
            // No total is knowable: the API is token-paginated with no count.
            items_total: None,
            message: format!("Page {page_no}, {events_total} events"),
        });

        token = resp.next_token().map(str::to_string);
        if token.is_none() {
            break;
        }

        tokio::time::sleep(PAGE_DELAY).await;
    }

    Ok(FetchOutcome {
        files_written,
        events_fetched: Some(events_total),
        trails: Vec::new(),
        bucket: None,
    })
}
