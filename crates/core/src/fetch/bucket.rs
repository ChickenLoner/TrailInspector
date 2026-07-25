//! Download delivered CloudTrail objects straight from the trail's S3 bucket.
//!
//! Full history and full fidelity — no 90-day cap, and data events are included
//! exactly as delivered. Costs more permissions: `DescribeTrails`, `ListBucket`,
//! `GetObject`.
//!
//! Named `bucket.rs`, not `s3.rs`: [`crate::s3`] already exists and is *analysis of
//! S3 events found in logs*, not an S3 client.
//!
//! Objects are written preserving their key path, so the local tree mirrors
//! `AWSLogs/<account>/CloudTrail/<region>/<y>/<m>/<d>/...`. `Store::load_directory`
//! then walks it exactly like an `aws s3 sync` result.

use std::path::{Path, PathBuf};

use crate::error::CoreError;
use crate::fetch::{aws_message, sdk_config, FetchOutcome, FetchPhase, FetchProgress, FetchRequest};

/// Where a trail delivers its logs.
struct TrailTarget {
    bucket: String,
    prefix: Option<String>,
    /// Every trail name the account exposed, for the pre-pull summary.
    all_names: Vec<String>,
}

/// Ask CloudTrail which bucket the trail writes to.
async fn describe_target(
    cfg: &aws_config::SdkConfig,
    region: &str,
) -> Result<TrailTarget, CoreError> {
    let client = crate::fetch::cloudtrail_client(cfg);
    let resp = client
        .describe_trails()
        .send()
        .await
        .map_err(|e| CoreError::aws("DescribeTrails", aws_message(&e)))?;

    // Prefer a trail homed in the requested region; otherwise take the first that
    // names a bucket (multi-region trails are homed in exactly one region).
    let trails = resp.trail_list();
    let chosen = trails
        .iter()
        .find(|t| t.home_region() == Some(region) && t.s3_bucket_name().is_some())
        .or_else(|| trails.iter().find(|t| t.s3_bucket_name().is_some()));

    let trail = chosen.ok_or_else(|| CoreError::Aws {
        context: "DescribeTrails".into(),
        message: "No trail with an S3 bucket was found for this account/region".into(),
    })?;

    Ok(TrailTarget {
        bucket: trail.s3_bucket_name().unwrap_or_default().to_string(),
        prefix: trail.s3_key_prefix().map(str::to_string),
        all_names: trails
            .iter()
            .filter_map(|t| t.name().map(str::to_string))
            .collect(),
    })
}

/// Build the S3 client, forcing path-style addressing when an endpoint override is
/// in play — LocalStack/moto rarely serve virtual-host-style bucket subdomains.
fn s3_client(cfg: &aws_config::SdkConfig, req: &FetchRequest) -> aws_sdk_s3::Client {
    let mut builder = aws_sdk_s3::config::Builder::from(cfg);
    if req.endpoint_url.as_deref().is_some_and(|u| !u.trim().is_empty()) {
        builder = builder.force_path_style(true);
    }
    aws_sdk_s3::Client::from_conf(builder.build())
}

/// Keep only objects that look like delivered CloudTrail logs and fall inside the
/// requested window. The date filter reads the `/YYYY/MM/DD/` path segments that
/// CloudTrail's key layout guarantees; keys that don't match that layout are kept
/// rather than dropped, so an unusual prefix can't silently lose data.
fn key_in_window(key: &str, start_ms: Option<i64>, end_ms: Option<i64>) -> bool {
    // Mirror `ingest::discovery`: any `.gz`, not just `.json.gz`. Real CloudTrail
    // delivers `.json.gz`, but emulated environments use names like `audit.log.gz`,
    // and an over-tight filter here drops them before they ever reach the parser.
    let k = key.to_lowercase();
    if !(k.ends_with(".json") || k.ends_with(".gz") || k.ends_with(".log")) {
        return false;
    }

    // No bounds at all means take everything; skip the date parse entirely.
    if start_ms.is_none() && end_ms.is_none() {
        return true;
    }

    let parts: Vec<&str> = key.split('/').collect();
    // Need at least y/m/d plus a filename.
    if parts.len() < 4 {
        return true;
    }

    let tail = &parts[parts.len() - 4..parts.len() - 1];
    let (Ok(y), Ok(m), Ok(d)) = (
        tail[0].parse::<i32>(),
        tail[1].parse::<u32>(),
        tail[2].parse::<u32>(),
    ) else {
        return true;
    };

    let Some(date) = chrono::NaiveDate::from_ymd_opt(y, m, d) else {
        return true;
    };
    let day_start = date.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp_millis();
    let day_end = day_start + 86_400_000;

    // Whole-day granularity: a day is kept if it overlaps the window at all.
    // An absent bound is treated as unbounded on that side. Trimming to the exact
    // instant happens later at query time.
    day_end > start_ms.unwrap_or(i64::MIN) && day_start < end_ms.unwrap_or(i64::MAX)
}

/// List bucket names the credentials can see.
///
/// Used to populate the bucket picker when `DescribeTrails` is unavailable and the
/// operator doesn't already know the bucket name.
pub async fn list_buckets(req: &FetchRequest) -> Result<Vec<String>, CoreError> {
    let cfg = sdk_config(req).await;
    let client = s3_client(&cfg, req);

    let resp = client
        .list_buckets()
        .send()
        .await
        .map_err(|e| CoreError::aws("ListBuckets", aws_message(&e)))?;

    Ok(resp
        .buckets()
        .iter()
        .filter_map(|b| b.name().map(str::to_string))
        .collect())
}

/// Download every in-window CloudTrail object into `dest`.
pub async fn fetch_trail_bucket<F>(
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

    // An explicit bucket skips DescribeTrails entirely. That call needs a
    // permission the S3 read path doesn't, and emulated AWS often implements S3
    // without the CloudTrail management API at all — so requiring discovery would
    // block cases that are otherwise perfectly workable.
    let target = match req.bucket.as_deref().map(str::trim).filter(|b| !b.is_empty()) {
        Some(bucket) => TrailTarget {
            bucket: bucket.to_string(),
            prefix: req.prefix.as_deref().map(str::trim).filter(|p| !p.is_empty()).map(str::to_string),
            all_names: Vec::new(),
        },
        None => describe_target(&cfg, &req.region).await?,
    };

    let client = s3_client(&cfg, req);

    on_progress(FetchProgress {
        phase: FetchPhase::Listing,
        items_done: 0,
        items_total: None,
        message: format!("Listing s3://{}", target.bucket),
    });

    // Collect the full key list first so the download phase has a real total and
    // the progress bar is determinate.
    let mut keys: Vec<String> = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let mut call = client.list_objects_v2().bucket(&target.bucket);
        if let Some(p) = &target.prefix {
            call = call.prefix(p);
        }
        if let Some(t) = &token {
            call = call.continuation_token(t);
        }

        let resp = call
            .send()
            .await
            .map_err(|e| CoreError::aws("ListObjectsV2", aws_message(&e)))?;

        for obj in resp.contents() {
            if let Some(k) = obj.key() {
                if key_in_window(k, req.start_ms, req.end_ms) {
                    keys.push(k.to_string());
                }
            }
        }

        on_progress(FetchProgress {
            phase: FetchPhase::Listing,
            items_done: keys.len(),
            items_total: None,
            message: format!("{} matching objects", keys.len()),
        });

        token = resp.next_continuation_token().map(str::to_string);
        if token.is_none() {
            break;
        }
    }

    let total = keys.len();
    let mut files_written = 0usize;

    for (i, key) in keys.iter().enumerate() {
        let resp = client
            .get_object()
            .bucket(&target.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| CoreError::aws(format!("GetObject {key}"), aws_message(&e)))?;

        let bytes = resp
            .body
            .collect()
            .await
            .map_err(|e| CoreError::aws(format!("GetObject {key}"), e))?
            .into_bytes();

        // Mirror the key path locally. `key` is server-supplied, so strip any
        // absolute or parent components before joining — an object named
        // `../../evil` must not escape `dest`.
        let rel: PathBuf = key
            .split('/')
            .filter(|seg| !seg.is_empty() && *seg != "." && *seg != "..")
            .collect();
        let out_path = dest.join(rel);

        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| CoreError::Io {
                path: parent.to_string_lossy().to_string(),
                source: e,
            })?;
        }
        std::fs::write(&out_path, &bytes).map_err(|e| CoreError::Io {
            path: out_path.to_string_lossy().to_string(),
            source: e,
        })?;

        files_written += 1;
        on_progress(FetchProgress {
            phase: FetchPhase::Downloading,
            items_done: i + 1,
            items_total: Some(total),
            message: format!("{}/{total} objects", i + 1),
        });
    }

    Ok(FetchOutcome {
        files_written,
        events_fetched: None,
        trails: target.all_names,
        bucket: Some(target.bucket),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400_000;
    /// 2026-07-25T00:00:00Z
    const JUL25: i64 = 1_784_937_600_000;

    #[test]
    fn rejects_non_log_extensions() {
        assert!(!key_in_window("AWSLogs/1/CloudTrail/us-east-1/2026/07/25/x.txt", None, None));
        assert!(key_in_window("AWSLogs/1/CloudTrail/us-east-1/2026/07/25/x.json.gz", None, None));
    }

    /// Emulated AWS delivers names like `audit.log.gz`; an extension filter tuned
    /// only for `.json.gz` drops the entire dataset silently.
    #[test]
    fn accepts_non_json_gzip_names() {
        assert!(key_in_window(
            "AWSLogs/us-east-1/CloudTrail/us-east-1/2026/06/24/audit.log.gz",
            None,
            None
        ));
        assert!(key_in_window("logs/2026/06/24/audit.LOG.GZ", None, None));
    }

    /// The `audit.log.gz` layout still date-filters correctly: the four segments
    /// before the filename are region/YYYY/MM/DD.
    #[test]
    fn date_filter_works_on_audit_log_layout() {
        let k = "AWSLogs/us-east-1/CloudTrail/us-east-1/2026/07/25/audit.log.gz";
        assert!(key_in_window(k, Some(JUL25), Some(JUL25 + DAY)));
        assert!(!key_in_window(k, Some(JUL25 + 2 * DAY), Some(JUL25 + 5 * DAY)));
    }

    #[test]
    fn keeps_day_overlapping_window() {
        let k = "AWSLogs/1/CloudTrail/us-east-1/2026/07/25/x.json.gz";
        assert!(key_in_window(k, Some(JUL25), Some(JUL25 + DAY)));
    }

    #[test]
    fn drops_day_outside_window() {
        let k = "AWSLogs/1/CloudTrail/us-east-1/2026/07/25/x.json.gz";
        // Window entirely before that day.
        assert!(!key_in_window(k, Some(JUL25 - 5 * DAY), Some(JUL25 - DAY)));
        // Window entirely after.
        assert!(!key_in_window(k, Some(JUL25 + 2 * DAY), Some(JUL25 + 5 * DAY)));
    }

    /// No bounds means take everything.
    #[test]
    fn unbounded_window_keeps_every_log() {
        let k = "AWSLogs/1/CloudTrail/us-east-1/2020/01/01/x.json.gz";
        assert!(key_in_window(k, None, None));
    }

    /// A single open-ended bound still filters the other side.
    #[test]
    fn half_open_window_filters_one_side() {
        let k = "AWSLogs/1/CloudTrail/us-east-1/2026/07/25/x.json.gz";
        assert!(key_in_window(k, Some(JUL25 - DAY), None));
        assert!(!key_in_window(k, Some(JUL25 + 2 * DAY), None));
        assert!(key_in_window(k, None, Some(JUL25 + DAY)));
        assert!(!key_in_window(k, None, Some(JUL25 - DAY)));
    }

    /// Unparseable layouts are kept, never silently dropped.
    #[test]
    fn keeps_keys_with_unexpected_layout() {
        assert!(key_in_window("weird.json.gz", Some(JUL25), Some(JUL25 + DAY)));
        assert!(key_in_window("a/b/c/notadate.json", Some(JUL25), Some(JUL25 + DAY)));
    }
}
