//! Pull CloudTrail logs directly from AWS onto local disk.
//!
//! Everything here is gated behind the `aws` cargo feature so the default build
//! of this crate stays synchronous and offline.
//!
//! Design: fetching **never** touches [`crate::store::Store`]. Each fetcher writes
//! plain files into a destination directory and returns a summary; the caller then
//! hands that directory to `Store::load_directory` exactly as if the user had
//! picked it with a file dialog. That keeps ingest, parsing, and indexing on one
//! code path regardless of where the bytes came from.

// Profile listing is plain std (INI section names only), so it stays available in
// the default offline build — the picker can populate without the SDK.
pub mod profiles;

#[cfg(feature = "aws")]
pub mod bucket;
#[cfg(feature = "aws")]
pub mod lookup;

use serde::{Deserialize, Serialize};

pub use profiles::{list_profiles, ProfileInfo};

#[cfg(feature = "aws")]
pub use bucket::{fetch_trail_bucket, list_buckets};
#[cfg(feature = "aws")]
pub use lookup::fetch_lookup_events;

/// Which AWS source to pull from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FetchSource {
    /// `cloudtrail:LookupEvents` — no S3 access needed, but capped at 90 days.
    LookupEvents,
    /// `DescribeTrails` + S3 download of the delivered `.json.gz` objects.
    /// Full history and full fidelity, but needs bucket read permissions.
    TrailBucket,
}

/// Directly supplied AWS credentials, as typed into the app.
///
/// The alternative to [`FetchRequest::profile`], for the case where there is no
/// `~/.aws/credentials` to point at — handed a key/secret/token pair for a CTF or a
/// one-off engagement.
///
/// `Debug` is implemented by hand to redact the secret and token: the derived impl
/// would print them in full, and these values travel through error paths and
/// anything that formats a request.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    /// Required for temporary credentials (`ASIA...` keys), which is what a CTF
    /// or an assumed role hands out.
    #[serde(default)]
    pub session_token: Option<String>,
}

impl std::fmt::Debug for AwsCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field("session_token", &self.session_token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// One fetch job.
///
/// Note the absence of `Serialize`: this struct can hold secret material, and
/// deriving it would make accidental round-tripping to the frontend or a log a
/// one-line mistake.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FetchRequest {
    /// Named profile from `~/.aws/config` / `~/.aws/credentials`.
    ///
    /// When set, only the *name* travels through this struct — the SDK resolves the
    /// secrets itself. Ignored when `credentials` is supplied.
    #[serde(default)]
    pub profile: Option<String>,
    /// Credentials typed directly into the app. Takes precedence over `profile`.
    #[serde(default)]
    pub credentials: Option<AwsCredentials>,
    pub region: String,
    pub source: FetchSource,
    /// Inclusive lower bound, epoch millis. `None` means "no lower bound" — for
    /// LookupEvents the API then applies its own 90-day default; for the S3 source
    /// it means every delivered object.
    #[serde(default)]
    pub start_ms: Option<i64>,
    /// Exclusive upper bound, epoch millis. `None` means "up to now".
    #[serde(default)]
    pub end_ms: Option<i64>,
    /// Read this bucket directly instead of discovering it via `DescribeTrails`.
    ///
    /// Two cases need this: a role with `s3:GetObject` but no
    /// `cloudtrail:DescribeTrails`, and emulated AWS (LocalStack, CTF mocks) that
    /// implements S3 but not the CloudTrail management API.
    #[serde(default)]
    pub bucket: Option<String>,
    /// Key prefix to narrow the listing. Only meaningful with `bucket`.
    #[serde(default)]
    pub prefix: Option<String>,
    /// Override the AWS service endpoint (the `aws --endpoint-url` equivalent).
    ///
    /// Needed for LocalStack, moto, and CTF-style emulated AWS. When set, S3 also
    /// switches to path-style addressing, since emulators rarely implement
    /// virtual-host-style bucket subdomains.
    #[serde(default)]
    pub endpoint_url: Option<String>,
}

impl FetchRequest {
    /// How to describe the identity in progress messages, without naming secrets.
    pub(crate) fn identity_label(&self) -> String {
        if self.credentials.is_some() {
            // Never the key id itself — this string reaches the UI.
            "supplied credentials".to_string()
        } else if let Some(p) = self.profile.as_deref().filter(|p| !p.trim().is_empty()) {
            format!("profile '{p}'")
        } else {
            "default credential chain".to_string()
        }
    }
}

/// Which stage of a fetch is running. Kept coarse — the UI shows this as a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FetchPhase {
    /// Resolving credentials and building the client.
    Connecting,
    /// Enumerating what needs downloading (paging LookupEvents, listing objects).
    Listing,
    /// Writing bytes to disk.
    Downloading,
}

/// Progress tick. `items_total` is `None` while the total is still unknown —
/// `LookupEvents` is a token-paginated API with no up-front count, so a
/// determinate progress bar is impossible until the last page arrives.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FetchProgress {
    pub phase: FetchPhase,
    pub items_done: usize,
    pub items_total: Option<usize>,
    pub message: String,
}

/// What a completed fetch produced.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FetchOutcome {
    /// Number of files written.
    pub files_written: usize,
    /// Number of CloudTrail events fetched, when the source can count them.
    /// `TrailBucket` leaves this `None` — the events are inside gzipped objects
    /// that have not been parsed yet at fetch time.
    pub events_fetched: Option<usize>,
    /// Trail names seen via `DescribeTrails`. Empty for the LookupEvents source,
    /// which never makes that call.
    #[serde(default)]
    pub trails: Vec<String>,
    #[serde(default)]
    pub bucket: Option<String>,
}

/// What a "check" found, before committing to load it into the analysis views.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FetchSummary {
    pub files: usize,
    /// Exact event count — the check pages through everything.
    pub events: usize,
    pub earliest_ms: Option<i64>,
    pub latest_ms: Option<i64>,
    /// Trail names discovered via `DescribeTrails`, when that call was made.
    #[serde(default)]
    pub trails: Vec<String>,
    #[serde(default)]
    pub bucket: Option<String>,
}

/// Count events and find the time range in an already-staged directory.
///
/// Runs the real ingest parser over the staged files rather than trusting the
/// fetcher's own tally, so the number shown before pulling is the number that will
/// actually load. Unparseable files are skipped — they surface as ingest warnings
/// at pull time, which is where they belong.
pub fn summarize_staged(dir: &std::path::Path) -> FetchSummary {
    use crate::ingest::{decompress, discovery, parser};

    let mut summary = FetchSummary::default();

    for path in discovery::find_log_files(dir) {
        // Same zip-vs-file split `Store::load_directory` uses.
        let is_zip = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("zip"));

        let batches = if is_zip {
            decompress::read_zip_entries(&path).unwrap_or_default()
        } else {
            match decompress::read_log_file(&path) {
                Ok(b) => vec![b],
                Err(_) => continue,
            }
        };

        for bytes in batches {
            let Ok(records) = parser::parse_records(&bytes, &path, 0, 0) else { continue };
            summary.events += records.len();
            for r in &records {
                // Records that failed timestamp parsing land on 0; ignore those
                // rather than reporting a 1970 range.
                if r.timestamp == 0 {
                    continue;
                }
                summary.earliest_ms =
                    Some(summary.earliest_ms.map_or(r.timestamp, |e: i64| e.min(r.timestamp)));
                summary.latest_ms =
                    Some(summary.latest_ms.map_or(r.timestamp, |l: i64| l.max(r.timestamp)));
            }
        }
        summary.files += 1;
    }

    summary
}

/// Condense an SDK error into one line: `Code: message`.
///
/// The SDK's own `DisplayErrorContext` renders the whole chain — raw response
/// body, headers, extensions — which runs to well over a thousand characters and
/// is unusable in a UI panel. Prefer the error metadata the service actually sent,
/// and fall back to the full context only when there is no metadata (connection
/// refused, DNS failure, TLS error), where the chain is the only useful detail.
#[cfg(feature = "aws")]
pub(crate) fn aws_message<E, R>(err: &aws_sdk_cloudtrail::error::SdkError<E, R>) -> String
where
    aws_sdk_cloudtrail::error::SdkError<E, R>: aws_sdk_cloudtrail::error::ProvideErrorMetadata,
    E: std::error::Error + 'static,
    R: std::fmt::Debug + 'static,
{
    use aws_sdk_cloudtrail::error::ProvideErrorMetadata;

    match (err.code(), err.message()) {
        (Some(code), Some(msg)) => format!("{code}: {msg}"),
        (Some(code), None) => code.to_string(),
        // No service metadata => transport-level failure (connection refused, DNS,
        // TLS). Walk the source chain by Display. The SDK's own
        // `DisplayErrorContext` appends a Debug dump of the whole error struct on
        // top of this, which is noise in a UI panel.
        _ => {
            let mut out = err.to_string();
            let mut src = std::error::Error::source(err);
            while let Some(e) = src {
                out.push_str(": ");
                out.push_str(&e.to_string());
                src = e.source();
            }
            out
        }
    }
}

/// Rewrites `X-Amz-Target` to the fully-qualified form the AWS CLI sends.
///
/// botocore emits
/// `com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents`, while
/// `aws-sdk-cloudtrail` emits the short `CloudTrail_20131101.LookupEvents`. Real
/// AWS accepts both; some emulators only register the qualified name and answer
/// the short form with `UnknownOperationException`, which reads like a missing
/// feature rather than a header mismatch.
///
/// Must run in `modify_before_signing`: `x-amz-target` is part of
/// `SignedHeaders`, so changing it after signing invalidates the signature.
#[cfg(feature = "aws")]
#[derive(Debug)]
struct QualifyTargetInterceptor;

#[cfg(feature = "aws")]
impl aws_sdk_cloudtrail::config::Intercept for QualifyTargetInterceptor {
    fn name(&self) -> &'static str {
        "QualifyCloudTrailTarget"
    }

    fn modify_before_signing(
        &self,
        context: &mut aws_smithy_runtime_api::client::interceptors::context::BeforeTransmitInterceptorContextMut<'_>,
        _runtime_components: &aws_smithy_runtime_api::client::runtime_components::RuntimeComponents,
        _cfg: &mut aws_smithy_types::config_bag::ConfigBag,
    ) -> Result<(), aws_smithy_runtime_api::box_error::BoxError> {
        const SHORT: &str = "CloudTrail_20131101.";
        const QUALIFIED: &str = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.";

        let headers = context.request_mut().headers_mut();
        let Some(target) = headers.get("x-amz-target").map(str::to_string) else {
            return Ok(());
        };
        // Only touch the short form; leave anything already qualified alone.
        if let Some(op) = target.strip_prefix(SHORT) {
            headers.insert("x-amz-target", format!("{QUALIFIED}{op}"));
        }
        Ok(())
    }
}

/// CloudTrail client with the target-header fix applied.
#[cfg(feature = "aws")]
pub(crate) fn cloudtrail_client(cfg: &aws_config::SdkConfig) -> aws_sdk_cloudtrail::Client {
    let conf = aws_sdk_cloudtrail::config::Builder::from(cfg)
        .interceptor(QualifyTargetInterceptor)
        .build();
    aws_sdk_cloudtrail::Client::from_conf(conf)
}

/// Build an SDK config for a request: named profile, explicit region, optional
/// endpoint override.
#[cfg(feature = "aws")]
pub(crate) async fn sdk_config(req: &FetchRequest) -> aws_config::SdkConfig {
    use aws_config::{meta::region::RegionProviderChain, BehaviorVersion, Region};

    let region = RegionProviderChain::first_try(Region::new(req.region.clone()));
    let mut loader = aws_config::defaults(BehaviorVersion::latest()).region(region);

    // Explicit credentials win over a named profile. When neither is given the SDK
    // falls back to its own chain (env vars, instance metadata, SSO).
    match (&req.credentials, &req.profile) {
        (Some(c), _) => {
            let creds = aws_sdk_cloudtrail::config::Credentials::new(
                c.access_key_id.trim(),
                c.secret_access_key.trim(),
                c.session_token.as_deref().map(str::trim).filter(|t| !t.is_empty()).map(str::to_string),
                None,
                "trailinspector-manual",
            );
            loader = loader.credentials_provider(creds);
        }
        (None, Some(p)) if !p.trim().is_empty() => {
            loader = loader.profile_name(p.trim());
        }
        _ => {}
    }

    if let Some(url) = req.endpoint_url.as_deref().filter(|u| !u.trim().is_empty()) {
        loader = loader.endpoint_url(url.trim());
    }

    loader.load().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_source_serializes_camel_case() {
        let j = serde_json::to_string(&FetchSource::LookupEvents).unwrap();
        assert_eq!(j, "\"lookupEvents\"");
        let j = serde_json::to_string(&FetchSource::TrailBucket).unwrap();
        assert_eq!(j, "\"trailBucket\"");
    }

    #[test]
    fn request_endpoint_url_defaults_to_none() {
        let req: FetchRequest = serde_json::from_str(
            r#"{"profile":"ctf","region":"us-east-1","source":"lookupEvents","startMs":0,"endMs":1}"#,
        )
        .unwrap();
        assert!(req.endpoint_url.is_none());
        assert!(req.credentials.is_none());
        assert_eq!(req.source, FetchSource::LookupEvents);
    }

    fn req_with_creds(token: Option<&str>) -> FetchRequest {
        FetchRequest {
            profile: None,
            credentials: Some(AwsCredentials {
                access_key_id: "AKIAEXAMPLE".into(),
                secret_access_key: "TOPSECRETVALUE".into(),
                session_token: token.map(str::to_string),
            }),
            region: "us-east-1".into(),
            source: FetchSource::LookupEvents,
            start_ms: None,
            end_ms: None,
            bucket: None,
            prefix: None,
            endpoint_url: None,
        }
    }

    /// The derived Debug would print secrets in full. Anything that formats a
    /// request — a log line, a panic message, an error path — must not leak them.
    #[test]
    fn debug_redacts_secret_and_token() {
        let dbg = format!("{:?}", req_with_creds(Some("SESSIONTOKENVALUE")));
        assert!(!dbg.contains("TOPSECRETVALUE"), "secret leaked: {dbg}");
        assert!(!dbg.contains("SESSIONTOKENVALUE"), "token leaked: {dbg}");
        assert!(dbg.contains("<redacted>"), "expected redaction marker: {dbg}");
    }

    /// Progress messages reach the UI, so the label must never carry key material.
    #[test]
    fn identity_label_never_names_key_material() {
        let label = req_with_creds(None).identity_label();
        assert!(!label.contains("AKIAEXAMPLE"), "key id leaked: {label}");
        assert_eq!(label, "supplied credentials");
    }

    #[test]
    fn identity_label_uses_profile_when_no_credentials() {
        let mut req = req_with_creds(None);
        req.credentials = None;
        req.profile = Some("ctf".into());
        assert_eq!(req.identity_label(), "profile 'ctf'");

        req.profile = None;
        assert_eq!(req.identity_label(), "default credential chain");
    }
}
