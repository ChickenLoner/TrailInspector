use crate::store::Store;
use crate::detection::Finding;
use super::window::{identity_burst, Windows};

/// EX-01: S3 Bucket Made Public (PutBucketPolicy or PutBucketAcl)
pub fn ex_01_s3_bucket_public(store: &Store) -> Option<Finding> {
    let event_names = ["PutBucketPolicy", "PutBucketAcl"];
    let mut matching = vec![];

    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
            for id in ids {
                if is_public_grant(store.parse_request_parameters(id)) {
                    matching.push(id);
                }
            }
        }
    }

    if matching.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} S3 bucket policy or ACL change(s) detected that may grant public access. \
             Publicly accessible buckets can expose sensitive data.",
            matching.len()
        ),
        matching,
        "eventName=PutBucketPolicy OR eventName=PutBucketAcl",
    ))
}

fn is_public_grant(params: Option<serde_json::Value>) -> bool {
    let params = match params {
        Some(p) => p,
        None => return false,
    };

    // Check ACL grants for AllUsers / AuthenticatedUsers
    let public_grantees = [
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    ];

    let params_str = params.to_string();
    for grantee in &public_grantees {
        if params_str.contains(grantee) {
            return true;
        }
    }

    // Check bucket policy for Principal = "*"
    if params_str.contains("\"Principal\":\"*\"")
        || params_str.contains("\"Principal\": \"*\"")
    {
        return true;
    }

    // If we can't determine, flag all PutBucketPolicy (has bucketPolicy field), always flag
    if params.get("bucketPolicy").is_some() {
        return true;
    }

    false
}

/// EX-03: S3 Bulk Download (50+ GetObject in 5 min by same identity)
pub fn ex_03_s3_bulk_download(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("GetObject")?;

    let threshold = 50;
    let burst = identity_burst(store, ids, threshold, 5 * 60 * 1000, Windows::First);

    if burst.is_empty() {
        return None;
    }

    // Sum bytes transferred from s3_event_index (zero blob reads)
    let total_bytes: u64 = burst
        .ids
        .iter()
        .filter_map(|id| store.s3_event_index.get(id))
        .map(|d| d.bytes_out)
        .sum();

    let query = burst.scoped_query("eventName=GetObject");
    let identities = burst.keys_joined();
    let bytes = format_bytes(total_bytes);
    let object_count = burst.ids.len();

    Some(
        Finding::new(
            format!(
                "≥{threshold} S3 GetObject calls within 5 minutes by same identity; ~{bytes} transferred. \
                 Bulk downloads suggest data exfiltration. Identities: {identities}"
            ),
            burst.ids,
            query,
        )
        .meta("identities", identities)
        .meta("total_bytes_out", bytes)
        .meta("object_count", object_count.to_string()),
    )
}

fn format_bytes(b: u64) -> String {
    if b < 1_024 {
        format!("{} B", b)
    } else if b < 1_024 * 1_024 {
        format!("{:.1} KB", b as f64 / 1_024.0)
    } else if b < 1_024 * 1_024 * 1_024 {
        format!("{:.1} MB", b as f64 / (1_024.0 * 1_024.0))
    } else {
        format!("{:.1} GB", b as f64 / (1_024.0 * 1_024.0 * 1_024.0))
    }
}

/// EX-04: S3 Bucket Logging Disabled
pub fn ex_04_s3_logging_disabled(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("PutBucketLogging")?;

    let mut matching = vec![];
    for id in ids {
        let params_str = store.get_request_parameters_str(id).unwrap_or_default();
        // Empty LoggingConfiguration means logging disabled
        if params_str.contains("\"BucketLoggingStatus\":{}")
            || params_str.contains("\"loggingEnabled\":{}")
            || (params_str.contains("BucketLoggingStatus") && !params_str.contains("LoggingEnabled"))
        {
            matching.push(id);
        }
    }

    if matching.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} S3 bucket(s) had access logging disabled. Removing bucket logs \
             hides evidence of data access and exfiltration.",
            matching.len()
        ),
        matching,
        "eventName=PutBucketLogging",
    ))
}

