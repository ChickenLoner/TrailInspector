use crate::store::Store;
use crate::detection::{Finding, jget, json_contains_pair, json_has_str, policy_statements, scoped_ids};
use super::window::{identity_burst, Windows};

/// EX-01: S3 Bucket Made Public (PutBucketPolicy or PutBucketAcl)
pub fn ex_01_s3_bucket_public(store: &Store) -> Option<Finding> {
    let event_names = ["PutBucketPolicy", "PutBucketAcl"];
    let mut matching = vec![];

    let mut conditional = 0usize;

    let ids = scoped_ids(store, &event_names, &["s3.amazonaws.com"], true);
    for id in ids {
        let Some(p) = store.parse_request_parameters(id) else { continue };
        match classify_exposure(&p) {
            Exposure::Public => matching.push(id),
            Exposure::Conditional => conditional += 1,
            Exposure::None => {}
        }
    }

    if matching.is_empty() {
        return None;
    }

    let mut finding = Finding::new(
        format!(
            "{} S3 bucket policy or ACL change(s) detected that may grant public access. \
             Publicly accessible buckets can expose sensitive data.",
            matching.len()
        ),
        matching,
        crate::detection::field_query_in("eventName", &event_names, &["s3.amazonaws.com"]),
    );
    if conditional > 0 {
        // Wildcard principals gated by a Condition are not flagged, but are worth a look.
        finding = finding.meta("conditional_wildcard_count", conditional.to_string());
    }
    Some(finding)
}

enum Exposure {
    /// Grants access to everyone, unconditionally.
    Public,
    /// Wildcard principal, but gated by a `Condition` (source IP, VPC endpoint, org id...).
    Conditional,
    None,
}

const PUBLIC_GRANTEES: [&str; 2] = [
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
];
const PUBLIC_CANNED_ACLS: [&str; 3] = ["public-read", "public-read-write", "authenticated-read"];

/// Does this statement's `Principal` include a wildcard? Accepts `"*"`, `{"AWS":"*"}`,
/// `{"AWS":["*", ...]}`.
fn principal_is_wildcard(principal: &serde_json::Value) -> bool {
    match principal {
        serde_json::Value::String(s) => s == "*",
        serde_json::Value::Object(_) => jget(principal, "AWS").is_some_and(|a| json_has_str(a, "*")),
        _ => false,
    }
}

fn classify_exposure(params: &serde_json::Value) -> Exposure {
    // PutBucketAcl: AllUsers / AuthenticatedUsers grantee, or a public canned ACL header.
    for uri in PUBLIC_GRANTEES {
        if json_contains_pair(params, "URI", uri) {
            return Exposure::Public;
        }
    }
    for key in ["x-amz-acl", "acl"] {
        if let Some(v) = jget(params, key) {
            if PUBLIC_CANNED_ACLS.iter().any(|a| json_has_str(v, a)) {
                return Exposure::Public;
            }
        }
    }

    // PutBucketPolicy: the policy arrives as an object or as a JSON string.
    let policy: Option<serde_json::Value> = match jget(params, "bucketPolicy").or_else(|| jget(params, "policy")) {
        Some(serde_json::Value::String(s)) => serde_json::from_str(s).ok(),
        Some(v) => Some(v.clone()),
        None => None,
    };
    let Some(policy) = policy else { return Exposure::None };

    let mut result = Exposure::None;
    for st in policy_statements(&policy) {
        let allow = jget(st, "Effect").is_some_and(|e| json_has_str(e, "Allow"));
        let wildcard = jget(st, "Principal").is_some_and(principal_is_wildcard);
        if !(allow && wildcard) {
            continue;
        }
        if jget(st, "Condition").is_some() {
            result = Exposure::Conditional;
        } else {
            return Exposure::Public;
        }
    }
    result
}

/// EX-03: S3 Bulk Download (50+ GetObject in 5 min by same identity)
pub fn ex_03_s3_bulk_download(store: &Store) -> Option<Finding> {
    let ids = scoped_ids(store, &["GetObject"], &["s3.amazonaws.com"], true);
    if ids.is_empty() {
        return None;
    }

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
    let ids = scoped_ids(store, &["PutBucketLogging"], &["s3.amazonaws.com"], true);
    if ids.is_empty() {
        return None;
    }

    let mut matching = vec![];
    for id in ids {
        {
            let params_str = store.get_request_parameters_str(id).unwrap_or_default();
            // Empty LoggingConfiguration means logging disabled
            if params_str.contains("\"BucketLoggingStatus\":{}")
                || params_str.contains("\"loggingEnabled\":{}")
                || (params_str.contains("BucketLoggingStatus") && !params_str.contains("LoggingEnabled"))
            {
                matching.push(id);
            }
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

