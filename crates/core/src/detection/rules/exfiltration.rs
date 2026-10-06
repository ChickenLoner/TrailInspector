use std::collections::HashMap;
use roaring::RoaringBitmap;
use crate::store::Store;
use crate::detection::{Alert, Severity, scoped_ids, jget, json_has_str, json_contains_pair, policy_statements, time_sorted};

/// EX-01: S3 Bucket Made Public (PutBucketPolicy or PutBucketAcl)
pub fn ex_01_s3_bucket_public(store: &Store) -> Vec<Alert> {
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
        return vec![];
    }

    let mut metadata = HashMap::new();
    if conditional > 0 {
        // Wildcard principals gated by a Condition are not flagged, but are worth a look.
        metadata.insert("conditional_wildcard_count".to_string(), conditional.to_string());
    }

    vec![Alert {
        rule_id: "EX-01".to_string(),
        severity: Severity::High,
        title: "S3 Bucket Policy/ACL Modified (Potential Public Exposure)".to_string(),
        description: format!(
            "{} S3 bucket policy or ACL change(s) detected that may grant public access. \
             Publicly accessible buckets can expose sensitive data.",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata,
        mitre_tactic: "Exfiltration".to_string(),
        mitre_technique: "T1537".to_string(),
        service: "S3".to_string(),
        query: "eventName=PutBucketPolicy eventSource=s3.amazonaws.com OR eventName=PutBucketAcl eventSource=s3.amazonaws.com".to_string(),
    }]
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

/// EX-02: S3 Bucket Deleted
pub fn ex_02_s3_bucket_deleted(store: &Store) -> Vec<Alert> {
    let ids = scoped_ids(store, &["DeleteBucket"], &["s3.amazonaws.com"], true);
    if ids.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "EX-02".to_string(),
        severity: Severity::Medium,
        title: "S3 Bucket Deleted".to_string(),
        description: format!(
            "{} S3 bucket(s) were deleted. Bucket deletion can indicate data destruction \
             or cleanup of evidence after exfiltration.",
            ids.len()
        ),
        matching_count: 0,
        matching_record_ids: ids.iter().collect(),
        metadata: HashMap::new(),
        mitre_tactic: "Exfiltration".to_string(),
        mitre_technique: "T1485".to_string(),
        service: "S3".to_string(),
        query: "eventName=DeleteBucket eventSource=s3.amazonaws.com".to_string(),
    }]
}

/// EX-03: S3 Bulk Download (50+ GetObject in 5 min by same identity)
pub fn ex_03_s3_bulk_download(store: &Store) -> Vec<Alert> {
    let ids = scoped_ids(store, &["GetObject"], &["s3.amazonaws.com"], true);
    if ids.is_empty() {
        return vec![];
    }

    let mut by_identity: HashMap<String, Vec<(i64, u32)>> = HashMap::new();
    for id in ids {
        if let Some(r) = store.get_record(id) {
            let identity = r.record.user_identity.arn.as_deref()
                .or_else(|| r.record.user_identity.user_name.as_deref())
                .unwrap_or("unknown")
                .to_string();
            by_identity.entry(identity).or_default().push((r.timestamp, id));
        }
    }

    let window_ms = 5 * 60 * 1000;
    let threshold = 50;
    let mut all_matching = RoaringBitmap::new();
    let mut offending_identities: Vec<String> = vec![];

    for (identity, mut events) in by_identity {
        events.sort_unstable();
        let mut start = 0;
        for end in 0..events.len() {
            while events[end].0 - events[start].0 > window_ms {
                start += 1;
            }
            if end - start + 1 >= threshold {
                for (_, wid) in &events[start..=end] {
                    all_matching.insert(*wid);
                }
                if !offending_identities.contains(&identity) {
                    offending_identities.push(identity.clone());
                }
                break;
            }
        }
    }

    if all_matching.is_empty() {
        return vec![];
    }

    // Sum bytes transferred from s3_event_index (zero blob reads)
    let total_bytes: u64 = all_matching
        .iter()
        .filter_map(|id| store.s3_event_index.get(&id))
        .map(|d| d.bytes_out)
        .sum();

    let mut meta = HashMap::new();
    meta.insert("identities".to_string(), offending_identities.join(", "));
    meta.insert("total_bytes_out".to_string(), format_bytes(total_bytes));
    meta.insert("object_count".to_string(), all_matching.len().to_string());

    let query = if offending_identities.len() == 1 {
        let id = &offending_identities[0];
        if id.starts_with("arn:") {
            format!("eventName=GetObject arn=\"{}\"", id)
        } else {
            format!("eventName=GetObject userName=\"{}\"", id)
        }
    } else {
        "eventName=GetObject".to_string()
    };
    let query = format!("{query} eventSource=s3.amazonaws.com");

    vec![Alert {
        rule_id: "EX-03".to_string(),
        severity: Severity::Medium,
        title: "S3 Bulk Object Download".to_string(),
        description: format!(
            "≥{} S3 GetObject calls within 5 minutes by same identity; ~{} transferred. \
             Bulk downloads suggest data exfiltration. Identities: {}",
            threshold,
            format_bytes(total_bytes),
            offending_identities.join(", ")
        ),
        matching_count: 0,
        matching_record_ids: time_sorted(store, &all_matching),
        metadata: meta,
        mitre_tactic: "Exfiltration".to_string(),
        mitre_technique: "T1530".to_string(),
        service: "S3".to_string(),
        query,
    }]
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
pub fn ex_04_s3_logging_disabled(store: &Store) -> Vec<Alert> {
    let ids = scoped_ids(store, &["PutBucketLogging"], &["s3.amazonaws.com"], true);
    if ids.is_empty() {
        return vec![];
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
        return vec![];
    }

    vec![Alert {
        rule_id: "EX-04".to_string(),
        severity: Severity::Medium,
        title: "S3 Bucket Access Logging Disabled".to_string(),
        description: format!(
            "{} S3 bucket(s) had access logging disabled. Removing bucket logs \
             hides evidence of data access and exfiltration.",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Exfiltration".to_string(),
        mitre_technique: "T1562.008".to_string(),
        service: "S3".to_string(),
        query: "eventName=PutBucketLogging eventSource=s3.amazonaws.com".to_string(),
    }]
}

/// EX-05: S3 Bucket Encryption Removed
pub fn ex_05_s3_encryption_removed(store: &Store) -> Vec<Alert> {
    let ids = scoped_ids(store, &["DeleteBucketEncryption"], &["s3.amazonaws.com"], true);
    if ids.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "EX-05".to_string(),
        severity: Severity::High,
        title: "S3 Bucket Encryption Removed".to_string(),
        description: format!(
            "{} S3 bucket(s) had server-side encryption removed. \
             Unencrypted buckets expose data at rest.",
            ids.len()
        ),
        matching_count: 0,
        matching_record_ids: ids.iter().collect(),
        metadata: HashMap::new(),
        mitre_tactic: "Exfiltration".to_string(),
        mitre_technique: "T1537".to_string(),
        service: "S3".to_string(),
        query: "eventName=DeleteBucketEncryption eventSource=s3.amazonaws.com".to_string(),
    }]
}
