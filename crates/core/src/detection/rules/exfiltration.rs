use std::collections::HashMap;
use crate::store::Store;
use crate::detection::{Alert, Severity};

/// EX-01: S3 Bucket Made Public (PutBucketPolicy or PutBucketAcl)
pub fn ex_01_s3_bucket_public(store: &Store) -> Vec<Alert> {
    let event_names = ["PutBucketPolicy", "PutBucketAcl"];
    let mut matching = vec![];

    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
            for &id in ids {
                if let Some(r) = store.get_record(id) {
                    if is_public_grant(r.record.parse_request_parameters()) {
                        matching.push(id);
                    }
                }
            }
        }
    }

    if matching.is_empty() {
        return vec![];
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
        metadata: HashMap::new(),
        mitre_tactic: "Exfiltration".to_string(),
        mitre_technique: "T1537".to_string(),
        service: "S3".to_string(),
        query: "eventName=PutBucketPolicy OR eventName=PutBucketAcl".to_string(),
    }]
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

/// EX-02: S3 Bucket Deleted
pub fn ex_02_s3_bucket_deleted(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("DeleteBucket") {
        Some(ids) => ids.clone(),
        None => return vec![],
    };

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
        matching_record_ids: ids,
        metadata: HashMap::new(),
        mitre_tactic: "Exfiltration".to_string(),
        mitre_technique: "T1485".to_string(),
        service: "S3".to_string(),
        query: "eventName=DeleteBucket".to_string(),
    }]
}

/// EX-03: S3 Bulk Download (50+ GetObject in 5 min by same identity)
pub fn ex_03_s3_bulk_download(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("GetObject") {
        Some(ids) => ids,
        None => return vec![],
    };

    let mut by_identity: HashMap<String, Vec<(i64, u64)>> = HashMap::new();
    for &id in ids {
        if let Some(r) = store.get_record(id) {
            let identity = r.record.user_identity.arn
                .clone()
                .or_else(|| r.record.user_identity.user_name.clone())
                .unwrap_or_else(|| "unknown".to_string());
            by_identity.entry(identity).or_default().push((r.timestamp, id));
        }
    }

    let window_ms = 5 * 60 * 1000;
    let threshold = 50;
    let mut all_matching: Vec<u64> = vec![];
    let mut offending_identities: Vec<String> = vec![];

    for (identity, mut events) in by_identity {
        events.sort_unstable_by_key(|(ts, _)| *ts);
        let mut start = 0;
        for end in 0..events.len() {
            while events[end].0 - events[start].0 > window_ms {
                start += 1;
            }
            if end - start + 1 >= threshold {
                for (_, wid) in &events[start..=end] {
                    if !all_matching.contains(wid) {
                        all_matching.push(*wid);
                    }
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

    let mut meta = HashMap::new();
    meta.insert("identities".to_string(), offending_identities.join(", "));

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

    vec![Alert {
        rule_id: "EX-03".to_string(),
        severity: Severity::Medium,
        title: "S3 Bulk Object Download".to_string(),
        description: format!(
            "≥{} S3 GetObject calls within 5 minutes by same identity. \
             Bulk downloads suggest data exfiltration. Identities: {}",
            threshold,
            offending_identities.join(", ")
        ),
        matching_count: 0,
        matching_record_ids: all_matching,
        metadata: meta,
        mitre_tactic: "Exfiltration".to_string(),
        mitre_technique: "T1530".to_string(),
        service: "S3".to_string(),
        query,
    }]
}

/// EX-04: S3 Bucket Logging Disabled
pub fn ex_04_s3_logging_disabled(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("PutBucketLogging") {
        Some(ids) => ids,
        None => return vec![],
    };

    let mut matching = vec![];
    for &id in ids {
        if let Some(r) = store.get_record(id) {
            let params_str = r.record.request_parameters
                .as_ref()
                .map(|v| v.get().to_string())
                .unwrap_or_default();
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
        query: "eventName=PutBucketLogging".to_string(),
    }]
}

/// EX-05: S3 Bucket Encryption Removed
pub fn ex_05_s3_encryption_removed(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("DeleteBucketEncryption") {
        Some(ids) => ids.clone(),
        None => return vec![],
    };

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
        matching_record_ids: ids,
        metadata: HashMap::new(),
        mitre_tactic: "Exfiltration".to_string(),
        mitre_technique: "T1537".to_string(),
        service: "S3".to_string(),
        query: "eventName=DeleteBucketEncryption".to_string(),
    }]
}
