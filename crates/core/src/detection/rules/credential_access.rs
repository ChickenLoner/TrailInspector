use std::collections::HashMap;
use crate::store::Store;
use crate::detection::{Alert, Severity};

/// CA-02: Secrets Manager Bulk Access (>5 GetSecretValue in 10 min by same identity)
pub fn ca_02_secrets_bulk(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("GetSecretValue") {
        Some(ids) => ids,
        None => return vec![],
    };

    // Group by identity (ARN or userName)
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

    let window_ms = 10 * 60 * 1000;
    let threshold = 5;
    let mut all_matching: Vec<u64> = vec![];
    let mut offending_identities: Vec<String> = vec![];

    for (identity, mut events) in by_identity {
        events.sort_unstable_by_key(|(ts, _)| *ts);
        let mut start = 0;
        for end in 0..events.len() {
            while events[end].0 - events[start].0 > window_ms {
                start += 1;
            }
            if end - start + 1 > threshold {
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

    // If single offending identity, scope the query to it
    let query = if offending_identities.len() == 1 {
        let id = &offending_identities[0];
        if id.starts_with("arn:") {
            format!("eventName=GetSecretValue arn=\"{}\"", id)
        } else {
            format!("eventName=GetSecretValue userName=\"{}\"", id)
        }
    } else {
        "eventName=GetSecretValue".to_string()
    };

    vec![Alert {
        rule_id: "CA-02".to_string(),
        severity: Severity::High,
        title: "Secrets Manager Bulk Access".to_string(),
        description: format!(
            "Identity accessed >{}  secrets within 10 minutes. \
             Bulk secret retrieval suggests credential harvesting. Identities: {}",
            threshold,
            offending_identities.join(", ")
        ),
        matching_record_ids: all_matching,
        metadata: meta,
        mitre_tactic: "Credential Access".to_string(),
        mitre_technique: "T1555".to_string(),
        service: "SecretsManager".to_string(),
        query,
    }]
}

/// CA-04: Password Policy Weakened
pub fn ca_04_password_policy_weakened(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("UpdateAccountPasswordPolicy") {
        Some(ids) => ids.clone(),
        None => return vec![],
    };

    if ids.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "CA-04".to_string(),
        severity: Severity::Medium,
        title: "Account Password Policy Modified".to_string(),
        description: format!(
            "{} modification(s) to the account password policy were detected. \
             Weakening password policies enables credential-based attacks.",
            ids.len()
        ),
        matching_record_ids: ids,
        metadata: HashMap::new(),
        mitre_tactic: "Credential Access".to_string(),
        mitre_technique: "T1556".to_string(),
        service: "IAM".to_string(),
        query: "eventName=UpdateAccountPasswordPolicy".to_string(),
    }]
}

/// CA-05: Root Console Login (specific ConsoleLogin event from Root identity)
pub fn ca_05_root_console_login(store: &Store) -> Vec<Alert> {
    let login_ids = match store.idx_event_name.get("ConsoleLogin") {
        Some(ids) => ids,
        None => return vec![],
    };

    let mut matching = vec![];
    for &id in login_ids {
        if let Some(r) = store.get_record(id) {
            let is_root = r.record.user_identity.identity_type
                .as_deref()
                .map(|t| t == "Root")
                .unwrap_or(false);

            let is_success = r.record.response_elements
                .as_ref()
                .and_then(|v| v.get("ConsoleLogin"))
                .and_then(|v| v.as_str())
                .map(|s| s == "Success")
                .unwrap_or(false);

            if is_root && is_success {
                matching.push(id);
            }
        }
    }

    if matching.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "CA-05".to_string(),
        severity: Severity::Critical,
        title: "Root Account Console Login".to_string(),
        description: format!(
            "{} successful root account console login(s) detected. Root console access \
             should never occur in normal operations and indicates a critical security event.",
            matching.len()
        ),
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Credential Access".to_string(),
        mitre_technique: "T1078.004".to_string(),
        service: "IAM".to_string(),
        query: "eventName=ConsoleLogin identityType=Root".to_string(),
    }]
}

/// CA-06: KMS Key Scheduled for Deletion
pub fn ca_06_kms_key_deletion(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("ScheduleKeyDeletion") {
        Some(ids) => ids.clone(),
        None => return vec![],
    };

    if ids.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "CA-06".to_string(),
        severity: Severity::High,
        title: "KMS Key Scheduled for Deletion".to_string(),
        description: format!(
            "{} KMS key(s) scheduled for deletion. Deleting encryption keys can render \
             encrypted data permanently inaccessible, causing data loss.",
            ids.len()
        ),
        matching_record_ids: ids,
        metadata: HashMap::new(),
        mitre_tactic: "Credential Access".to_string(),
        mitre_technique: "T1485".to_string(),
        service: "KMS".to_string(),
        query: "eventName=ScheduleKeyDeletion".to_string(),
    }]
}
