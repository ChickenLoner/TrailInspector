use std::collections::HashMap;
use crate::store::Store;
use crate::detection::{Alert, Severity};

/// DI-02: IAM Enumeration
pub fn di_02_iam_enumeration(store: &Store) -> Vec<Alert> {
    let event_names = [
        "ListUsers",
        "ListRoles",
        "ListPolicies",
        "ListGroups",
        "GetAccountAuthorizationDetails",
        "ListAttachedUserPolicies",
        "ListAttachedRolePolicies",
    ];

    let mut matching = vec![];
    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
            matching.extend_from_slice(ids);
        }
    }

    if matching.is_empty() {
        return vec![];
    }

    let mut meta = HashMap::new();
    meta.insert("count".to_string(), matching.len().to_string());

    vec![Alert {
        rule_id: "DI-02".to_string(),
        severity: Severity::Medium,
        title: "IAM Enumeration Detected".to_string(),
        description: format!(
            "{} IAM enumeration event(s) detected (ListUsers, ListRoles, ListPolicies, etc.). \
             Reconnaissance of IAM resources is a common precursor to privilege escalation.",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata: meta,
        mitre_tactic: "Discovery".to_string(),
        mitre_technique: "T1087.004".to_string(),
        service: "IAM".to_string(),
        query: "eventName=ListUsers OR eventName=ListRoles OR eventName=ListPolicies OR eventName=GetAccountAuthorizationDetails OR eventName=ListGroups".to_string(),
    }]
}

/// DI-03: AccessDenied Spike (≥10 AccessDenied in 10 min by same identity)
pub fn di_03_access_denied_spike(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_error_code.get("AccessDenied") {
        Some(ids) => ids,
        None => return vec![],
    };

    // Group by identity
    let mut by_identity: HashMap<String, Vec<(i64, u64)>> = HashMap::new();
    for &id in ids {
        if let Some(r) = store.get_record(id) {
            let identity = r.record.user_identity.arn
                .clone()
                .or_else(|| r.record.user_identity.user_name.clone())
                .or_else(|| r.record.source_ip_address.clone())
                .unwrap_or_else(|| "unknown".to_string());
            by_identity.entry(identity).or_default().push((r.timestamp, id));
        }
    }

    let window_ms = 10 * 60 * 1000;
    let threshold = 10;
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

    // Scope to the specific identity if single offender
    let query = if offending_identities.len() == 1 {
        let id = &offending_identities[0];
        if id.starts_with("arn:") {
            format!("errorCode=AccessDenied arn=\"{}\"", id)
        } else {
            format!("errorCode=AccessDenied userName=\"{}\"", id)
        }
    } else {
        "errorCode=AccessDenied".to_string()
    };

    vec![Alert {
        rule_id: "DI-03".to_string(),
        severity: Severity::Medium,
        title: "AccessDenied Spike — Possible Permission Probing".to_string(),
        description: format!(
            "≥{} AccessDenied errors within 10 minutes by same identity. \
             This pattern indicates systematic permission probing. Identities: {}",
            threshold,
            offending_identities.join(", ")
        ),
        matching_count: 0,
        matching_record_ids: all_matching,
        metadata: meta,
        mitre_tactic: "Discovery".to_string(),
        mitre_technique: "T1580".to_string(),
        service: "IAM".to_string(),
        query,
    }]
}
