use std::collections::HashMap;
use crate::store::Store;
use crate::detection::{Alert, Severity};

/// IM-01: EC2 Instances Launched in Bulk (>5 RunInstances in 10 min, any identity)
pub fn im_01_ec2_bulk_launch(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("RunInstances") {
        Some(ids) => ids,
        None => return vec![],
    };

    // Collect all RunInstances timestamps
    let mut events: Vec<(i64, u32)> = ids
        .iter()
        .filter_map(|&id| store.get_record(id).map(|r| (r.timestamp, id)))
        .collect();

    events.sort_unstable_by_key(|(ts, _)| *ts);

    let window_ms = 10 * 60 * 1000;
    let threshold = 5;
    let mut all_matching: Vec<u32> = vec![];

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
        }
    }

    if all_matching.is_empty() {
        return vec![];
    }

    let mut meta = HashMap::new();
    meta.insert("total_run_instances".to_string(), ids.len().to_string());

    vec![Alert {
        rule_id: "IM-01".to_string(),
        severity: Severity::High,
        title: "EC2 Instances Launched in Bulk".to_string(),
        description: format!(
            ">{} EC2 RunInstances events within 10 minutes. \
             Bulk launches may indicate cryptomining or resource abuse.",
            threshold
        ),
        matching_count: 0,
        matching_record_ids: all_matching,
        metadata: meta,
        mitre_tactic: "Impact".to_string(),
        mitre_technique: "T1496".to_string(),
        service: "EC2".to_string(),
        query: "eventName=RunInstances".to_string(),
    }]
}

/// IM-02: Resource Deletion Spree (>10 Delete*/Terminate* events in 5 min by same identity)
pub fn im_02_resource_deletion_spree(store: &Store) -> Vec<Alert> {
    // Collect all Delete* and Terminate* events
    let mut deletion_ids: Vec<u32> = vec![];

    for (event_name, ids) in &store.idx_event_name {
        if event_name.starts_with("Delete")
            || event_name.starts_with("Terminate")
            || event_name.starts_with("Destroy")
            || event_name.starts_with("Remove")
        {
            deletion_ids.extend_from_slice(ids);
        }
    }

    if deletion_ids.is_empty() {
        return vec![];
    }

    // Group by identity
    let mut by_identity: HashMap<String, Vec<(i64, u32)>> = HashMap::new();
    for &id in &deletion_ids {
        if let Some(r) = store.get_record(id) {
            let identity = r.record.user_identity.arn.as_deref()
                .or_else(|| r.record.user_identity.user_name.as_deref())
                .unwrap_or("unknown")
                .to_string();
            by_identity.entry(identity).or_default().push((r.timestamp, id));
        }
    }

    let window_ms = 5 * 60 * 1000; // 5 minutes
    let threshold = 10;
    let mut all_matching: Vec<u32> = vec![];
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

    // Scope to the specific identity if single offender
    let query = if offending_identities.len() == 1 {
        let id = &offending_identities[0];
        if id.starts_with("arn:") {
            format!("eventName=Delete* arn=\"{}\"", id)
        } else {
            format!("eventName=Delete* userName=\"{}\"", id)
        }
    } else {
        "eventName=Delete* OR eventName=Terminate*".to_string()
    };

    vec![Alert {
        rule_id: "IM-02".to_string(),
        severity: Severity::Critical,
        title: "Resource Deletion Spree".to_string(),
        description: format!(
            ">{} Delete/Terminate/Destroy events within 5 minutes by the same identity. \
             This pattern indicates destructive activity or ransomware. Identities: {}",
            threshold,
            offending_identities.join(", ")
        ),
        matching_count: 0,
        matching_record_ids: all_matching,
        metadata: meta,
        mitre_tactic: "Impact".to_string(),
        mitre_technique: "T1485".to_string(),
        service: "Multi".to_string(),
        query,
    }]
}

/// IM-03: SES Email Identity Verification (potential phishing setup)
pub fn im_03_ses_email_verified(store: &Store) -> Vec<Alert> {
    let event_names = ["VerifyEmailIdentity", "CreateEmailIdentity", "VerifyDomainIdentity"];
    let mut matching = vec![];

    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
            matching.extend_from_slice(ids);
        }
    }

    if matching.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "IM-03".to_string(),
        severity: Severity::Low,
        title: "SES Email Identity Verified".to_string(),
        description: format!(
            "{} SES email/domain identit(ies) verified. Attackers may verify email \
             identities to send phishing emails using the compromised account.",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Impact".to_string(),
        mitre_technique: "T1534".to_string(),
        service: "SES".to_string(),
        query: "eventName=VerifyEmailIdentity OR eventName=CreateEmailIdentity OR eventName=VerifyDomainIdentity".to_string(),
    }]
}
