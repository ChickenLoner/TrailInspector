// Additional persistence rules (PE-05, PE-06, PE-07)
use std::collections::HashMap;
use crate::store::Store;
use crate::detection::{Alert, Severity};

/// PE-05: MFA Device Deactivated
pub fn pe_05_mfa_deactivated(store: &Store) -> Vec<Alert> {
    let event_names = ["DeactivateMFADevice", "DeleteVirtualMFADevice"];
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
        rule_id: "PE-05".to_string(),
        severity: Severity::High,
        title: "MFA Device Deactivated".to_string(),
        description: format!(
            "{} MFA device(s) were deactivated or deleted. Removing MFA weakens account \
             security and may allow attackers to maintain persistent access via stolen credentials.",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Persistence".to_string(),
        mitre_technique: "T1556.006".to_string(),
        service: "IAM".to_string(),
        query: "eventName=DeactivateMFADevice OR eventName=DeleteVirtualMFADevice".to_string(),
    }]
}

/// PE-06: IAM Policy Version Created and Set as Default
pub fn pe_06_policy_version_created(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("CreatePolicyVersion") {
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
            if params_str.contains("\"setAsDefault\":true")
                || params_str.contains("\"setAsDefault\": true")
            {
                matching.push(id);
            }
        }
    }

    if matching.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "PE-06".to_string(),
        severity: Severity::Medium,
        title: "IAM Policy Version Created and Set as Default".to_string(),
        description: format!(
            "{} IAM policy version(s) created and immediately set as default. \
             This pattern is used to escalate privileges by silently updating policy permissions.",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Persistence".to_string(),
        mitre_technique: "T1098.003".to_string(),
        service: "IAM".to_string(),
        query: "eventName=CreatePolicyVersion".to_string(),
    }]
}

/// PE-07: Cross-Account AssumeRole
pub fn pe_07_cross_account_assume_role(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("AssumeRole") {
        Some(ids) => ids,
        None => return vec![],
    };

    let mut matching = vec![];
    for &id in ids {
        if let Some(r) = store.get_record(id) {
            let caller_account = r.record.user_identity.account_id.as_deref().unwrap_or("");
            let params = r.record.parse_request_parameters();
            let role_arn_owned = params.as_ref()
                .and_then(|v| v.get("roleArn"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let role_arn = role_arn_owned.as_deref().unwrap_or("");

            // Extract account ID from role ARN (arn:aws:iam::ACCOUNT_ID:role/...)
            if !role_arn.is_empty() && !caller_account.is_empty() {
                let arn_parts: Vec<&str> = role_arn.split(':').collect();
                if arn_parts.len() >= 5 {
                    let role_account = arn_parts[4];
                    if !role_account.is_empty() && role_account != caller_account {
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
        rule_id: "PE-07".to_string(),
        severity: Severity::Medium,
        title: "Cross-Account Role Assumption".to_string(),
        description: format!(
            "{} AssumeRole event(s) where the caller assumed a role in a different AWS account. \
             Cross-account access warrants review to verify it is authorized.",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Persistence".to_string(),
        mitre_technique: "T1098.001".to_string(),
        service: "STS".to_string(),
        query: "eventName=AssumeRole".to_string(),
    }]
}
