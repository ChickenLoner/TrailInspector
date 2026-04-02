use std::collections::HashMap;
use crate::store::Store;
use crate::detection::{Alert, Severity};

/// PE-01: IAM User Created
pub fn pe_01_iam_user_created(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("CreateUser") {
        Some(ids) => ids.clone(),
        None => return vec![],
    };

    if ids.is_empty() {
        return vec![];
    }

    let mut meta = HashMap::new();
    meta.insert("count".to_string(), ids.len().to_string());

    vec![Alert {
        rule_id: "PE-01".to_string(),
        severity: Severity::Medium,
        title: "IAM User Created".to_string(),
        description: format!(
            "{} IAM user(s) were created. Review whether these accounts are expected \
             and authorized.",
            ids.len()
        ),
        matching_count: 0,
        matching_record_ids: ids,
        metadata: meta,
        mitre_tactic: "Persistence".to_string(),
        mitre_technique: "T1136.003".to_string(),
        service: "IAM".to_string(),
        query: "eventName=CreateUser".to_string(),
    }]
}

/// PE-02: Access Key Created for Another User
pub fn pe_02_access_key_for_other(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("CreateAccessKey") {
        Some(ids) => ids,
        None => return vec![],
    };

    let mut matching = vec![];
    for &id in ids {
        if let Some(r) = store.get_record(id) {
            let caller = r.record.user_identity.user_name.as_deref().unwrap_or("");
            let params = r.record.parse_request_parameters();
            let target = params.as_ref()
                .and_then(|v| v.get("userName"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            // If target is set and differs from caller, flag it
            if !target.is_empty() && !caller.is_empty() && target != caller {
                matching.push(id);
            }
        }
    }

    if matching.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "PE-02".to_string(),
        severity: Severity::High,
        title: "Access Key Created for Another User".to_string(),
        description: format!(
            "{} access key(s) were created where the creator differs from the target user. \
             This pattern is used to establish covert persistence.",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Persistence".to_string(),
        mitre_technique: "T1098.001".to_string(),
        service: "IAM".to_string(),
        query: "eventName=CreateAccessKey".to_string(),
    }]
}

/// PE-03: Login Profile Created
pub fn pe_03_login_profile_created(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("CreateLoginProfile") {
        Some(ids) => ids.clone(),
        None => return vec![],
    };

    if ids.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "PE-03".to_string(),
        severity: Severity::Medium,
        title: "Login Profile Created (Console Access Added)".to_string(),
        description: format!(
            "{} IAM user(s) had console access (login profiles) created. \
             This grants password-based console access to previously API-only accounts.",
            ids.len()
        ),
        matching_count: 0,
        matching_record_ids: ids,
        metadata: HashMap::new(),
        mitre_tactic: "Persistence".to_string(),
        mitre_technique: "T1098".to_string(),
        service: "IAM".to_string(),
        query: "eventName=CreateLoginProfile".to_string(),
    }]
}

/// PE-04: Admin policy attached (AttachUserPolicy/AttachRolePolicy/PutUserPolicy/PutRolePolicy
/// where policy name/ARN contains "AdministratorAccess" or a wildcard resource)
pub fn pe_04_admin_policy_attached(store: &Store) -> Vec<Alert> {
    let event_names = [
        "AttachUserPolicy",
        "AttachRolePolicy",
        "AttachGroupPolicy",
        "PutUserPolicy",
        "PutRolePolicy",
        "PutGroupPolicy",
    ];

    let mut matching = vec![];

    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
            for &id in ids {
                if let Some(r) = store.get_record(id) {
                    let is_admin = check_admin_policy(r.record.parse_request_parameters());
                    if is_admin {
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
        rule_id: "PE-04".to_string(),
        severity: Severity::Critical,
        title: "Administrative Policy Attached".to_string(),
        description: format!(
            "{} event(s) attached an administrative policy (AdministratorAccess or wildcard). \
             This grants unrestricted access and is a common backdoor technique.",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Persistence".to_string(),
        mitre_technique: "T1098.003".to_string(),
        service: "IAM".to_string(),
        query: "eventName=AttachUserPolicy OR eventName=AttachRolePolicy OR eventName=PutUserPolicy OR eventName=PutRolePolicy".to_string(),
    }]
}

fn check_admin_policy(params: Option<serde_json::Value>) -> bool {
    let params = match params {
        Some(p) => p,
        None => return false,
    };

    // Managed policy ARN (AttachUserPolicy etc.)
    if let Some(arn) = params.get("policyArn").and_then(|v| v.as_str()) {
        if arn.contains("AdministratorAccess") || arn == "*" {
            return true;
        }
    }

    // Inline policy document (PutUserPolicy etc.)
    if let Some(doc) = params.get("policyDocument").and_then(|v| v.as_str()) {
        // Quick string scan for admin wildcards
        if doc.contains("\"*\"") && doc.contains("\"Effect\":\"Allow\"") {
            return true;
        }
        if doc.contains("AdministratorAccess") {
            return true;
        }
    }

    false
}
