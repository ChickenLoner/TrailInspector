use std::collections::HashMap;
use crate::store::Store;
use crate::detection::{Alert, Severity, scoped_ids, jget, json_has_str, policy_statements};

/// PE-01: IAM User Created
pub fn pe_01_iam_user_created(store: &Store) -> Vec<Alert> {
    let ids = scoped_ids(store, &["CreateUser"], &["iam.amazonaws.com"], true);
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
        matching_record_ids: ids.iter().collect(),
        metadata: meta,
        mitre_tactic: "Persistence".to_string(),
        mitre_technique: "T1136.003".to_string(),
        service: "IAM".to_string(),
        query: "eventName=CreateUser eventSource=iam.amazonaws.com".to_string(),
    }]
}

/// The IAM user name behind an identity: the `userName` field, else the name parsed from a
/// `...:user/[path/]NAME` ARN. `None` for assumed roles, root, services and federated callers.
fn caller_user_name(identity: &crate::model::UserIdentity) -> Option<&str> {
    if let Some(name) = identity.user_name.as_deref() {
        return Some(name);
    }
    let arn = identity.arn.as_deref()?;
    let rest = &arn[arn.find(":user/")? + ":user/".len()..];
    rest.rsplit('/').next().filter(|n| !n.is_empty())
}

/// PE-02: Access Key Created for Another User
pub fn pe_02_access_key_for_other(store: &Store) -> Vec<Alert> {
    let ids = scoped_ids(store, &["CreateAccessKey"], &["iam.amazonaws.com"], true);
    if ids.is_empty() {
        return vec![];
    }

    let mut matching = vec![];
    for id in ids {
        if let Some(r) = store.get_record(id) {
            let caller = caller_user_name(&r.record.user_identity);
            let params = store.parse_request_parameters(id);
            let target = params.as_ref()
                .and_then(|v| v.get("userName"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            // Flag when a target is named and the caller is not that same IAM user.
            // Assumed roles and root have no IAM user name, so they always count as "other".
            if !target.is_empty() && caller != Some(target) {
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
        query: "eventName=CreateAccessKey eventSource=iam.amazonaws.com".to_string(),
    }]
}

/// PE-03: Login Profile Created
pub fn pe_03_login_profile_created(store: &Store) -> Vec<Alert> {
    let ids = scoped_ids(store, &["CreateLoginProfile"], &["iam.amazonaws.com"], true);
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
        matching_record_ids: ids.iter().collect(),
        metadata: HashMap::new(),
        mitre_tactic: "Persistence".to_string(),
        mitre_technique: "T1098".to_string(),
        service: "IAM".to_string(),
        query: "eventName=CreateLoginProfile eventSource=iam.amazonaws.com".to_string(),
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

    let ids = scoped_ids(store, &event_names, &["iam.amazonaws.com"], true);
    for id in ids {
        if store.get_record(id).is_some() {
            let is_admin = check_admin_policy(store.parse_request_parameters(id));
            if is_admin {
                matching.push(id);
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
        query: ["AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy", "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy"].iter().map(|n| format!("eventName={n} eventSource=iam.amazonaws.com")).collect::<Vec<_>>().join(" OR "),
    }]
}

/// Managed policies that are effectively admin.
const ADMIN_MANAGED_POLICIES: [&str; 3] = ["AdministratorAccess", "PowerUserAccess", "IAMFullAccess"];

/// Decode `%XX` escapes. CloudTrail often records inline `policyDocument` URL-encoded.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hi = (b[i + 1] as char).to_digit(16);
            let lo = (b[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Does this statement `Allow` every action (or `iam:*`) on every resource?
fn statement_is_admin(st: &serde_json::Value) -> bool {
    let allow = jget(st, "Effect").is_some_and(|e| json_has_str(e, "Allow"));
    let all_actions = jget(st, "Action").is_some_and(|a| json_has_str(a, "*") || json_has_str(a, "iam:*"));
    let all_resources = jget(st, "Resource").is_some_and(|r| json_has_str(r, "*"));
    allow && all_actions && all_resources
}

fn check_admin_policy(params: Option<serde_json::Value>) -> bool {
    let params = match params {
        Some(p) => p,
        None => return false,
    };

    // Managed policy ARN (AttachUserPolicy etc.)
    if let Some(arn) = jget(&params, "policyArn").and_then(|v| v.as_str()) {
        if ADMIN_MANAGED_POLICIES.iter().any(|name| arn.ends_with(&format!("policy/{name}"))) {
            return true;
        }
    }

    // Inline policy document (PutUserPolicy etc.): a JSON string, possibly URL-encoded,
    // or an already-parsed object.
    let doc: Option<serde_json::Value> = match jget(&params, "policyDocument") {
        Some(serde_json::Value::String(s)) => {
            let text = if s.contains('%') { percent_decode(s) } else { s.clone() };
            serde_json::from_str(&text).ok()
        }
        Some(v @ serde_json::Value::Object(_)) => Some(v.clone()),
        _ => None,
    };
    doc.is_some_and(|d| policy_statements(&d).into_iter().any(statement_is_admin))
}
