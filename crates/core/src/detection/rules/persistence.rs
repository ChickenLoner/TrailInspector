use crate::store::Store;
use crate::detection::Finding;

/// PE-01: IAM User Created
pub fn pe_01_iam_user_created(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("CreateUser")?;

    if ids.is_empty() {
        return None;
    }

    let count = ids.len();
    Some(
        Finding::new(
            format!(
                "{count} IAM user(s) were created. Review whether these accounts are expected \
                 and authorized."
            ),
            ids.iter().collect(),
            "eventName=CreateUser",
        )
        .meta("count", count.to_string()),
    )
}

/// PE-02: Access Key Created for Another User
pub fn pe_02_access_key_for_other(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("CreateAccessKey")?;

    let mut matching = vec![];
    for id in ids {
        if let Some(r) = store.get_record(id) {
            let caller = r.record.user_identity.user_name.as_deref().unwrap_or("");
            let params = store.parse_request_parameters(id);
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
        return None;
    }

    Some(Finding::new(
        format!(
            "{} access key(s) were created where the creator differs from the target user. \
             This pattern is used to establish covert persistence.",
            matching.len()
        ),
        matching,
        "eventName=CreateAccessKey",
    ))
}

/// PE-03: Login Profile Created
pub fn pe_03_login_profile_created(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("CreateLoginProfile")?;

    if ids.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} IAM user(s) had console access (login profiles) created. \
             This grants password-based console access to previously API-only accounts.",
            ids.len()
        ),
        ids.iter().collect(),
        "eventName=CreateLoginProfile",
    ))
}

/// PE-04: Admin policy attached (AttachUserPolicy/AttachRolePolicy/PutUserPolicy/PutRolePolicy
/// where policy name/ARN contains "AdministratorAccess" or a wildcard resource)
pub fn pe_04_admin_policy_attached(store: &Store) -> Option<Finding> {
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
            for id in ids {
                if store.get_record(id).is_some() {
                    let is_admin = check_admin_policy(store.parse_request_parameters(id));
                    if is_admin {
                        matching.push(id);
                    }
                }
            }
        }
    }

    if matching.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} event(s) attached an administrative policy (AdministratorAccess or wildcard). \
             This grants unrestricted access and is a common backdoor technique.",
            matching.len()
        ),
        matching,
        "eventName=AttachUserPolicy OR eventName=AttachRolePolicy OR eventName=PutUserPolicy OR eventName=PutRolePolicy",
    ))
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
