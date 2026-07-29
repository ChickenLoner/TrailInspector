// Additional persistence rules (PE-05, PE-06, PE-07)
use crate::store::Store;
use crate::detection::Finding;

/// PE-06: IAM Policy Version Created and Set as Default
pub fn pe_06_policy_version_created(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("CreatePolicyVersion")?;

    let mut matching = vec![];
    for id in ids {
        if store.get_record(id).is_some() {
            let params_str = store.get_request_parameters_str(id).unwrap_or_default();
            if params_str.contains("\"setAsDefault\":true")
                || params_str.contains("\"setAsDefault\": true")
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
            "{} IAM policy version(s) created and immediately set as default. \
             This pattern is used to escalate privileges by silently updating policy permissions.",
            matching.len()
        ),
        matching,
        "eventName=CreatePolicyVersion",
    ))
}

/// PE-07: Cross-Account AssumeRole
pub fn pe_07_cross_account_assume_role(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("AssumeRole")?;

    let mut matching = vec![];
    for id in ids {
        if let Some(r) = store.get_record(id) {
            let caller_account = r.record.user_identity.account_id.as_deref().unwrap_or("");
            let params = store.parse_request_parameters(id);
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
        return None;
    }

    Some(Finding::new(
        format!(
            "{} AssumeRole event(s) where the caller assumed a role in a different AWS account. \
             Cross-account access warrants review to verify it is authorized.",
            matching.len()
        ),
        matching,
        "eventName=AssumeRole",
    ))
}
