use crate::store::Store;
use crate::detection::Finding;

/// LM-01: Lambda Function Public Access via Resource Policy
pub fn lm_01_lambda_public_access(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("AddPermission20150331v2")?;

    let mut matching = vec![];
    for id in ids {
        if store.get_record(id).is_some() {
            let params_str = store.get_request_parameters_str(id).unwrap_or_default();
            // principal "*" means public access
            if params_str.contains("\"principal\":\"*\"")
                || params_str.contains("\"Principal\":\"*\"")
                || params_str.contains("principal: \"*\"")
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
            "{} Lambda function(s) were granted public invocation access (principal=*). \
             Publicly accessible Lambda functions can be invoked by any AWS principal.",
            matching.len()
        ),
        matching,
        "eventName=AddPermission20150331v2",
    ))
}

/// LM-02: Lambda Environment Variables Updated
pub fn lm_02_lambda_env_updated(store: &Store) -> Option<Finding> {
    // Lambda function configuration updates (v2 API variant)
    let event_names = [
        "UpdateFunctionConfiguration20150331v2",
        "UpdateFunctionConfiguration",
    ];
    let mut matching = vec![];

    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
            for id in ids {
                let params_str = store.get_request_parameters_str(id).unwrap_or_default();
                if params_str.contains("Environment") || params_str.contains("environment") {
                    matching.push(id);
                }
            }
        }
    }

    if matching.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} Lambda function(s) had environment variables updated. Attackers may inject \
             malicious values (e.g., modified endpoints, stolen credentials as env vars).",
            matching.len()
        ),
        matching,
        "eventName=UpdateFunctionConfiguration20150331v2",
    ))
}
