use std::collections::HashMap;
use crate::store::Store;
use crate::detection::{Alert, Severity};

/// LM-01: Lambda Function Public Access via Resource Policy
pub fn lm_01_lambda_public_access(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("AddPermission20150331v2") {
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
        return vec![];
    }

    vec![Alert {
        rule_id: "LM-01".to_string(),
        severity: Severity::High,
        title: "Lambda Function Granted Public Access".to_string(),
        description: format!(
            "{} Lambda function(s) were granted public invocation access (principal=*). \
             Publicly accessible Lambda functions can be invoked by any AWS principal.",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Persistence".to_string(),
        mitre_technique: "T1098".to_string(),
        service: "Lambda".to_string(),
        query: "eventName=AddPermission20150331v2".to_string(),
    }]
}

/// LM-02: Lambda Environment Variables Updated
pub fn lm_02_lambda_env_updated(store: &Store) -> Vec<Alert> {
    // Lambda function configuration updates (v2 API variant)
    let event_names = [
        "UpdateFunctionConfiguration20150331v2",
        "UpdateFunctionConfiguration",
    ];
    let mut matching = vec![];

    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
            for &id in ids {
                if let Some(r) = store.get_record(id) {
                    let params_str = r.record.request_parameters
                        .as_ref()
                        .map(|v| v.get().to_string())
                        .unwrap_or_default();
                    if params_str.contains("Environment") || params_str.contains("environment") {
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
        rule_id: "LM-02".to_string(),
        severity: Severity::Low,
        title: "Lambda Environment Variables Updated".to_string(),
        description: format!(
            "{} Lambda function(s) had environment variables updated. Attackers may inject \
             malicious values (e.g., modified endpoints, stolen credentials as env vars).",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Persistence".to_string(),
        mitre_technique: "T1525".to_string(),
        service: "Lambda".to_string(),
        query: "eventName=UpdateFunctionConfiguration20150331v2".to_string(),
    }]
}
