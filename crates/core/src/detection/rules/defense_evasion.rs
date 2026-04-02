use std::collections::HashMap;
use crate::store::Store;
use crate::detection::{Alert, Severity};

/// DE-01: CloudTrail Stopped or Deleted
pub fn de_01_cloudtrail_stopped(store: &Store) -> Vec<Alert> {
    let event_names = ["StopLogging", "DeleteTrail", "UpdateTrail"];
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
        rule_id: "DE-01".to_string(),
        severity: Severity::Critical,
        title: "CloudTrail Logging Tampered".to_string(),
        description: format!(
            "{} event(s) stopped, deleted, or modified CloudTrail logging. \
             Attackers disable logging to avoid detection of subsequent actions.",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata: meta,
        mitre_tactic: "Defense Evasion".to_string(),
        mitre_technique: "T1562.008".to_string(),
        service: "CloudTrail".to_string(),
        query: "eventName=StopLogging OR eventName=DeleteTrail OR eventName=UpdateTrail".to_string(),
    }]
}

/// DE-02: GuardDuty Disabled
pub fn de_02_guardduty_disabled(store: &Store) -> Vec<Alert> {
    let event_names = ["DeleteDetector", "StopMonitoringMembers", "DisassociateMembers"];
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
        rule_id: "DE-02".to_string(),
        severity: Severity::Critical,
        title: "GuardDuty Disabled".to_string(),
        description: format!(
            "{} event(s) disabled or disrupted GuardDuty threat detection. \
             This removes active threat monitoring from the account.",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Defense Evasion".to_string(),
        mitre_technique: "T1562.001".to_string(),
        service: "GuardDuty".to_string(),
        query: "eventName=DeleteDetector OR eventName=StopMonitoringMembers OR eventName=DisassociateMembers".to_string(),
    }]
}

/// DE-04: Config Recorder Stopped
pub fn de_04_config_recorder_stopped(store: &Store) -> Vec<Alert> {
    let event_names = ["StopConfigurationRecorder", "DeleteConfigurationRecorder"];
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
        rule_id: "DE-04".to_string(),
        severity: Severity::High,
        title: "AWS Config Recorder Stopped".to_string(),
        description: format!(
            "{} event(s) stopped or deleted the AWS Config configuration recorder. \
             This disables resource configuration tracking.",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Defense Evasion".to_string(),
        mitre_technique: "T1562.001".to_string(),
        service: "Config".to_string(),
        query: "eventName=StopConfigurationRecorder OR eventName=DeleteConfigurationRecorder".to_string(),
    }]
}

/// DE-05: VPC Flow Log Deletion
pub fn de_05_flow_log_deleted(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("DeleteFlowLogs") {
        Some(ids) => ids.clone(),
        None => return vec![],
    };

    if ids.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "DE-05".to_string(),
        severity: Severity::Critical,
        title: "VPC Flow Logs Deleted".to_string(),
        description: format!(
            "{} VPC flow log(s) were deleted. Flow logs capture network traffic metadata; \
             deleting them blinds network-level investigation.",
            ids.len()
        ),
        matching_count: 0,
        matching_record_ids: ids,
        metadata: HashMap::new(),
        mitre_tactic: "Defense Evasion".to_string(),
        mitre_technique: "T1562.008".to_string(),
        service: "VPC".to_string(),
        query: "eventName=DeleteFlowLogs".to_string(),
    }]
}

/// DE-06: CloudWatch Log Group Deletion
pub fn de_06_log_group_deleted(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("DeleteLogGroup") {
        Some(ids) => ids.clone(),
        None => return vec![],
    };

    if ids.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "DE-06".to_string(),
        severity: Severity::High,
        title: "CloudWatch Log Group Deleted".to_string(),
        description: format!(
            "{} CloudWatch log group(s) were deleted. Removing log groups destroys audit \
             evidence and may hide attacker activity.",
            ids.len()
        ),
        matching_count: 0,
        matching_record_ids: ids,
        metadata: HashMap::new(),
        mitre_tactic: "Defense Evasion".to_string(),
        mitre_technique: "T1562.008".to_string(),
        service: "CloudWatch".to_string(),
        query: "eventName=DeleteLogGroup".to_string(),
    }]
}

/// DE-07: CloudTrail S3 Logging Bucket Changed (UpdateTrail with s3BucketName)
pub fn de_07_cloudtrail_s3_changed(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("UpdateTrail") {
        Some(ids) => ids,
        None => return vec![],
    };

    let mut matching = vec![];
    for &id in ids {
        if let Some(r) = store.get_record(id) {
            let has_s3_change = r.record.parse_request_parameters()
                .and_then(|v| v.get("s3BucketName").map(|_| true))
                .unwrap_or(false);
            if has_s3_change {
                matching.push(id);
            }
        }
    }

    if matching.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "DE-07".to_string(),
        severity: Severity::High,
        title: "CloudTrail S3 Logging Bucket Changed".to_string(),
        description: format!(
            "{} CloudTrail trail(s) had their S3 logging bucket changed. \
             Redirecting logs to an attacker-controlled bucket can hide evidence.",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Defense Evasion".to_string(),
        mitre_technique: "T1562.008".to_string(),
        service: "CloudTrail".to_string(),
        query: "eventName=UpdateTrail".to_string(),
    }]
}

/// DE-08: EventBridge Rule Disabled
pub fn de_08_eventbridge_rule_disabled(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("DisableRule") {
        Some(ids) => ids.clone(),
        None => return vec![],
    };

    if ids.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "DE-08".to_string(),
        severity: Severity::Medium,
        title: "EventBridge Rule Disabled".to_string(),
        description: format!(
            "{} EventBridge rule(s) were disabled. Disabling event rules can \
             suppress automated security responses and alerting.",
            ids.len()
        ),
        matching_count: 0,
        matching_record_ids: ids,
        metadata: HashMap::new(),
        mitre_tactic: "Defense Evasion".to_string(),
        mitre_technique: "T1562.001".to_string(),
        service: "EventBridge".to_string(),
        query: "eventName=DisableRule".to_string(),
    }]
}

/// DE-09: WAF Web ACL Deletion
pub fn de_09_waf_acl_deleted(store: &Store) -> Vec<Alert> {
    let event_names = ["DeleteWebACL", "DeleteWebAclV2"];
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
        rule_id: "DE-09".to_string(),
        severity: Severity::High,
        title: "WAF Web ACL Deleted".to_string(),
        description: format!(
            "{} WAF Web ACL(s) were deleted. Removing WAF rules eliminates \
             protection against web-based attacks.",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Defense Evasion".to_string(),
        mitre_technique: "T1562.001".to_string(),
        service: "WAF".to_string(),
        query: "eventName=DeleteWebACL OR eventName=DeleteWebAclV2".to_string(),
    }]
}

/// DE-10: CloudFront Distribution Logging Disabled
pub fn de_10_cloudfront_logging_disabled(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("UpdateDistribution") {
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
            // Look for logging being disabled (Enabled: false in Logging config)
            if params_str.contains("\"Enabled\":false") || params_str.contains("\"enabled\":false") {
                matching.push(id);
            }
        }
    }

    if matching.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "DE-10".to_string(),
        severity: Severity::Medium,
        title: "CloudFront Distribution Logging Disabled".to_string(),
        description: format!(
            "{} CloudFront distribution(s) had logging disabled. \
             This removes visibility into CDN access patterns.",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Defense Evasion".to_string(),
        mitre_technique: "T1562.008".to_string(),
        service: "CloudFront".to_string(),
        query: "eventName=UpdateDistribution".to_string(),
    }]
}

/// DE-11: SQS Queue Encryption Removed
pub fn de_11_sqs_encryption_removed(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("SetQueueAttributes") {
        Some(ids) => ids,
        None => return vec![],
    };

    let mut matching = vec![];
    for &id in ids {
        if let Some(r) = store.get_record(id) {
            // Flag if KmsMasterKeyId is being set to empty or removed
            let params_str = r.record.request_parameters
                .as_ref()
                .map(|v| v.get().to_string())
                .unwrap_or_default();
            if params_str.contains("KmsMasterKeyId") {
                let has_empty_key = params_str.contains("\"KmsMasterKeyId\":\"\"")
                    || params_str.contains("\"KmsMasterKeyId\": \"\"");
                if has_empty_key {
                    matching.push(id);
                }
            }
        }
    }

    if matching.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "DE-11".to_string(),
        severity: Severity::Medium,
        title: "SQS Queue Encryption Removed".to_string(),
        description: format!(
            "{} SQS queue(s) had encryption removed. Messages in unencrypted \
             queues may be exposed to unauthorized access.",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Defense Evasion".to_string(),
        mitre_technique: "T1562.001".to_string(),
        service: "SQS".to_string(),
        query: "eventName=SetQueueAttributes".to_string(),
    }]
}

/// DE-12: SNS Topic Encryption Removed
pub fn de_12_sns_encryption_removed(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("SetTopicAttributes") {
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
            if params_str.contains("KmsMasterKeyId") {
                let has_empty_key = params_str.contains("\"attributeValue\":\"\"")
                    || params_str.contains("\"attributeValue\": \"\"");
                if has_empty_key {
                    matching.push(id);
                }
            }
        }
    }

    if matching.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "DE-12".to_string(),
        severity: Severity::Medium,
        title: "SNS Topic Encryption Removed".to_string(),
        description: format!(
            "{} SNS topic(s) had KMS encryption removed. Unencrypted topics \
             may expose message contents.",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Defense Evasion".to_string(),
        mitre_technique: "T1562.001".to_string(),
        service: "SNS".to_string(),
        query: "eventName=SetTopicAttributes".to_string(),
    }]
}

/// DE-13: Route53 Hosted Zone Deleted
pub fn de_13_route53_zone_deleted(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("DeleteHostedZone") {
        Some(ids) => ids.clone(),
        None => return vec![],
    };

    if ids.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "DE-13".to_string(),
        severity: Severity::Medium,
        title: "Route53 Hosted Zone Deleted".to_string(),
        description: format!(
            "{} Route53 hosted zone(s) were deleted. This can cause DNS resolution \
             failures and may be used to disrupt services.",
            ids.len()
        ),
        matching_count: 0,
        matching_record_ids: ids,
        metadata: HashMap::new(),
        mitre_tactic: "Defense Evasion".to_string(),
        mitre_technique: "T1485".to_string(),
        service: "Route53".to_string(),
        query: "eventName=DeleteHostedZone".to_string(),
    }]
}
