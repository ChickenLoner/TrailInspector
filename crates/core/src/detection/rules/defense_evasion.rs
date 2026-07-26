use crate::store::Store;
use crate::detection::Finding;

/// DE-01: CloudTrail Stopped or Deleted
pub fn de_01_cloudtrail_stopped(store: &Store) -> Option<Finding> {
    let event_names = ["StopLogging", "DeleteTrail", "UpdateTrail"];
    let mut matching = vec![];

    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
            matching.extend(ids);
        }
    }

    if matching.is_empty() {
        return None;
    }

    let count = matching.len();
    Some(
        Finding::new(
            format!(
                "{count} event(s) stopped, deleted, or modified CloudTrail logging. \
                 Attackers disable logging to avoid detection of subsequent actions."
            ),
            matching,
            "eventName=StopLogging OR eventName=DeleteTrail OR eventName=UpdateTrail",
        )
        .meta("count", count.to_string()),
    )
}

/// DE-02: GuardDuty Disabled
pub fn de_02_guardduty_disabled(store: &Store) -> Option<Finding> {
    let event_names = ["DeleteDetector", "StopMonitoringMembers", "DisassociateMembers"];
    let mut matching = vec![];

    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
            matching.extend(ids);
        }
    }

    if matching.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} event(s) disabled or disrupted GuardDuty threat detection. \
             This removes active threat monitoring from the account.",
            matching.len()
        ),
        matching,
        "eventName=DeleteDetector OR eventName=StopMonitoringMembers OR eventName=DisassociateMembers",
    ))
}

/// DE-04: Config Recorder Stopped
pub fn de_04_config_recorder_stopped(store: &Store) -> Option<Finding> {
    let event_names = ["StopConfigurationRecorder", "DeleteConfigurationRecorder"];
    let mut matching = vec![];

    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
            matching.extend(ids);
        }
    }

    if matching.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} event(s) stopped or deleted the AWS Config configuration recorder. \
             This disables resource configuration tracking.",
            matching.len()
        ),
        matching,
        "eventName=StopConfigurationRecorder OR eventName=DeleteConfigurationRecorder",
    ))
}

/// DE-05: VPC Flow Log Deletion
pub fn de_05_flow_log_deleted(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("DeleteFlowLogs")?;

    if ids.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} VPC flow log(s) were deleted. Flow logs capture network traffic metadata; \
             deleting them blinds network-level investigation.",
            ids.len()
        ),
        ids.iter().collect(),
        "eventName=DeleteFlowLogs",
    ))
}

/// DE-06: CloudWatch Log Group Deletion
pub fn de_06_log_group_deleted(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("DeleteLogGroup")?;

    if ids.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} CloudWatch log group(s) were deleted. Removing log groups destroys audit \
             evidence and may hide attacker activity.",
            ids.len()
        ),
        ids.iter().collect(),
        "eventName=DeleteLogGroup",
    ))
}

/// DE-07: CloudTrail S3 Logging Bucket Changed (UpdateTrail with s3BucketName)
pub fn de_07_cloudtrail_s3_changed(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("UpdateTrail")?;

    let mut matching = vec![];
    for id in ids {
        if store.get_record(id).is_some() {
            let has_s3_change = store.parse_request_parameters(id)
                .and_then(|v| v.get("s3BucketName").map(|_| true))
                .unwrap_or(false);
            if has_s3_change {
                matching.push(id);
            }
        }
    }

    if matching.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} CloudTrail trail(s) had their S3 logging bucket changed. \
             Redirecting logs to an attacker-controlled bucket can hide evidence.",
            matching.len()
        ),
        matching,
        "eventName=UpdateTrail",
    ))
}

/// DE-08: EventBridge Rule Disabled
pub fn de_08_eventbridge_rule_disabled(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("DisableRule")?;

    if ids.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} EventBridge rule(s) were disabled. Disabling event rules can \
             suppress automated security responses and alerting.",
            ids.len()
        ),
        ids.iter().collect(),
        "eventName=DisableRule",
    ))
}

/// DE-09: WAF Web ACL Deletion
pub fn de_09_waf_acl_deleted(store: &Store) -> Option<Finding> {
    let event_names = ["DeleteWebACL", "DeleteWebAclV2"];
    let mut matching = vec![];

    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
            matching.extend(ids);
        }
    }

    if matching.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} WAF Web ACL(s) were deleted. Removing WAF rules eliminates \
             protection against web-based attacks.",
            matching.len()
        ),
        matching,
        "eventName=DeleteWebACL OR eventName=DeleteWebAclV2",
    ))
}

/// DE-10: CloudFront Distribution Logging Disabled
pub fn de_10_cloudfront_logging_disabled(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("UpdateDistribution")?;

    let mut matching = vec![];
    for id in ids {
        if store.get_record(id).is_some() {
            let params_str = store.get_request_parameters_str(id).unwrap_or_default();
            // Look for logging being disabled (Enabled: false in Logging config)
            if params_str.contains("\"Enabled\":false") || params_str.contains("\"enabled\":false") {
                matching.push(id);
            }
        }
    }

    if matching.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} CloudFront distribution(s) had logging disabled. \
             This removes visibility into CDN access patterns.",
            matching.len()
        ),
        matching,
        "eventName=UpdateDistribution",
    ))
}

/// DE-11: SQS Queue Encryption Removed
pub fn de_11_sqs_encryption_removed(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("SetQueueAttributes")?;

    let mut matching = vec![];
    for id in ids {
        if store.get_record(id).is_some() {
            // Flag if KmsMasterKeyId is being set to empty or removed
            let params_str = store.get_request_parameters_str(id).unwrap_or_default();
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
        return None;
    }

    Some(Finding::new(
        format!(
            "{} SQS queue(s) had encryption removed. Messages in unencrypted \
             queues may be exposed to unauthorized access.",
            matching.len()
        ),
        matching,
        "eventName=SetQueueAttributes",
    ))
}

/// DE-12: SNS Topic Encryption Removed
pub fn de_12_sns_encryption_removed(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("SetTopicAttributes")?;

    let mut matching = vec![];
    for id in ids {
        if store.get_record(id).is_some() {
            let params_str = store.get_request_parameters_str(id).unwrap_or_default();
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
        return None;
    }

    Some(Finding::new(
        format!(
            "{} SNS topic(s) had KMS encryption removed. Unencrypted topics \
             may expose message contents.",
            matching.len()
        ),
        matching,
        "eventName=SetTopicAttributes",
    ))
}

/// DE-13: Route53 Hosted Zone Deleted
pub fn de_13_route53_zone_deleted(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("DeleteHostedZone")?;

    if ids.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} Route53 hosted zone(s) were deleted. This can cause DNS resolution \
             failures and may be used to disrupt services.",
            ids.len()
        ),
        ids.iter().collect(),
        "eventName=DeleteHostedZone",
    ))
}
