use crate::store::Store;
use crate::detection::Finding;

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

