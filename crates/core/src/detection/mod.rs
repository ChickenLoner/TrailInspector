use std::collections::HashMap;
use crate::store::Store;
use crate::geoip::GeoIpEngine;

pub mod rules;
pub mod custom_rules;

#[cfg(test)]
mod tests;

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Alert {
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    /// True count of matching records (may exceed matching_record_ids.len()).
    pub matching_count: usize,
    /// Up to 100 matching record IDs (capped for IPC efficiency).
    pub matching_record_ids: Vec<u32>,
    pub metadata: HashMap<String, String>,
    pub mitre_tactic: String,
    pub mitre_technique: String,
    /// AWS service category (e.g. "IAM", "S3", "VPC", "RDS")
    pub service: String,
    /// Pre-built query string — paste into the search bar to see matching events.
    pub query: String,
}

pub struct DetectionRule {
    pub id: &'static str,
    pub name: &'static str,
    pub severity: Severity,
    pub mitre_tactic: &'static str,
    pub mitre_technique: &'static str,
    pub service: &'static str,
    pub evaluate: fn(&Store) -> Vec<Alert>,
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

fn all_rules() -> Vec<DetectionRule> {
    vec![
        // ── Initial Access ───────────────────────────────────────────────
        DetectionRule {
            id: "IA-01",
            name: "Console Login Without MFA",
            severity: Severity::High,
            mitre_tactic: "Initial Access",
            mitre_technique: "T1078.004",
            service: "IAM",
            evaluate: rules::initial_access::ia_01_console_login_no_mfa,
        },
        DetectionRule {
            id: "IA-03",
            name: "Root Account Usage",
            severity: Severity::Critical,
            mitre_tactic: "Initial Access",
            mitre_technique: "T1078.004",
            service: "IAM",
            evaluate: rules::initial_access::ia_03_root_usage,
        },
        DetectionRule {
            id: "IA-04",
            name: "Failed Login Brute Force",
            severity: Severity::High,
            mitre_tactic: "Initial Access",
            mitre_technique: "T1110.001",
            service: "IAM",
            evaluate: rules::initial_access::ia_04_brute_force,
        },
        // ── Persistence ──────────────────────────────────────────────────
        DetectionRule {
            id: "PE-01",
            name: "IAM User Created",
            severity: Severity::Medium,
            mitre_tactic: "Persistence",
            mitre_technique: "T1136.003",
            service: "IAM",
            evaluate: rules::persistence::pe_01_iam_user_created,
        },
        DetectionRule {
            id: "PE-02",
            name: "Access Key Created for Another User",
            severity: Severity::High,
            mitre_tactic: "Persistence",
            mitre_technique: "T1098.001",
            service: "IAM",
            evaluate: rules::persistence::pe_02_access_key_for_other,
        },
        DetectionRule {
            id: "PE-03",
            name: "Login Profile Created",
            severity: Severity::Medium,
            mitre_tactic: "Persistence",
            mitre_technique: "T1098",
            service: "IAM",
            evaluate: rules::persistence::pe_03_login_profile_created,
        },
        DetectionRule {
            id: "PE-04",
            name: "Backdoor Admin Policy Attached",
            severity: Severity::Critical,
            mitre_tactic: "Persistence",
            mitre_technique: "T1098.003",
            service: "IAM",
            evaluate: rules::persistence::pe_04_admin_policy_attached,
        },
        DetectionRule {
            id: "PE-05",
            name: "MFA Device Deactivated",
            severity: Severity::High,
            mitre_tactic: "Persistence",
            mitre_technique: "T1556.006",
            service: "IAM",
            evaluate: rules::persistence_ext::pe_05_mfa_deactivated,
        },
        DetectionRule {
            id: "PE-06",
            name: "IAM Policy Version Created (SetAsDefault)",
            severity: Severity::Medium,
            mitre_tactic: "Persistence",
            mitre_technique: "T1098.003",
            service: "IAM",
            evaluate: rules::persistence_ext::pe_06_policy_version_created,
        },
        DetectionRule {
            id: "PE-07",
            name: "Cross-Account AssumeRole",
            severity: Severity::Medium,
            mitre_tactic: "Persistence",
            mitre_technique: "T1098.001",
            service: "STS",
            evaluate: rules::persistence_ext::pe_07_cross_account_assume_role,
        },
        // ── Defense Evasion ──────────────────────────────────────────────
        DetectionRule {
            id: "DE-01",
            name: "CloudTrail Stopped or Deleted",
            severity: Severity::Critical,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.008",
            service: "CloudTrail",
            evaluate: rules::defense_evasion::de_01_cloudtrail_stopped,
        },
        DetectionRule {
            id: "DE-02",
            name: "GuardDuty Disabled",
            severity: Severity::Critical,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.001",
            service: "GuardDuty",
            evaluate: rules::defense_evasion::de_02_guardduty_disabled,
        },
        DetectionRule {
            id: "DE-04",
            name: "Config Recorder Stopped",
            severity: Severity::High,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.001",
            service: "Config",
            evaluate: rules::defense_evasion::de_04_config_recorder_stopped,
        },
        DetectionRule {
            id: "DE-05",
            name: "VPC Flow Log Deletion",
            severity: Severity::Critical,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.008",
            service: "VPC",
            evaluate: rules::defense_evasion::de_05_flow_log_deleted,
        },
        DetectionRule {
            id: "DE-06",
            name: "CloudWatch Log Group Deleted",
            severity: Severity::High,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.008",
            service: "CloudWatch",
            evaluate: rules::defense_evasion::de_06_log_group_deleted,
        },
        DetectionRule {
            id: "DE-07",
            name: "CloudTrail S3 Logging Bucket Changed",
            severity: Severity::High,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.008",
            service: "CloudTrail",
            evaluate: rules::defense_evasion::de_07_cloudtrail_s3_changed,
        },
        DetectionRule {
            id: "DE-08",
            name: "EventBridge Rule Disabled",
            severity: Severity::Medium,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.001",
            service: "EventBridge",
            evaluate: rules::defense_evasion::de_08_eventbridge_rule_disabled,
        },
        DetectionRule {
            id: "DE-09",
            name: "WAF Web ACL Deleted",
            severity: Severity::High,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.001",
            service: "WAF",
            evaluate: rules::defense_evasion::de_09_waf_acl_deleted,
        },
        DetectionRule {
            id: "DE-10",
            name: "CloudFront Distribution Logging Disabled",
            severity: Severity::Medium,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.008",
            service: "CloudFront",
            evaluate: rules::defense_evasion::de_10_cloudfront_logging_disabled,
        },
        DetectionRule {
            id: "DE-11",
            name: "SQS Queue Encryption Removed",
            severity: Severity::Medium,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.001",
            service: "SQS",
            evaluate: rules::defense_evasion::de_11_sqs_encryption_removed,
        },
        DetectionRule {
            id: "DE-12",
            name: "SNS Topic Encryption Removed",
            severity: Severity::Medium,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.001",
            service: "SNS",
            evaluate: rules::defense_evasion::de_12_sns_encryption_removed,
        },
        DetectionRule {
            id: "DE-13",
            name: "Route53 Hosted Zone Deleted",
            severity: Severity::Medium,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1485",
            service: "Route53",
            evaluate: rules::defense_evasion::de_13_route53_zone_deleted,
        },
        // ── Credential Access ────────────────────────────────────────────
        DetectionRule {
            id: "CA-02",
            name: "Secrets Manager Bulk Access",
            severity: Severity::High,
            mitre_tactic: "Credential Access",
            mitre_technique: "T1555",
            service: "SecretsManager",
            evaluate: rules::credential_access::ca_02_secrets_bulk,
        },
        DetectionRule {
            id: "CA-04",
            name: "Password Policy Weakened",
            severity: Severity::Medium,
            mitre_tactic: "Credential Access",
            mitre_technique: "T1556",
            service: "IAM",
            evaluate: rules::credential_access::ca_04_password_policy_weakened,
        },
        DetectionRule {
            id: "CA-05",
            name: "Root Account Console Login",
            severity: Severity::Critical,
            mitre_tactic: "Credential Access",
            mitre_technique: "T1078.004",
            service: "IAM",
            evaluate: rules::credential_access::ca_05_root_console_login,
        },
        DetectionRule {
            id: "CA-06",
            name: "KMS Key Scheduled for Deletion",
            severity: Severity::High,
            mitre_tactic: "Credential Access",
            mitre_technique: "T1485",
            service: "KMS",
            evaluate: rules::credential_access::ca_06_kms_key_deletion,
        },
        // ── Discovery ────────────────────────────────────────────────────
        DetectionRule {
            id: "DI-02",
            name: "IAM Enumeration",
            severity: Severity::Medium,
            mitre_tactic: "Discovery",
            mitre_technique: "T1087.004",
            service: "IAM",
            evaluate: rules::discovery::di_02_iam_enumeration,
        },
        DetectionRule {
            id: "DI-03",
            name: "AccessDenied Spike",
            severity: Severity::Medium,
            mitre_tactic: "Discovery",
            mitre_technique: "T1580",
            service: "IAM",
            evaluate: rules::discovery::di_03_access_denied_spike,
        },
        // ── Exfiltration ─────────────────────────────────────────────────
        DetectionRule {
            id: "EX-01",
            name: "S3 Bucket Made Public",
            severity: Severity::High,
            mitre_tactic: "Exfiltration",
            mitre_technique: "T1537",
            service: "S3",
            evaluate: rules::exfiltration::ex_01_s3_bucket_public,
        },
        DetectionRule {
            id: "EX-02",
            name: "S3 Bucket Deleted",
            severity: Severity::Medium,
            mitre_tactic: "Exfiltration",
            mitre_technique: "T1485",
            service: "S3",
            evaluate: rules::exfiltration::ex_02_s3_bucket_deleted,
        },
        DetectionRule {
            id: "EX-03",
            name: "S3 Bulk Object Download",
            severity: Severity::Medium,
            mitre_tactic: "Exfiltration",
            mitre_technique: "T1530",
            service: "S3",
            evaluate: rules::exfiltration::ex_03_s3_bulk_download,
        },
        DetectionRule {
            id: "EX-04",
            name: "S3 Bucket Access Logging Disabled",
            severity: Severity::Medium,
            mitre_tactic: "Exfiltration",
            mitre_technique: "T1562.008",
            service: "S3",
            evaluate: rules::exfiltration::ex_04_s3_logging_disabled,
        },
        DetectionRule {
            id: "EX-05",
            name: "S3 Bucket Encryption Removed",
            severity: Severity::High,
            mitre_tactic: "Exfiltration",
            mitre_technique: "T1537",
            service: "S3",
            evaluate: rules::exfiltration::ex_05_s3_encryption_removed,
        },
        // ── Impact ───────────────────────────────────────────────────────
        DetectionRule {
            id: "IM-01",
            name: "EC2 Instances Launched in Bulk",
            severity: Severity::High,
            mitre_tactic: "Impact",
            mitre_technique: "T1496",
            service: "EC2",
            evaluate: rules::impact::im_01_ec2_bulk_launch,
        },
        DetectionRule {
            id: "IM-02",
            name: "Resource Deletion Spree",
            severity: Severity::Critical,
            mitre_tactic: "Impact",
            mitre_technique: "T1485",
            service: "Multi",
            evaluate: rules::impact::im_02_resource_deletion_spree,
        },
        DetectionRule {
            id: "IM-03",
            name: "SES Email Identity Verified",
            severity: Severity::Low,
            mitre_tactic: "Impact",
            mitre_technique: "T1534",
            service: "SES",
            evaluate: rules::impact::im_03_ses_email_verified,
        },
        // ── Network ──────────────────────────────────────────────────────
        DetectionRule {
            id: "NW-01",
            name: "Security Group Ingress Open to 0.0.0.0/0",
            severity: Severity::High,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.007",
            service: "VPC",
            evaluate: rules::network::nw_01_sg_ingress_all,
        },
        DetectionRule {
            id: "NW-02",
            name: "Network ACL Allows All Traffic",
            severity: Severity::Medium,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.007",
            service: "VPC",
            evaluate: rules::network::nw_02_nacl_allows_all,
        },
        DetectionRule {
            id: "NW-03",
            name: "Internet Gateway Created",
            severity: Severity::Info,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.007",
            service: "VPC",
            evaluate: rules::network::nw_03_igw_created,
        },
        DetectionRule {
            id: "NW-04",
            name: "Route to Internet Added",
            severity: Severity::Medium,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.007",
            service: "VPC",
            evaluate: rules::network::nw_04_route_to_internet,
        },
        DetectionRule {
            id: "NW-05",
            name: "VPC Peering Connection Created",
            severity: Severity::Info,
            mitre_tactic: "Lateral Movement",
            mitre_technique: "T1021",
            service: "VPC",
            evaluate: rules::network::nw_05_vpc_peering_created,
        },
        DetectionRule {
            id: "NW-06",
            name: "Security Group Deleted",
            severity: Severity::Low,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.007",
            service: "VPC",
            evaluate: rules::network::nw_06_sg_deleted,
        },
        DetectionRule {
            id: "NW-07",
            name: "Subnet Auto-Assign Public IP Enabled",
            severity: Severity::Medium,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.007",
            service: "VPC",
            evaluate: rules::network::nw_07_subnet_public,
        },
        DetectionRule {
            id: "NW-08",
            name: "NAT Gateway Deleted",
            severity: Severity::Low,
            mitre_tactic: "Impact",
            mitre_technique: "T1485",
            service: "VPC",
            evaluate: rules::network::nw_08_nat_deleted,
        },
        // ── RDS ──────────────────────────────────────────────────────────
        DetectionRule {
            id: "RDS-01",
            name: "RDS Deletion Protection Disabled",
            severity: Severity::High,
            mitre_tactic: "Impact",
            mitre_technique: "T1485",
            service: "RDS",
            evaluate: rules::rds::rds_01_deletion_protection_disabled,
        },
        DetectionRule {
            id: "RDS-02",
            name: "RDS Instance Restored with Public Access",
            severity: Severity::High,
            mitre_tactic: "Exfiltration",
            mitre_technique: "T1537",
            service: "RDS",
            evaluate: rules::rds::rds_02_public_snapshot_restore,
        },
        DetectionRule {
            id: "RDS-03",
            name: "RDS Master Password Changed",
            severity: Severity::Medium,
            mitre_tactic: "Credential Access",
            mitre_technique: "T1098",
            service: "RDS",
            evaluate: rules::rds::rds_03_master_password_changed,
        },
        // ── EBS ──────────────────────────────────────────────────────────
        DetectionRule {
            id: "EBS-01",
            name: "EBS Default Encryption Disabled",
            severity: Severity::High,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1486",
            service: "EBS",
            evaluate: rules::ebs::ebs_01_encryption_disabled,
        },
        DetectionRule {
            id: "EBS-02",
            name: "EBS Snapshot Made Public",
            severity: Severity::Critical,
            mitre_tactic: "Exfiltration",
            mitre_technique: "T1537",
            service: "EBS",
            evaluate: rules::ebs::ebs_02_snapshot_public,
        },
        DetectionRule {
            id: "EBS-03",
            name: "EBS Volume Detached",
            severity: Severity::Low,
            mitre_tactic: "Exfiltration",
            mitre_technique: "T1537",
            service: "EBS",
            evaluate: rules::ebs::ebs_03_volume_detached,
        },
        DetectionRule {
            id: "EBS-04",
            name: "EBS Snapshot Deleted",
            severity: Severity::Medium,
            mitre_tactic: "Impact",
            mitre_technique: "T1485",
            service: "EBS",
            evaluate: rules::ebs::ebs_04_snapshot_deleted,
        },
        DetectionRule {
            id: "EBS-05",
            name: "EBS Default KMS Key Changed",
            severity: Severity::Medium,
            mitre_tactic: "Impact",
            mitre_technique: "T1486",
            service: "EBS",
            evaluate: rules::ebs::ebs_05_default_kms_changed,
        },
        // ── Lambda ───────────────────────────────────────────────────────
        DetectionRule {
            id: "LM-01",
            name: "Lambda Function Granted Public Access",
            severity: Severity::High,
            mitre_tactic: "Persistence",
            mitre_technique: "T1098",
            service: "Lambda",
            evaluate: rules::lambda::lm_01_lambda_public_access,
        },
        DetectionRule {
            id: "LM-02",
            name: "Lambda Environment Variables Updated",
            severity: Severity::Low,
            mitre_tactic: "Persistence",
            mitre_technique: "T1525",
            service: "Lambda",
            evaluate: rules::lambda::lm_02_lambda_env_updated,
        },
        // ── Resource Sharing ─────────────────────────────────────────────
        DetectionRule {
            id: "RS-01",
            name: "EC2 AMI Made Public",
            severity: Severity::High,
            mitre_tactic: "Exfiltration",
            mitre_technique: "T1537",
            service: "EC2",
            evaluate: rules::resource_sharing::rs_01_ami_made_public,
        },
        DetectionRule {
            id: "RS-02",
            name: "SSM Document Made Public",
            severity: Severity::High,
            mitre_tactic: "Exfiltration",
            mitre_technique: "T1537",
            service: "SSM",
            evaluate: rules::resource_sharing::rs_02_ssm_document_public,
        },
        DetectionRule {
            id: "RS-03",
            name: "RDS Snapshot Made Public",
            severity: Severity::High,
            mitre_tactic: "Exfiltration",
            mitre_technique: "T1537",
            service: "RDS",
            evaluate: rules::resource_sharing::rs_03_rds_snapshot_public,
        },
    ]
}

/// Run all registered detection rules against the store.
/// Returns alerts sorted by severity descending (Critical first).
/// Maximum number of matching record IDs sent over IPC per alert.
/// The true count is always stored in `alert.matching_count`.
const MAX_ALERT_IDS: usize = 100;

pub fn run_all_rules(store: &Store) -> Vec<Alert> {
    let mut alerts: Vec<Alert> = all_rules()
        .iter()
        .flat_map(|rule| (rule.evaluate)(store))
        .collect();

    cap_alert_ids(&mut alerts);
    alerts.sort_by(|a, b| b.severity.cmp(&a.severity));
    alerts
}

/// Cap matching_record_ids to MAX_ALERT_IDS, storing the true count in matching_count.
fn cap_alert_ids(alerts: &mut [Alert]) {
    for alert in alerts.iter_mut() {
        alert.matching_count = alert.matching_record_ids.len();
        alert.matching_record_ids.truncate(MAX_ALERT_IDS);
    }
}

/// Filter alerts to only include matching records within [start_ms, end_ms].
/// Alerts with no remaining matching records are dropped.
pub fn filter_alerts_by_time(store: &Store, mut alerts: Vec<Alert>, start_ms: i64, end_ms: i64) -> Vec<Alert> {
    for alert in &mut alerts {
        alert.matching_record_ids.retain(|&id| {
            store.get_record(id)
                .map(|r| r.timestamp >= start_ms && r.timestamp <= end_ms)
                .unwrap_or(false)
        });
        alert.matching_count = alert.matching_record_ids.len();
    }
    alerts.retain(|a| !a.matching_record_ids.is_empty());
    alerts
}

/// Run geo anomaly rules (requires a loaded GeoIpEngine).
/// Results are appended to the alert list from run_all_rules.
pub fn run_geo_rules(store: &Store, geoip: &GeoIpEngine) -> Vec<Alert> {
    let mut alerts = vec![
        rules::geo_anomaly::geo_01_multi_country(store, geoip),
        rules::geo_anomaly::geo_02_console_unusual_country(store, geoip),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();

    cap_alert_ids(&mut alerts);
    alerts.sort_by(|a, b| b.severity.cmp(&a.severity));
    alerts
}
