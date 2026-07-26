use std::collections::HashMap;
use roaring::RoaringBitmap;
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

/// What a rule decides: which records matched, why, and where to look.
///
/// Identity — id, title, severity, MITRE tactic/technique, service — is *not*
/// here. It lives in the [`DetectionRule`] registry entry that owns the rule and
/// is stamped on by [`run_all_rules`]. Rules used to restate all six as owned
/// `String`s in every alert literal, which meant a rule's severity could
/// silently disagree with the registry's and nothing would catch it.
pub struct Finding {
    pub description: String,
    pub matching_record_ids: Vec<u32>,
    pub metadata: HashMap<String, String>,
    /// Pre-built query string — paste into the search bar to see matching events.
    pub query: String,
}

impl Finding {
    pub fn new(
        description: impl Into<String>,
        matching_record_ids: Vec<u32>,
        query: impl Into<String>,
    ) -> Self {
        Finding {
            description: description.into(),
            matching_record_ids,
            metadata: HashMap::new(),
            query: query.into(),
        }
    }

    /// Attach one metadata entry, chainable.
    pub fn meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// How a rule is invoked. Geo rules need a loaded `GeoIpEngine`, which is
/// optional at runtime, so they are a distinct variant rather than a second
/// registry — one table stays the single source of rule identity.
pub enum Eval {
    /// "Alert if any record matches one of these values on an indexed field."
    ///
    /// 31 rules had this as their entire body — look up posting lists, union
    /// them, bail if empty, format a count into a sentence. Stating it as data
    /// removes that boilerplate and two classes of bug with it: a rule can no
    /// longer forget the empty check, and the query can no longer disagree with
    /// what the rule actually matched, because it is derived from the same
    /// `field`/`values`.
    ///
    /// `description` is a template; `{n}` is replaced with the match count.
    Match {
        /// Canonical field name, resolved through [`Store::index_for`].
        field: &'static str,
        values: &'static [&'static str],
        description: &'static str,
    },
    Store(fn(&Store) -> Option<Finding>),
    Geo(fn(&Store, &GeoIpEngine) -> Option<Finding>),
}

/// Evaluate an [`Eval::Match`] spec.
fn eval_match(
    store: &Store,
    field: &str,
    values: &[&str],
    description: &str,
) -> Option<Finding> {
    let idx = store.index_for(field)?;

    let mut ids = RoaringBitmap::new();
    for value in values {
        if let Some(posting) = idx.get(*value) {
            ids |= posting;
        }
    }
    if ids.is_empty() {
        return None;
    }

    let query = values
        .iter()
        .map(|v| format!("{field}={v}"))
        .collect::<Vec<_>>()
        .join(" OR ");

    Some(Finding::new(
        description.replace("{n}", &ids.len().to_string()),
        ids.iter().collect(),
        query,
    ))
}

pub struct DetectionRule {
    pub id: &'static str,
    /// Alert headline shown in the Detection tab.
    pub title: &'static str,
    pub severity: Severity,
    pub mitre_tactic: &'static str,
    pub mitre_technique: &'static str,
    pub service: &'static str,
    pub evaluate: Eval,
}

impl DetectionRule {
    /// Promote a rule's finding to a full alert by stamping this entry's identity.
    fn to_alert(&self, finding: Finding) -> Alert {
        Alert {
            rule_id: self.id.to_string(),
            severity: self.severity.clone(),
            title: self.title.to_string(),
            description: finding.description,
            matching_count: finding.matching_record_ids.len(),
            matching_record_ids: finding.matching_record_ids,
            metadata: finding.metadata,
            mitre_tactic: self.mitre_tactic.to_string(),
            mitre_technique: self.mitre_technique.to_string(),
            service: self.service.to_string(),
            query: finding.query,
        }
    }
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) fn all_rules() -> Vec<DetectionRule> {
    all_rules_inner()
}

#[cfg(not(test))]
fn all_rules() -> Vec<DetectionRule> {
    all_rules_inner()
}

fn all_rules_inner() -> Vec<DetectionRule> {
    vec![
        // ── Initial Access ───────────────────────────────────────────────
        DetectionRule {
            id: "IA-01",
            title: "Console Login Without MFA",
            severity: Severity::High,
            mitre_tactic: "Initial Access",
            mitre_technique: "T1078.004",
            service: "IAM",
            evaluate: Eval::Store(rules::initial_access::ia_01_console_login_no_mfa),
        },
        DetectionRule {
            id: "IA-03",
            title: "Root Account Usage Detected",
            severity: Severity::Critical,
            mitre_tactic: "Initial Access",
            mitre_technique: "T1078.004",
            service: "IAM",
            evaluate: Eval::Match {
                field: "identityType",
                values: &["Root"],
                description: "The root account performed {n} API call(s). Root usage is a high-risk indicator as \
                     root has unrestricted access to all AWS resources.",
            },
        },
        DetectionRule {
            id: "IA-04",
            title: "Brute Force Login Attempt Detected",
            severity: Severity::High,
            mitre_tactic: "Initial Access",
            mitre_technique: "T1110.001",
            service: "IAM",
            evaluate: Eval::Store(rules::initial_access::ia_04_brute_force),
        },
        // ── Persistence ──────────────────────────────────────────────────
        DetectionRule {
            id: "PE-01",
            title: "IAM User Created",
            severity: Severity::Medium,
            mitre_tactic: "Persistence",
            mitre_technique: "T1136.003",
            service: "IAM",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["CreateUser"],
                description: "{n} IAM user(s) were created. Review whether these accounts are expected and \
                     authorized.",
            },
        },
        DetectionRule {
            id: "PE-02",
            title: "Access Key Created for Another User",
            severity: Severity::High,
            mitre_tactic: "Persistence",
            mitre_technique: "T1098.001",
            service: "IAM",
            evaluate: Eval::Store(rules::persistence::pe_02_access_key_for_other),
        },
        DetectionRule {
            id: "PE-03",
            title: "Login Profile Created (Console Access Added)",
            severity: Severity::Medium,
            mitre_tactic: "Persistence",
            mitre_technique: "T1098",
            service: "IAM",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["CreateLoginProfile"],
                description: "{n} IAM user(s) had console access (login profiles) created. This grants \
                     password-based console access to previously API-only accounts.",
            },
        },
        DetectionRule {
            id: "PE-04",
            title: "Administrative Policy Attached",
            severity: Severity::Critical,
            mitre_tactic: "Persistence",
            mitre_technique: "T1098.003",
            service: "IAM",
            evaluate: Eval::Store(rules::persistence::pe_04_admin_policy_attached),
        },
        DetectionRule {
            id: "PE-05",
            title: "MFA Device Deactivated",
            severity: Severity::High,
            mitre_tactic: "Persistence",
            mitre_technique: "T1556.006",
            service: "IAM",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["DeactivateMFADevice", "DeleteVirtualMFADevice"],
                description: "{n} MFA device(s) were deactivated or deleted. Removing MFA weakens account security \
                     and may allow attackers to maintain persistent access via stolen credentials.",
            },
        },
        DetectionRule {
            id: "PE-06",
            title: "IAM Policy Version Created and Set as Default",
            severity: Severity::Medium,
            mitre_tactic: "Persistence",
            mitre_technique: "T1098.003",
            service: "IAM",
            evaluate: Eval::Store(rules::persistence_ext::pe_06_policy_version_created),
        },
        DetectionRule {
            id: "PE-07",
            title: "Cross-Account Role Assumption",
            severity: Severity::Medium,
            mitre_tactic: "Persistence",
            mitre_technique: "T1098.001",
            service: "STS",
            evaluate: Eval::Store(rules::persistence_ext::pe_07_cross_account_assume_role),
        },
        // ── Defense Evasion ──────────────────────────────────────────────
        DetectionRule {
            id: "DE-01",
            title: "CloudTrail Logging Tampered",
            severity: Severity::Critical,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.008",
            service: "CloudTrail",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["StopLogging", "DeleteTrail", "UpdateTrail"],
                description: "{n} event(s) stopped, deleted, or modified CloudTrail logging. Attackers disable \
                     logging to avoid detection of subsequent actions.",
            },
        },
        DetectionRule {
            id: "DE-02",
            title: "GuardDuty Disabled",
            severity: Severity::Critical,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.001",
            service: "GuardDuty",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["DeleteDetector", "StopMonitoringMembers", "DisassociateMembers"],
                description: "{n} event(s) disabled or disrupted GuardDuty threat detection. This removes active \
                     threat monitoring from the account.",
            },
        },
        DetectionRule {
            id: "DE-04",
            title: "AWS Config Recorder Stopped",
            severity: Severity::High,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.001",
            service: "Config",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["StopConfigurationRecorder", "DeleteConfigurationRecorder"],
                description: "{n} event(s) stopped or deleted the AWS Config configuration recorder. This disables \
                     resource configuration tracking.",
            },
        },
        DetectionRule {
            id: "DE-05",
            title: "VPC Flow Logs Deleted",
            severity: Severity::Critical,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.008",
            service: "VPC",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["DeleteFlowLogs"],
                description: "{n} VPC flow log(s) were deleted. Flow logs capture network traffic metadata; \
                     deleting them blinds network-level investigation.",
            },
        },
        DetectionRule {
            id: "DE-06",
            title: "CloudWatch Log Group Deleted",
            severity: Severity::High,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.008",
            service: "CloudWatch",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["DeleteLogGroup"],
                description: "{n} CloudWatch log group(s) were deleted. Removing log groups destroys audit \
                     evidence and may hide attacker activity.",
            },
        },
        DetectionRule {
            id: "DE-07",
            title: "CloudTrail S3 Logging Bucket Changed",
            severity: Severity::High,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.008",
            service: "CloudTrail",
            evaluate: Eval::Store(rules::defense_evasion::de_07_cloudtrail_s3_changed),
        },
        DetectionRule {
            id: "DE-08",
            title: "EventBridge Rule Disabled",
            severity: Severity::Medium,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.001",
            service: "EventBridge",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["DisableRule"],
                description: "{n} EventBridge rule(s) were disabled. Disabling event rules can suppress automated \
                     security responses and alerting.",
            },
        },
        DetectionRule {
            id: "DE-09",
            title: "WAF Web ACL Deleted",
            severity: Severity::High,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.001",
            service: "WAF",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["DeleteWebACL", "DeleteWebAclV2"],
                description: "{n} WAF Web ACL(s) were deleted. Removing WAF rules eliminates protection against \
                     web-based attacks.",
            },
        },
        DetectionRule {
            id: "DE-10",
            title: "CloudFront Distribution Logging Disabled",
            severity: Severity::Medium,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.008",
            service: "CloudFront",
            evaluate: Eval::Store(rules::defense_evasion::de_10_cloudfront_logging_disabled),
        },
        DetectionRule {
            id: "DE-11",
            title: "SQS Queue Encryption Removed",
            severity: Severity::Medium,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.001",
            service: "SQS",
            evaluate: Eval::Store(rules::defense_evasion::de_11_sqs_encryption_removed),
        },
        DetectionRule {
            id: "DE-12",
            title: "SNS Topic Encryption Removed",
            severity: Severity::Medium,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.001",
            service: "SNS",
            evaluate: Eval::Store(rules::defense_evasion::de_12_sns_encryption_removed),
        },
        DetectionRule {
            id: "DE-13",
            title: "Route53 Hosted Zone Deleted",
            severity: Severity::Medium,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1485",
            service: "Route53",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["DeleteHostedZone"],
                description: "{n} Route53 hosted zone(s) were deleted. This can cause DNS resolution failures and \
                     may be used to disrupt services.",
            },
        },
        // ── Credential Access ────────────────────────────────────────────
        DetectionRule {
            id: "CA-02",
            title: "Secrets Manager Bulk Access",
            severity: Severity::High,
            mitre_tactic: "Credential Access",
            mitre_technique: "T1555",
            service: "SecretsManager",
            evaluate: Eval::Store(rules::credential_access::ca_02_secrets_bulk),
        },
        DetectionRule {
            id: "CA-04",
            title: "Account Password Policy Modified",
            severity: Severity::Medium,
            mitre_tactic: "Credential Access",
            mitre_technique: "T1556",
            service: "IAM",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["UpdateAccountPasswordPolicy"],
                description: "{n} modification(s) to the account password policy were detected. Weakening password \
                     policies enables credential-based attacks.",
            },
        },
        DetectionRule {
            id: "CA-05",
            title: "Root Account Console Login",
            severity: Severity::Critical,
            mitre_tactic: "Credential Access",
            mitre_technique: "T1078.004",
            service: "IAM",
            evaluate: Eval::Store(rules::credential_access::ca_05_root_console_login),
        },
        DetectionRule {
            id: "CA-06",
            title: "KMS Key Scheduled for Deletion",
            severity: Severity::High,
            mitre_tactic: "Credential Access",
            mitre_technique: "T1485",
            service: "KMS",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["ScheduleKeyDeletion"],
                description: "{n} KMS key(s) scheduled for deletion. Deleting encryption keys can render encrypted \
                     data permanently inaccessible, causing data loss.",
            },
        },
        // ── Discovery ────────────────────────────────────────────────────
        DetectionRule {
            id: "DI-02",
            title: "IAM Enumeration Detected",
            severity: Severity::Medium,
            mitre_tactic: "Discovery",
            mitre_technique: "T1087.004",
            service: "IAM",
            evaluate: Eval::Match {
                field: "eventName",
                values: &[
                    "ListUsers",
                    "ListRoles",
                    "ListPolicies",
                    "ListGroups",
                    "GetAccountAuthorizationDetails",
                    "ListAttachedUserPolicies",
                    "ListAttachedRolePolicies",
                ],
                description: "{n} IAM enumeration event(s) detected (ListUsers, ListRoles, ListPolicies, etc.). \
                     Reconnaissance of IAM resources is a common precursor to privilege escalation.",
            },
        },
        DetectionRule {
            id: "DI-03",
            title: "AccessDenied Spike — Possible Permission Probing",
            severity: Severity::Medium,
            mitre_tactic: "Discovery",
            mitre_technique: "T1580",
            service: "IAM",
            evaluate: Eval::Store(rules::discovery::di_03_access_denied_spike),
        },
        // ── Exfiltration ─────────────────────────────────────────────────
        DetectionRule {
            id: "EX-01",
            title: "S3 Bucket Policy/ACL Modified (Potential Public Exposure)",
            severity: Severity::High,
            mitre_tactic: "Exfiltration",
            mitre_technique: "T1537",
            service: "S3",
            evaluate: Eval::Store(rules::exfiltration::ex_01_s3_bucket_public),
        },
        DetectionRule {
            id: "EX-02",
            title: "S3 Bucket Deleted",
            severity: Severity::Medium,
            mitre_tactic: "Exfiltration",
            mitre_technique: "T1485",
            service: "S3",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["DeleteBucket"],
                description: "{n} S3 bucket(s) were deleted. Bucket deletion can indicate data destruction or \
                     cleanup of evidence after exfiltration.",
            },
        },
        DetectionRule {
            id: "EX-03",
            title: "S3 Bulk Object Download",
            severity: Severity::Medium,
            mitre_tactic: "Exfiltration",
            mitre_technique: "T1530",
            service: "S3",
            evaluate: Eval::Store(rules::exfiltration::ex_03_s3_bulk_download),
        },
        DetectionRule {
            id: "EX-04",
            title: "S3 Bucket Access Logging Disabled",
            severity: Severity::Medium,
            mitre_tactic: "Exfiltration",
            mitre_technique: "T1562.008",
            service: "S3",
            evaluate: Eval::Store(rules::exfiltration::ex_04_s3_logging_disabled),
        },
        DetectionRule {
            id: "EX-05",
            title: "S3 Bucket Encryption Removed",
            severity: Severity::High,
            mitre_tactic: "Exfiltration",
            mitre_technique: "T1537",
            service: "S3",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["DeleteBucketEncryption"],
                description: "{n} S3 bucket(s) had server-side encryption removed. Unencrypted buckets expose data \
                     at rest.",
            },
        },
        // ── Impact ───────────────────────────────────────────────────────
        DetectionRule {
            id: "IM-01",
            title: "EC2 Instances Launched in Bulk",
            severity: Severity::High,
            mitre_tactic: "Impact",
            mitre_technique: "T1496",
            service: "EC2",
            evaluate: Eval::Store(rules::impact::im_01_ec2_bulk_launch),
        },
        DetectionRule {
            id: "IM-02",
            title: "Resource Deletion Spree",
            severity: Severity::Critical,
            mitre_tactic: "Impact",
            mitre_technique: "T1485",
            service: "Multi",
            evaluate: Eval::Store(rules::impact::im_02_resource_deletion_spree),
        },
        DetectionRule {
            id: "IM-03",
            title: "SES Email Identity Verified",
            severity: Severity::Low,
            mitre_tactic: "Impact",
            mitre_technique: "T1534",
            service: "SES",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["VerifyEmailIdentity", "CreateEmailIdentity", "VerifyDomainIdentity"],
                description: "{n} SES email/domain identit(ies) verified. Attackers may verify email identities to \
                     send phishing emails using the compromised account.",
            },
        },
        DetectionRule {
            id: "IM-04",
            title: "Mass EC2 Instance Stop",
            severity: Severity::High,
            mitre_tactic: "Impact",
            mitre_technique: "T1489",
            service: "EC2",
            evaluate: Eval::Store(rules::impact::im_04_mass_instance_stop),
        },
        DetectionRule {
            id: "IM-05",
            title: "Mass EC2 Instance Termination",
            severity: Severity::Critical,
            mitre_tactic: "Impact",
            mitre_technique: "T1485",
            service: "EC2",
            evaluate: Eval::Store(rules::impact::im_05_mass_instance_terminate),
        },
        DetectionRule {
            id: "IM-06",
            title: "Mass EC2 Instance Start",
            severity: Severity::Medium,
            mitre_tactic: "Impact",
            mitre_technique: "T1496",
            service: "EC2",
            evaluate: Eval::Store(rules::impact::im_06_mass_instance_start),
        },
        // ── Network ──────────────────────────────────────────────────────
        DetectionRule {
            id: "NW-01",
            title: "Security Group Opened to All Traffic (0.0.0.0/0)",
            severity: Severity::High,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.007",
            service: "VPC",
            evaluate: Eval::Store(rules::network::nw_01_sg_ingress_all),
        },
        DetectionRule {
            id: "NW-02",
            title: "Network ACL Allows All Traffic",
            severity: Severity::Medium,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.007",
            service: "VPC",
            evaluate: Eval::Store(rules::network::nw_02_nacl_allows_all),
        },
        DetectionRule {
            id: "NW-03",
            title: "Internet Gateway Created or Attached",
            severity: Severity::Info,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.007",
            service: "VPC",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["CreateInternetGateway", "AttachInternetGateway"],
                description: "{n} internet gateway event(s) detected. New internet gateways may indicate \
                     unauthorized VPC exposure to the internet.",
            },
        },
        DetectionRule {
            id: "NW-04",
            title: "Default Route Added to Route Table",
            severity: Severity::Medium,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.007",
            service: "VPC",
            evaluate: Eval::Store(rules::network::nw_04_route_to_internet),
        },
        DetectionRule {
            id: "NW-05",
            title: "VPC Peering Connection Created",
            severity: Severity::Info,
            mitre_tactic: "Lateral Movement",
            mitre_technique: "T1021",
            service: "VPC",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["CreateVpcPeeringConnection"],
                description: "{n} VPC peering connection(s) created. VPC peering can extend network access between \
                     previously isolated environments.",
            },
        },
        DetectionRule {
            id: "NW-06",
            title: "Security Group Deleted",
            severity: Severity::Low,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.007",
            service: "VPC",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["DeleteSecurityGroup"],
                description: "{n} security group(s) deleted. Security group deletion can expose instances that \
                     relied on those rules for protection.",
            },
        },
        DetectionRule {
            id: "NW-07",
            title: "Subnet Auto-Assign Public IP Enabled",
            severity: Severity::Medium,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.007",
            service: "VPC",
            evaluate: Eval::Store(rules::network::nw_07_subnet_public),
        },
        DetectionRule {
            id: "NW-08",
            title: "NAT Gateway Deleted",
            severity: Severity::Low,
            mitre_tactic: "Impact",
            mitre_technique: "T1485",
            service: "VPC",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["DeleteNatGateway"],
                description: "{n} NAT gateway(s) deleted. Removing NAT gateways can disrupt outbound internet \
                     access for private subnets.",
            },
        },
        // ── RDS ──────────────────────────────────────────────────────────
        DetectionRule {
            id: "RDS-01",
            title: "RDS Deletion Protection Disabled",
            severity: Severity::High,
            mitre_tactic: "Impact",
            mitre_technique: "T1485",
            service: "RDS",
            evaluate: Eval::Store(rules::rds::rds_01_deletion_protection_disabled),
        },
        DetectionRule {
            id: "RDS-02",
            title: "RDS Instance Restored with Public Access",
            severity: Severity::High,
            mitre_tactic: "Exfiltration",
            mitre_technique: "T1537",
            service: "RDS",
            evaluate: Eval::Store(rules::rds::rds_02_public_snapshot_restore),
        },
        DetectionRule {
            id: "RDS-03",
            title: "RDS Master Password Changed",
            severity: Severity::Medium,
            mitre_tactic: "Credential Access",
            mitre_technique: "T1098",
            service: "RDS",
            evaluate: Eval::Store(rules::rds::rds_03_master_password_changed),
        },
        // ── EBS ──────────────────────────────────────────────────────────
        DetectionRule {
            id: "EBS-01",
            title: "EBS Default Encryption Disabled",
            severity: Severity::High,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1486",
            service: "EBS",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["DisableEbsEncryptionByDefault"],
                description: "{n} event(s) disabled EBS default encryption. New EBS volumes in this region will be \
                     created unencrypted, exposing data at rest.",
            },
        },
        DetectionRule {
            id: "EBS-02",
            title: "EBS Snapshot Made Public",
            severity: Severity::Critical,
            mitre_tactic: "Exfiltration",
            mitre_technique: "T1537",
            service: "EBS",
            evaluate: Eval::Store(rules::ebs::ebs_02_snapshot_public),
        },
        DetectionRule {
            id: "EBS-03",
            title: "EBS Volume Detached",
            severity: Severity::Low,
            mitre_tactic: "Exfiltration",
            mitre_technique: "T1537",
            service: "EBS",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["DetachVolume"],
                description: "{n} EBS volume(s) were detached from EC2 instances. Unexpected detachments may \
                     indicate data staging prior to exfiltration.",
            },
        },
        DetectionRule {
            id: "EBS-04",
            title: "EBS Snapshot Deleted",
            severity: Severity::Medium,
            mitre_tactic: "Impact",
            mitre_technique: "T1485",
            service: "EBS",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["DeleteSnapshot"],
                description: "{n} EBS snapshot(s) were deleted. Snapshot deletion destroys backup copies and may \
                     be used to eliminate forensic evidence.",
            },
        },
        DetectionRule {
            id: "EBS-05",
            title: "EBS Default KMS Encryption Key Changed",
            severity: Severity::Medium,
            mitre_tactic: "Impact",
            mitre_technique: "T1486",
            service: "EBS",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["ModifyEbsDefaultKmsKeyId"],
                description: "{n} event(s) changed the default KMS key used for EBS volume encryption. Changing to \
                     an attacker-controlled key can prevent data recovery.",
            },
        },
        // ── EC2 ──────────────────────────────────────────────────────────
        DetectionRule {
            id: "EC-01",
            title: "EC2 Instance User Data Modified",
            severity: Severity::High,
            mitre_tactic: "Execution",
            mitre_technique: "T1059",
            service: "EC2",
            evaluate: Eval::Store(rules::ec2::ec_01_userdata_modified),
        },
        DetectionRule {
            id: "EC-02",
            title: "EC2 Key Pair Created",
            severity: Severity::Medium,
            mitre_tactic: "Persistence",
            mitre_technique: "T1098.004",
            service: "EC2",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["CreateKeyPair"],
                description: "{n} EC2 key pair(s) created. New key pairs establish persistent SSH access to any \
                     instance configured to accept them.",
            },
        },
        DetectionRule {
            id: "EC-03",
            title: "Launch Template Created with User Data",
            severity: Severity::Medium,
            mitre_tactic: "Persistence",
            mitre_technique: "T1059",
            service: "EC2",
            evaluate: Eval::Store(rules::ec2::ec_03_launch_template_userdata),
        },
        DetectionRule {
            id: "EC-04",
            title: "EC2 IMDSv2 Enforcement Disabled",
            severity: Severity::High,
            mitre_tactic: "Credential Access",
            mitre_technique: "T1552.005",
            service: "EC2",
            evaluate: Eval::Store(rules::ec2::ec_04_imds_v2_downgraded),
        },
        DetectionRule {
            id: "EC-05",
            title: "EC2 Windows Instance Password Retrieved",
            severity: Severity::Medium,
            mitre_tactic: "Credential Access",
            mitre_technique: "T1078.004",
            service: "EC2",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["GetPasswordData"],
                description: "{n} GetPasswordData call(s) retrieved the encrypted Windows administrator password. \
                     An attacker with the instance key pair can decrypt this for full RDP access.",
            },
        },
        DetectionRule {
            id: "EC-06",
            title: "EC2 Instance Connect SSH Key Pushed",
            severity: Severity::High,
            mitre_tactic: "Lateral Movement",
            mitre_technique: "T1098.004",
            service: "EC2",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["SendSSHPublicKey", "SendSerialConsoleSSHPublicKey"],
                description: "{n} ephemeral SSH public key(s) pushed to EC2 instances via Instance Connect. \
                     Attackers use this to gain shell access without leaving persistent key pairs, making \
                     it harder to detect in post-incident review.",
            },
        },
        DetectionRule {
            id: "EC-07",
            title: "SSM Run Command Sent",
            severity: Severity::High,
            mitre_tactic: "Execution",
            mitre_technique: "T1651",
            service: "SSM",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["SendCommand"],
                description: "{n} SSM SendCommand event(s) detected. SSM Run Command provides remote code \
                     execution on managed EC2 instances without requiring SSH or open ports, and is \
                     commonly abused for post-compromise execution.",
            },
        },
        DetectionRule {
            id: "EC-08",
            title: "EC2 Serial Console Access Enabled",
            severity: Severity::Medium,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1078",
            service: "EC2",
            evaluate: Eval::Match {
                field: "eventName",
                values: &["EnableSerialConsoleAccess"],
                description: "{n} event(s) enabled EC2 serial console access for the account. Serial console \
                     bypasses all SSH key and network security controls, providing direct low-level \
                     access to instance terminals.",
            },
        },
        // ── Lambda ───────────────────────────────────────────────────────
        DetectionRule {
            id: "LM-01",
            title: "Lambda Function Granted Public Access",
            severity: Severity::High,
            mitre_tactic: "Persistence",
            mitre_technique: "T1098",
            service: "Lambda",
            evaluate: Eval::Store(rules::lambda::lm_01_lambda_public_access),
        },
        DetectionRule {
            id: "LM-02",
            title: "Lambda Environment Variables Updated",
            severity: Severity::Low,
            mitre_tactic: "Persistence",
            mitre_technique: "T1525",
            service: "Lambda",
            evaluate: Eval::Store(rules::lambda::lm_02_lambda_env_updated),
        },
        // ── Resource Sharing ─────────────────────────────────────────────
        DetectionRule {
            id: "RS-01",
            title: "EC2 AMI Made Public",
            severity: Severity::High,
            mitre_tactic: "Exfiltration",
            mitre_technique: "T1537",
            service: "EC2",
            evaluate: Eval::Store(rules::resource_sharing::rs_01_ami_made_public),
        },
        DetectionRule {
            id: "RS-02",
            title: "SSM Document Made Public",
            severity: Severity::High,
            mitre_tactic: "Exfiltration",
            mitre_technique: "T1537",
            service: "SSM",
            evaluate: Eval::Store(rules::resource_sharing::rs_02_ssm_document_public),
        },
        DetectionRule {
            id: "RS-03",
            title: "RDS Snapshot Made Public",
            severity: Severity::High,
            mitre_tactic: "Exfiltration",
            mitre_technique: "T1537",
            service: "RDS",
            evaluate: Eval::Store(rules::resource_sharing::rs_03_rds_snapshot_public),
        },
        // ── Geo anomaly (skipped unless a GeoIP database is loaded) ──────
        DetectionRule {
            id: "GEO-01",
            title: "Identity Active from Multiple Countries",
            severity: Severity::Medium,
            mitre_tactic: "Initial Access",
            mitre_technique: "T1078",
            service: "IAM",
            evaluate: Eval::Geo(rules::geo_anomaly::geo_01_multi_country),
        },
        DetectionRule {
            id: "GEO-02",
            title: "Console Login from Unusual Country",
            severity: Severity::High,
            mitre_tactic: "Initial Access",
            mitre_technique: "T1078.004",
            service: "IAM",
            evaluate: Eval::Geo(rules::geo_anomaly::geo_02_console_unusual_country),
        },
    ]
}

/// Maximum number of matching record IDs sent over IPC per alert.
/// The true count is always stored in `alert.matching_count`.
const MAX_ALERT_IDS: usize = 100;

/// Run all registered detection rules against the store.
/// Returns alerts sorted by severity descending (Critical first).
///
/// Record ID lists are **not** capped — in-process consumers (session
/// correlation, time filtering) need the full set to be correct. Call
/// [`cap_alert_ids`] last, at the IPC boundary.
pub fn run_all_rules(store: &Store) -> Vec<Alert> {
    use rayon::prelude::*;

    // Rules are pure `fn(&Store)` with no shared state, and roughly half of them
    // read request-parameter blobs. Those reads are a lock-free slice into the
    // sealed mmap, so they scale across threads rather than serialising.
    //
    // `par_iter().collect()` preserves registry order, and the severity sort
    // below is stable, so the alert order stays deterministic.
    //
    // Measured on the 100K-record benchmark: ~1.37s vs ~1.42s best-case, ~1.45s
    // vs ~1.67s median. Modest, not linear — the runtime is concentrated in a
    // couple of heavy rules (IM-02 groups every Delete*/Terminate* event), so
    // spreading 70 mostly-trivial rules across cores cannot do much. Speeding up
    // those individual rules is where the remaining time is.
    let mut alerts: Vec<Alert> = all_rules()
        .par_iter()
        .filter_map(|rule| match rule.evaluate {
            // Geo rules are run separately by `run_geo_rules`, which has the engine.
            Eval::Geo(_) => None,
            Eval::Store(f) => f(store).map(|finding| rule.to_alert(finding)),
            Eval::Match { field, values, description } => {
                eval_match(store, field, values, description).map(|f| rule.to_alert(f))
            }
        })
        .collect();

    alerts.sort_by(|a, b| b.severity.cmp(&a.severity));
    alerts
}

/// Truncate `matching_record_ids` to `MAX_ALERT_IDS` for transport.
///
/// `matching_count` is left alone — it already holds the true count — so the
/// frontend can still render "100 of 4,812 shown". Call this **last**, after
/// any time filtering: capping first would drop an alert whose visible 100 ids
/// all fall outside the requested window.
pub fn cap_alert_ids(alerts: &mut [Alert]) {
    for alert in alerts.iter_mut() {
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
/// Uncapped, for the same reason as [`run_all_rules`].
pub fn run_geo_rules(store: &Store, geoip: &GeoIpEngine) -> Vec<Alert> {
    let mut alerts: Vec<Alert> = all_rules()
        .iter()
        .filter_map(|rule| match rule.evaluate {
            Eval::Store(_) | Eval::Match { .. } => None,
            Eval::Geo(f) => f(store, geoip).map(|finding| rule.to_alert(finding)),
        })
        .collect();

    alerts.sort_by(|a, b| b.severity.cmp(&a.severity));
    alerts
}
