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
// Candidate scoping shared by every rule
// ---------------------------------------------------------------------------

/// Records that carry any `errorCode` (union of the whole error index).
fn errored_ids(store: &Store) -> RoaringBitmap {
    let mut all = RoaringBitmap::new();
    for ids in store.idx_error_code.values() {
        all |= ids;
    }
    all
}

/// Narrow `ids` to the given event sources (empty = any) and, when `exclude_errors`
/// is set, drop every record that carries an `errorCode`: a denied call is not a
/// completed action and must not fire "X happened" alerts.
pub fn restrict(
    store: &Store,
    mut ids: RoaringBitmap,
    sources: &[&str],
    exclude_errors: bool,
) -> RoaringBitmap {
    if !sources.is_empty() {
        let mut allowed = RoaringBitmap::new();
        for s in sources {
            if let Some(b) = store.idx_event_source.get(*s) {
                allowed |= b;
            }
        }
        ids &= allowed;
    }
    if exclude_errors && !ids.is_empty() {
        ids -= errored_ids(store);
    }
    ids
}

/// Candidate ids for a rule: the union of the named events, restricted to the given
/// event sources and (optionally) minus records that carry an errorCode.
/// Event names collide across services (`CreateUser` exists in Transfer, ElastiCache,
/// Identity Store...), so every rule names the service it is about.
pub fn scoped_ids(
    store: &Store,
    event_names: &[&str],
    sources: &[&str],
    exclude_errors: bool,
) -> RoaringBitmap {
    let mut ids = RoaringBitmap::new();
    for n in event_names {
        if let Some(b) = store.idx_event_name.get(*n) {
            ids |= b;
        }
    }
    restrict(store, ids, sources, exclude_errors)
}

/// A bitmap's ids as a Vec in (timestamp, id) order. Record ids follow ingestion arrival order,
/// which is arbitrary under parallel parsing; time order is what an analyst expects to read, and
/// it makes the 100-id IPC cap keep the earliest evidence rather than an arbitrary slice.
pub(crate) fn time_sorted(store: &Store, ids: &RoaringBitmap) -> Vec<u32> {
    let mut v: Vec<(i64, u32)> = ids
        .iter()
        .map(|id| (store.get_record(id).map(|r| r.timestamp).unwrap_or(0), id))
        .collect();
    v.sort_unstable();
    v.into_iter().map(|(_, id)| id).collect()
}

// ---------------------------------------------------------------------------
// JSON navigation for requestParameters
// ---------------------------------------------------------------------------
// Rules used to substring-match the raw JSON text, which misfires on remove/add
// confusion, unrelated words ("install" contains "all") and defaults that are always
// present. These helpers navigate the parsed value instead.

/// Object key lookup, exact first then ASCII case-insensitive. CloudTrail normalises most
/// services to lowerCamel keys but a few keep PascalCase.
pub(crate) fn jget<'a>(v: &'a serde_json::Value, key: &str) -> Option<&'a serde_json::Value> {
    let o = v.as_object()?;
    o.get(key)
        .or_else(|| o.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v))
}

/// True when `v` is a string equal to `needle` (ASCII case-insensitive), or an array
/// containing such a string.
pub(crate) fn json_has_str(v: &serde_json::Value, needle: &str) -> bool {
    match v {
        serde_json::Value::String(s) => s.eq_ignore_ascii_case(needle),
        serde_json::Value::Array(a) => a.iter().any(|x| json_has_str(x, needle)),
        _ => false,
    }
}

/// True when any object anywhere under `v` has `key` (case-insensitive) holding a string
/// equal to `needle` (case-insensitive). Used for shapes like `{"items":[{"group":"all"}]}`.
pub(crate) fn json_contains_pair(v: &serde_json::Value, key: &str, needle: &str) -> bool {
    match v {
        serde_json::Value::Object(o) => o.iter().any(|(k, val)| {
            (k.eq_ignore_ascii_case(key) && json_has_str(val, needle)) || json_contains_pair(val, key, needle)
        }),
        serde_json::Value::Array(a) => a.iter().any(|x| json_contains_pair(x, key, needle)),
        _ => false,
    }
}

/// True when an EC2 `Modify*Attribute` call **adds** the public group `all` to
/// `permission_key` (`launchPermission` for AMIs, `createVolumePermission` for snapshots).
/// `remove` never matches: removing the group makes the resource private.
pub(crate) fn adds_public_group(params: &serde_json::Value, permission_key: &str) -> bool {
    // Shape 1: {"<permission_key>":{"add":{"items":[{"group":"all"}]}}}
    if let Some(add) = jget(params, permission_key).and_then(|p| jget(p, "add")) {
        if json_contains_pair(add, "group", "all") {
            return true;
        }
    }
    // Shape 2: {"attributeType":"<permission_key>","operationType":"add","userGroups":{"items":[{"group":"all"}]}}
    let is_add = jget(params, "operationType").is_some_and(|v| json_has_str(v, "add"));
    let is_attr = jget(params, "attributeType").is_some_and(|v| json_has_str(v, permission_key));
    if is_add && is_attr {
        for k in ["userGroups", "userGroup", "groupNames", "groupName"] {
            if let Some(g) = jget(params, k) {
                if json_has_str(g, "all") || json_contains_pair(g, "group", "all") {
                    return true;
                }
            }
        }
    }
    false
}

/// The `Statement` entries of an IAM/S3 policy document (array or single object).
pub(crate) fn policy_statements(policy: &serde_json::Value) -> Vec<&serde_json::Value> {
    match jget(policy, "Statement") {
        Some(serde_json::Value::Array(a)) => a.iter().collect(),
        Some(obj @ serde_json::Value::Object(_)) => vec![obj],
        _ => vec![],
    }
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
        DetectionRule {
            id: "IM-04",
            name: "Mass EC2 Instance Stop",
            severity: Severity::High,
            mitre_tactic: "Impact",
            mitre_technique: "T1489",
            service: "EC2",
            evaluate: rules::impact::im_04_mass_instance_stop,
        },
        DetectionRule {
            id: "IM-05",
            name: "Mass EC2 Instance Termination",
            severity: Severity::Critical,
            mitre_tactic: "Impact",
            mitre_technique: "T1485",
            service: "EC2",
            evaluate: rules::impact::im_05_mass_instance_terminate,
        },
        DetectionRule {
            id: "IM-06",
            name: "Mass EC2 Instance Start",
            severity: Severity::Medium,
            mitre_tactic: "Impact",
            mitre_technique: "T1496",
            service: "EC2",
            evaluate: rules::impact::im_06_mass_instance_start,
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
        // ── EC2 ──────────────────────────────────────────────────────────
        DetectionRule {
            id: "EC-01",
            name: "EC2 Instance User Data Modified",
            severity: Severity::High,
            mitre_tactic: "Execution",
            mitre_technique: "T1059",
            service: "EC2",
            evaluate: rules::ec2::ec_01_userdata_modified,
        },
        DetectionRule {
            id: "EC-02",
            name: "EC2 Key Pair Created",
            severity: Severity::Medium,
            mitre_tactic: "Persistence",
            mitre_technique: "T1098.004",
            service: "EC2",
            evaluate: rules::ec2::ec_02_keypair_created,
        },
        DetectionRule {
            id: "EC-03",
            name: "Launch Template Created with User Data",
            severity: Severity::Medium,
            mitre_tactic: "Persistence",
            mitre_technique: "T1059",
            service: "EC2",
            evaluate: rules::ec2::ec_03_launch_template_userdata,
        },
        DetectionRule {
            id: "EC-04",
            name: "EC2 IMDSv2 Enforcement Disabled",
            severity: Severity::High,
            mitre_tactic: "Credential Access",
            mitre_technique: "T1552.005",
            service: "EC2",
            evaluate: rules::ec2::ec_04_imds_v2_downgraded,
        },
        DetectionRule {
            id: "EC-05",
            name: "EC2 Windows Instance Password Retrieved",
            severity: Severity::Medium,
            mitre_tactic: "Credential Access",
            mitre_technique: "T1078.004",
            service: "EC2",
            evaluate: rules::ec2::ec_05_get_password_data,
        },
        DetectionRule {
            id: "EC-06",
            name: "EC2 Instance Connect SSH Key Pushed",
            severity: Severity::High,
            mitre_tactic: "Lateral Movement",
            mitre_technique: "T1098.004",
            service: "EC2",
            evaluate: rules::ec2::ec_06_instance_connect,
        },
        DetectionRule {
            id: "EC-07",
            name: "SSM Run Command Sent",
            severity: Severity::High,
            mitre_tactic: "Execution",
            mitre_technique: "T1651",
            service: "SSM",
            evaluate: rules::ec2::ec_07_ssm_run_command,
        },
        DetectionRule {
            id: "EC-08",
            name: "EC2 Serial Console Access Enabled",
            severity: Severity::Medium,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1078",
            service: "EC2",
            evaluate: rules::ec2::ec_08_serial_console_enabled,
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

    alerts.sort_by(|a, b| b.severity.cmp(&a.severity));
    alerts
}

/// Cap matching_record_ids to MAX_ALERT_IDS, storing the true count in matching_count.
///
/// Runs **after** any time filtering (see `finalize_alerts`): capping first would make
/// the time filter operate on a 100-id sample and drop real alerts.
pub fn cap_alert_ids(alerts: &mut [Alert]) {
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

/// Final pass before alerts leave the core crate: optional time filter first, then the
/// IPC id cap, then a stable severity-descending order (rule id breaks ties).
/// Every caller that returns alerts to the UI goes through here.
pub fn finalize_alerts(store: &Store, alerts: Vec<Alert>, time_range: Option<(i64, i64)>) -> Vec<Alert> {
    let mut alerts = match time_range {
        Some((s, e)) => filter_alerts_by_time(store, alerts, s, e),
        None => alerts,
    };
    cap_alert_ids(&mut alerts);
    alerts.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.rule_id.cmp(&b.rule_id)));
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

    alerts.sort_by(|a, b| b.severity.cmp(&a.severity));
    alerts
}
