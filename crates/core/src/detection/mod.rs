// Phase 4: Detection engine
use std::collections::HashMap;
use crate::store::Store;

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
    pub matching_record_ids: Vec<u64>,
    pub metadata: HashMap<String, String>,
    pub mitre_tactic: String,
    pub mitre_technique: String,
    /// Pre-built query string — paste into the search bar to see matching events.
    pub query: String,
}

pub struct DetectionRule {
    pub id: &'static str,
    pub name: &'static str,
    pub severity: Severity,
    pub mitre_tactic: &'static str,
    pub mitre_technique: &'static str,
    pub evaluate: fn(&Store) -> Vec<Alert>,
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

fn all_rules() -> Vec<DetectionRule> {
    vec![
        // Initial Access
        DetectionRule {
            id: "IA-01",
            name: "Console Login Without MFA",
            severity: Severity::High,
            mitre_tactic: "Initial Access",
            mitre_technique: "T1078.004",
            evaluate: rules::initial_access::ia_01_console_login_no_mfa,
        },
        DetectionRule {
            id: "IA-03",
            name: "Root Account Usage",
            severity: Severity::Critical,
            mitre_tactic: "Initial Access",
            mitre_technique: "T1078.004",
            evaluate: rules::initial_access::ia_03_root_usage,
        },
        DetectionRule {
            id: "IA-04",
            name: "Failed Login Brute Force",
            severity: Severity::High,
            mitre_tactic: "Initial Access",
            mitre_technique: "T1110.001",
            evaluate: rules::initial_access::ia_04_brute_force,
        },
        // Persistence
        DetectionRule {
            id: "PE-01",
            name: "IAM User Created",
            severity: Severity::Medium,
            mitre_tactic: "Persistence",
            mitre_technique: "T1136.003",
            evaluate: rules::persistence::pe_01_iam_user_created,
        },
        DetectionRule {
            id: "PE-02",
            name: "Access Key Created for Another User",
            severity: Severity::High,
            mitre_tactic: "Persistence",
            mitre_technique: "T1098.001",
            evaluate: rules::persistence::pe_02_access_key_for_other,
        },
        DetectionRule {
            id: "PE-03",
            name: "Login Profile Created",
            severity: Severity::Medium,
            mitre_tactic: "Persistence",
            mitre_technique: "T1098",
            evaluate: rules::persistence::pe_03_login_profile_created,
        },
        DetectionRule {
            id: "PE-04",
            name: "Backdoor Admin Policy Attached",
            severity: Severity::Critical,
            mitre_tactic: "Persistence",
            mitre_technique: "T1098.003",
            evaluate: rules::persistence::pe_04_admin_policy_attached,
        },
        // Defense Evasion
        DetectionRule {
            id: "DE-01",
            name: "CloudTrail Stopped or Deleted",
            severity: Severity::Critical,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.008",
            evaluate: rules::defense_evasion::de_01_cloudtrail_stopped,
        },
        DetectionRule {
            id: "DE-02",
            name: "GuardDuty Disabled",
            severity: Severity::Critical,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.001",
            evaluate: rules::defense_evasion::de_02_guardduty_disabled,
        },
        DetectionRule {
            id: "DE-04",
            name: "Config Recorder Stopped",
            severity: Severity::High,
            mitre_tactic: "Defense Evasion",
            mitre_technique: "T1562.001",
            evaluate: rules::defense_evasion::de_04_config_recorder_stopped,
        },
        // Credential Access
        DetectionRule {
            id: "CA-02",
            name: "Secrets Manager Bulk Access",
            severity: Severity::High,
            mitre_tactic: "Credential Access",
            mitre_technique: "T1555",
            evaluate: rules::credential_access::ca_02_secrets_bulk,
        },
        DetectionRule {
            id: "CA-04",
            name: "Password Policy Weakened",
            severity: Severity::Medium,
            mitre_tactic: "Credential Access",
            mitre_technique: "T1556",
            evaluate: rules::credential_access::ca_04_password_policy_weakened,
        },
        // Discovery
        DetectionRule {
            id: "DI-02",
            name: "IAM Enumeration",
            severity: Severity::Medium,
            mitre_tactic: "Discovery",
            mitre_technique: "T1087.004",
            evaluate: rules::discovery::di_02_iam_enumeration,
        },
        DetectionRule {
            id: "DI-03",
            name: "AccessDenied Spike",
            severity: Severity::Medium,
            mitre_tactic: "Discovery",
            mitre_technique: "T1580",
            evaluate: rules::discovery::di_03_access_denied_spike,
        },
        // Exfiltration
        DetectionRule {
            id: "EX-01",
            name: "S3 Bucket Made Public",
            severity: Severity::High,
            mitre_tactic: "Exfiltration",
            mitre_technique: "T1537",
            evaluate: rules::exfiltration::ex_01_s3_bucket_public,
        },
        // Impact
        DetectionRule {
            id: "IM-01",
            name: "EC2 Instances Launched in Bulk",
            severity: Severity::High,
            mitre_tactic: "Impact",
            mitre_technique: "T1496",
            evaluate: rules::impact::im_01_ec2_bulk_launch,
        },
        DetectionRule {
            id: "IM-02",
            name: "Resource Deletion Spree",
            severity: Severity::Critical,
            mitre_tactic: "Impact",
            mitre_technique: "T1485",
            evaluate: rules::impact::im_02_resource_deletion_spree,
        },
    ]
}

/// Run all registered detection rules against the store.
/// Returns alerts sorted by severity descending (Critical first).
pub fn run_all_rules(store: &Store) -> Vec<Alert> {
    let mut alerts: Vec<Alert> = all_rules()
        .iter()
        .flat_map(|rule| (rule.evaluate)(store))
        .collect();

    // Sort: Critical > High > Medium > Low > Info (reverse of enum ord)
    alerts.sort_by(|a, b| b.severity.cmp(&a.severity));
    alerts
}

// ---------------------------------------------------------------------------
// Rule implementations
// ---------------------------------------------------------------------------

pub mod rules {
    pub mod initial_access {
        use std::collections::HashMap;
        use crate::store::Store;
        use crate::detection::{Alert, Severity};

        /// IA-01: Console Login Without MFA
        pub fn ia_01_console_login_no_mfa(store: &Store) -> Vec<Alert> {
            let ids = match store.idx_event_name.get("ConsoleLogin") {
                Some(ids) => ids,
                None => return vec![],
            };

            let mut matching = vec![];
            for &id in ids {
                if let Some(r) = store.get_record(id) {
                    // Check success
                    let is_success = r.record.response_elements
                        .as_ref()
                        .and_then(|v| v.get("ConsoleLogin"))
                        .and_then(|v| v.as_str())
                        .map(|s| s == "Success")
                        .unwrap_or(false);

                    if !is_success {
                        continue;
                    }

                    // Check MFA not used
                    let mfa_used = r.record.additional_event_data
                        .as_ref()
                        .and_then(|v| v.get("MFAUsed"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("No");

                    if mfa_used != "Yes" {
                        matching.push(id);
                    }
                }
            }

            if matching.is_empty() {
                return vec![];
            }

            vec![Alert {
                rule_id: "IA-01".to_string(),
                severity: Severity::High,
                title: "Console Login Without MFA".to_string(),
                description: format!(
                    "{} successful console login(s) occurred without MFA. \
                     Accounts without MFA are vulnerable to credential theft.",
                    matching.len()
                ),
                matching_record_ids: matching,
                metadata: HashMap::new(),
                mitre_tactic: "Initial Access".to_string(),
                mitre_technique: "T1078.004".to_string(),
                query: "eventName=ConsoleLogin".to_string(),
            }]
        }

        /// IA-03: Root Account Usage
        pub fn ia_03_root_usage(store: &Store) -> Vec<Alert> {
            let ids = match store.idx_identity_type.get("Root") {
                Some(ids) => ids.clone(),
                None => return vec![],
            };

            if ids.is_empty() {
                return vec![];
            }

            let mut meta = HashMap::new();
            meta.insert("count".to_string(), ids.len().to_string());

            vec![Alert {
                rule_id: "IA-03".to_string(),
                severity: Severity::Critical,
                title: "Root Account Usage Detected".to_string(),
                description: format!(
                    "The root account performed {} API call(s). Root usage is a high-risk indicator \
                     as root has unrestricted access to all AWS resources.",
                    ids.len()
                ),
                matching_record_ids: ids,
                metadata: meta,
                mitre_tactic: "Initial Access".to_string(),
                mitre_technique: "T1078.004".to_string(),
                query: "identityType=Root".to_string(),
            }]
        }

        /// IA-04: Failed Login Brute Force (≥5 failures within 10 min from same IP)
        pub fn ia_04_brute_force(store: &Store) -> Vec<Alert> {
            let ids = match store.idx_event_name.get("ConsoleLogin") {
                Some(ids) => ids,
                None => return vec![],
            };

            // Collect failure events grouped by source IP
            let mut by_ip: HashMap<String, Vec<(i64, u64)>> = HashMap::new();
            for &id in ids {
                if let Some(r) = store.get_record(id) {
                    let is_failure = r.record.response_elements
                        .as_ref()
                        .and_then(|v| v.get("ConsoleLogin"))
                        .and_then(|v| v.as_str())
                        .map(|s| s == "Failure")
                        .unwrap_or(false);

                    if is_failure {
                        if let Some(ip) = &r.record.source_ip_address {
                            by_ip.entry(ip.clone()).or_default().push((r.timestamp, id));
                        }
                    }
                }
            }

            let window_ms = 10 * 60 * 1000; // 10 minutes
            let threshold = 5;
            let mut all_matching: Vec<u64> = vec![];
            let mut meta = HashMap::new();
            let mut offending_ips: Vec<String> = vec![];

            for (ip, mut events) in by_ip {
                events.sort_unstable_by_key(|(ts, _)| *ts);
                // Sliding window
                let mut start = 0;
                for end in 0..events.len() {
                    while events[end].0 - events[start].0 > window_ms {
                        start += 1;
                    }
                    let window_count = end - start + 1;
                    if window_count >= threshold {
                        // Collect all IDs in this window
                        let window_ids: Vec<u64> = events[start..=end]
                            .iter()
                            .map(|(_, id)| *id)
                            .collect();
                        for wid in &window_ids {
                            if !all_matching.contains(wid) {
                                all_matching.push(*wid);
                            }
                        }
                        if !offending_ips.contains(&ip) {
                            offending_ips.push(ip.clone());
                        }
                        break;
                    }
                }
            }

            if all_matching.is_empty() {
                return vec![];
            }

            meta.insert("offending_ips".to_string(), offending_ips.join(", "));
            meta.insert("threshold".to_string(), threshold.to_string());

            // Build query: filter by IP if single offender, otherwise just eventName
            let query = if offending_ips.len() == 1 {
                format!("eventName=ConsoleLogin sourceIPAddress={}", offending_ips[0])
            } else {
                "eventName=ConsoleLogin".to_string()
            };

            vec![Alert {
                rule_id: "IA-04".to_string(),
                severity: Severity::High,
                title: "Brute Force Login Attempt Detected".to_string(),
                description: format!(
                    "≥{} failed console logins within 10 minutes from the same source IP. \
                     Offending IPs: {}",
                    threshold,
                    offending_ips.join(", ")
                ),
                matching_record_ids: all_matching,
                metadata: meta,
                mitre_tactic: "Initial Access".to_string(),
                mitre_technique: "T1110.001".to_string(),
                query,
            }]
        }
    }

    pub mod persistence {
        use std::collections::HashMap;
        use crate::store::Store;
        use crate::detection::{Alert, Severity};

        /// PE-01: IAM User Created
        pub fn pe_01_iam_user_created(store: &Store) -> Vec<Alert> {
            let ids = match store.idx_event_name.get("CreateUser") {
                Some(ids) => ids.clone(),
                None => return vec![],
            };

            if ids.is_empty() {
                return vec![];
            }

            let mut meta = HashMap::new();
            meta.insert("count".to_string(), ids.len().to_string());

            vec![Alert {
                rule_id: "PE-01".to_string(),
                severity: Severity::Medium,
                title: "IAM User Created".to_string(),
                description: format!(
                    "{} IAM user(s) were created. Review whether these accounts are expected \
                     and authorized.",
                    ids.len()
                ),
                matching_record_ids: ids,
                metadata: meta,
                mitre_tactic: "Persistence".to_string(),
                mitre_technique: "T1136.003".to_string(),
                query: "eventName=CreateUser".to_string(),
            }]
        }

        /// PE-02: Access Key Created for Another User
        pub fn pe_02_access_key_for_other(store: &Store) -> Vec<Alert> {
            let ids = match store.idx_event_name.get("CreateAccessKey") {
                Some(ids) => ids,
                None => return vec![],
            };

            let mut matching = vec![];
            for &id in ids {
                if let Some(r) = store.get_record(id) {
                    let caller = r.record.user_identity.user_name.as_deref().unwrap_or("");
                    let target = r.record.request_parameters
                        .as_ref()
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
                return vec![];
            }

            vec![Alert {
                rule_id: "PE-02".to_string(),
                severity: Severity::High,
                title: "Access Key Created for Another User".to_string(),
                description: format!(
                    "{} access key(s) were created where the creator differs from the target user. \
                     This pattern is used to establish covert persistence.",
                    matching.len()
                ),
                matching_record_ids: matching,
                metadata: HashMap::new(),
                mitre_tactic: "Persistence".to_string(),
                mitre_technique: "T1098.001".to_string(),
                query: "eventName=CreateAccessKey".to_string(),
            }]
        }

        /// PE-03: Login Profile Created
        pub fn pe_03_login_profile_created(store: &Store) -> Vec<Alert> {
            let ids = match store.idx_event_name.get("CreateLoginProfile") {
                Some(ids) => ids.clone(),
                None => return vec![],
            };

            if ids.is_empty() {
                return vec![];
            }

            vec![Alert {
                rule_id: "PE-03".to_string(),
                severity: Severity::Medium,
                title: "Login Profile Created (Console Access Added)".to_string(),
                description: format!(
                    "{} IAM user(s) had console access (login profiles) created. \
                     This grants password-based console access to previously API-only accounts.",
                    ids.len()
                ),
                matching_record_ids: ids,
                metadata: HashMap::new(),
                mitre_tactic: "Persistence".to_string(),
                mitre_technique: "T1098".to_string(),
                query: "eventName=CreateLoginProfile".to_string(),
            }]
        }

        /// PE-04: Admin policy attached (AttachUserPolicy/AttachRolePolicy/PutUserPolicy/PutRolePolicy
        /// where policy name/ARN contains "AdministratorAccess" or a wildcard resource)
        pub fn pe_04_admin_policy_attached(store: &Store) -> Vec<Alert> {
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
                    for &id in ids {
                        if let Some(r) = store.get_record(id) {
                            let is_admin = check_admin_policy(&r.record.request_parameters);
                            if is_admin {
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
                rule_id: "PE-04".to_string(),
                severity: Severity::Critical,
                title: "Administrative Policy Attached".to_string(),
                description: format!(
                    "{} event(s) attached an administrative policy (AdministratorAccess or wildcard). \
                     This grants unrestricted access and is a common backdoor technique.",
                    matching.len()
                ),
                matching_record_ids: matching,
                metadata: HashMap::new(),
                mitre_tactic: "Persistence".to_string(),
                mitre_technique: "T1098.003".to_string(),
                query: "eventName=AttachUserPolicy OR eventName=AttachRolePolicy OR eventName=PutUserPolicy OR eventName=PutRolePolicy".to_string(),
            }]
        }

        fn check_admin_policy(params: &Option<serde_json::Value>) -> bool {
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
    }

    pub mod defense_evasion {
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
                matching_record_ids: matching,
                metadata: meta,
                mitre_tactic: "Defense Evasion".to_string(),
                mitre_technique: "T1562.008".to_string(),
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
                matching_record_ids: matching,
                metadata: HashMap::new(),
                mitre_tactic: "Defense Evasion".to_string(),
                mitre_technique: "T1562.001".to_string(),
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
                matching_record_ids: matching,
                metadata: HashMap::new(),
                mitre_tactic: "Defense Evasion".to_string(),
                mitre_technique: "T1562.001".to_string(),
                query: "eventName=StopConfigurationRecorder OR eventName=DeleteConfigurationRecorder".to_string(),
            }]
        }
    }

    pub mod credential_access {
        use std::collections::HashMap;
        use crate::store::Store;
        use crate::detection::{Alert, Severity};

        /// CA-02: Secrets Manager Bulk Access (>5 GetSecretValue in 10 min by same identity)
        pub fn ca_02_secrets_bulk(store: &Store) -> Vec<Alert> {
            let ids = match store.idx_event_name.get("GetSecretValue") {
                Some(ids) => ids,
                None => return vec![],
            };

            // Group by identity (ARN or userName)
            let mut by_identity: HashMap<String, Vec<(i64, u64)>> = HashMap::new();
            for &id in ids {
                if let Some(r) = store.get_record(id) {
                    let identity = r.record.user_identity.arn
                        .clone()
                        .or_else(|| r.record.user_identity.user_name.clone())
                        .unwrap_or_else(|| "unknown".to_string());
                    by_identity.entry(identity).or_default().push((r.timestamp, id));
                }
            }

            let window_ms = 10 * 60 * 1000;
            let threshold = 5;
            let mut all_matching: Vec<u64> = vec![];
            let mut offending_identities: Vec<String> = vec![];

            for (identity, mut events) in by_identity {
                events.sort_unstable_by_key(|(ts, _)| *ts);
                let mut start = 0;
                for end in 0..events.len() {
                    while events[end].0 - events[start].0 > window_ms {
                        start += 1;
                    }
                    if end - start + 1 > threshold {
                        for (_, wid) in &events[start..=end] {
                            if !all_matching.contains(wid) {
                                all_matching.push(*wid);
                            }
                        }
                        if !offending_identities.contains(&identity) {
                            offending_identities.push(identity.clone());
                        }
                        break;
                    }
                }
            }

            if all_matching.is_empty() {
                return vec![];
            }

            let mut meta = HashMap::new();
            meta.insert("identities".to_string(), offending_identities.join(", "));

            // If single offending identity, scope the query to it
            let query = if offending_identities.len() == 1 {
                let id = &offending_identities[0];
                if id.starts_with("arn:") {
                    format!("eventName=GetSecretValue arn=\"{}\"", id)
                } else {
                    format!("eventName=GetSecretValue userName=\"{}\"", id)
                }
            } else {
                "eventName=GetSecretValue".to_string()
            };

            vec![Alert {
                rule_id: "CA-02".to_string(),
                severity: Severity::High,
                title: "Secrets Manager Bulk Access".to_string(),
                description: format!(
                    "Identity accessed >{}  secrets within 10 minutes. \
                     Bulk secret retrieval suggests credential harvesting. Identities: {}",
                    threshold,
                    offending_identities.join(", ")
                ),
                matching_record_ids: all_matching,
                metadata: meta,
                mitre_tactic: "Credential Access".to_string(),
                mitre_technique: "T1555".to_string(),
                query,
            }]
        }

        /// CA-04: Password Policy Weakened
        pub fn ca_04_password_policy_weakened(store: &Store) -> Vec<Alert> {
            let ids = match store.idx_event_name.get("UpdateAccountPasswordPolicy") {
                Some(ids) => ids.clone(),
                None => return vec![],
            };

            if ids.is_empty() {
                return vec![];
            }

            vec![Alert {
                rule_id: "CA-04".to_string(),
                severity: Severity::Medium,
                title: "Account Password Policy Modified".to_string(),
                description: format!(
                    "{} modification(s) to the account password policy were detected. \
                     Weakening password policies enables credential-based attacks.",
                    ids.len()
                ),
                matching_record_ids: ids,
                metadata: HashMap::new(),
                mitre_tactic: "Credential Access".to_string(),
                mitre_technique: "T1556".to_string(),
                query: "eventName=UpdateAccountPasswordPolicy".to_string(),
            }]
        }
    }

    pub mod discovery {
        use std::collections::HashMap;
        use crate::store::Store;
        use crate::detection::{Alert, Severity};

        /// DI-02: IAM Enumeration
        pub fn di_02_iam_enumeration(store: &Store) -> Vec<Alert> {
            let event_names = [
                "ListUsers",
                "ListRoles",
                "ListPolicies",
                "ListGroups",
                "GetAccountAuthorizationDetails",
                "ListAttachedUserPolicies",
                "ListAttachedRolePolicies",
            ];

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
                rule_id: "DI-02".to_string(),
                severity: Severity::Medium,
                title: "IAM Enumeration Detected".to_string(),
                description: format!(
                    "{} IAM enumeration event(s) detected (ListUsers, ListRoles, ListPolicies, etc.). \
                     Reconnaissance of IAM resources is a common precursor to privilege escalation.",
                    matching.len()
                ),
                matching_record_ids: matching,
                metadata: meta,
                mitre_tactic: "Discovery".to_string(),
                mitre_technique: "T1087.004".to_string(),
                query: "eventName=ListUsers OR eventName=ListRoles OR eventName=ListPolicies OR eventName=GetAccountAuthorizationDetails OR eventName=ListGroups".to_string(),
            }]
        }

        /// DI-03: AccessDenied Spike (≥10 AccessDenied in 10 min by same identity)
        pub fn di_03_access_denied_spike(store: &Store) -> Vec<Alert> {
            let ids = match store.idx_error_code.get("AccessDenied") {
                Some(ids) => ids,
                None => return vec![],
            };

            // Group by identity
            let mut by_identity: HashMap<String, Vec<(i64, u64)>> = HashMap::new();
            for &id in ids {
                if let Some(r) = store.get_record(id) {
                    let identity = r.record.user_identity.arn
                        .clone()
                        .or_else(|| r.record.user_identity.user_name.clone())
                        .or_else(|| r.record.source_ip_address.clone())
                        .unwrap_or_else(|| "unknown".to_string());
                    by_identity.entry(identity).or_default().push((r.timestamp, id));
                }
            }

            let window_ms = 10 * 60 * 1000;
            let threshold = 10;
            let mut all_matching: Vec<u64> = vec![];
            let mut offending_identities: Vec<String> = vec![];

            for (identity, mut events) in by_identity {
                events.sort_unstable_by_key(|(ts, _)| *ts);
                let mut start = 0;
                for end in 0..events.len() {
                    while events[end].0 - events[start].0 > window_ms {
                        start += 1;
                    }
                    if end - start + 1 >= threshold {
                        for (_, wid) in &events[start..=end] {
                            if !all_matching.contains(wid) {
                                all_matching.push(*wid);
                            }
                        }
                        if !offending_identities.contains(&identity) {
                            offending_identities.push(identity.clone());
                        }
                        break;
                    }
                }
            }

            if all_matching.is_empty() {
                return vec![];
            }

            let mut meta = HashMap::new();
            meta.insert("identities".to_string(), offending_identities.join(", "));

            // Scope to the specific identity if single offender
            let query = if offending_identities.len() == 1 {
                let id = &offending_identities[0];
                if id.starts_with("arn:") {
                    format!("errorCode=AccessDenied arn=\"{}\"", id)
                } else {
                    format!("errorCode=AccessDenied userName=\"{}\"", id)
                }
            } else {
                "errorCode=AccessDenied".to_string()
            };

            vec![Alert {
                rule_id: "DI-03".to_string(),
                severity: Severity::Medium,
                title: "AccessDenied Spike — Possible Permission Probing".to_string(),
                description: format!(
                    "≥{} AccessDenied errors within 10 minutes by same identity. \
                     This pattern indicates systematic permission probing. Identities: {}",
                    threshold,
                    offending_identities.join(", ")
                ),
                matching_record_ids: all_matching,
                metadata: meta,
                mitre_tactic: "Discovery".to_string(),
                mitre_technique: "T1580".to_string(),
                query,
            }]
        }
    }

    pub mod exfiltration {
        use std::collections::HashMap;
        use crate::store::Store;
        use crate::detection::{Alert, Severity};

        /// EX-01: S3 Bucket Made Public (PutBucketPolicy or PutBucketAcl)
        pub fn ex_01_s3_bucket_public(store: &Store) -> Vec<Alert> {
            let event_names = ["PutBucketPolicy", "PutBucketAcl"];
            let mut matching = vec![];

            for name in &event_names {
                if let Some(ids) = store.idx_event_name.get(*name) {
                    for &id in ids {
                        if let Some(r) = store.get_record(id) {
                            if is_public_grant(&r.record.request_parameters) {
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
                rule_id: "EX-01".to_string(),
                severity: Severity::High,
                title: "S3 Bucket Policy/ACL Modified (Potential Public Exposure)".to_string(),
                description: format!(
                    "{} S3 bucket policy or ACL change(s) detected that may grant public access. \
                     Publicly accessible buckets can expose sensitive data.",
                    matching.len()
                ),
                matching_record_ids: matching,
                metadata: HashMap::new(),
                mitre_tactic: "Exfiltration".to_string(),
                mitre_technique: "T1537".to_string(),
                query: "eventName=PutBucketPolicy OR eventName=PutBucketAcl".to_string(),
            }]
        }

        fn is_public_grant(params: &Option<serde_json::Value>) -> bool {
            let params = match params {
                Some(p) => p,
                None => return false,
            };

            // Check ACL grants for AllUsers / AuthenticatedUsers
            let public_grantees = [
                "http://acs.amazonaws.com/groups/global/AllUsers",
                "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
            ];

            let params_str = params.to_string();
            for grantee in &public_grantees {
                if params_str.contains(grantee) {
                    return true;
                }
            }

            // Check bucket policy for Principal = "*"
            if params_str.contains("\"Principal\":\"*\"")
                || params_str.contains("\"Principal\": \"*\"")
            {
                return true;
            }

            // If we can't determine, flag all PutBucketPolicy/PutBucketAcl as worth reviewing
            // For PutBucketPolicy (has bucketPolicy field), always flag
            if params.get("bucketPolicy").is_some() {
                return true;
            }

            false
        }
    }

    pub mod impact {
        use std::collections::HashMap;
        use crate::store::Store;
        use crate::detection::{Alert, Severity};

        /// IM-01: EC2 Instances Launched in Bulk (>5 RunInstances in 10 min, any identity)
        pub fn im_01_ec2_bulk_launch(store: &Store) -> Vec<Alert> {
            let ids = match store.idx_event_name.get("RunInstances") {
                Some(ids) => ids,
                None => return vec![],
            };

            // Collect all RunInstances timestamps
            let mut events: Vec<(i64, u64)> = ids
                .iter()
                .filter_map(|&id| store.get_record(id).map(|r| (r.timestamp, id)))
                .collect();

            events.sort_unstable_by_key(|(ts, _)| *ts);

            let window_ms = 10 * 60 * 1000;
            let threshold = 5;
            let mut all_matching: Vec<u64> = vec![];

            let mut start = 0;
            for end in 0..events.len() {
                while events[end].0 - events[start].0 > window_ms {
                    start += 1;
                }
                if end - start + 1 > threshold {
                    for (_, wid) in &events[start..=end] {
                        if !all_matching.contains(wid) {
                            all_matching.push(*wid);
                        }
                    }
                }
            }

            if all_matching.is_empty() {
                return vec![];
            }

            let mut meta = HashMap::new();
            meta.insert("total_run_instances".to_string(), ids.len().to_string());

            vec![Alert {
                rule_id: "IM-01".to_string(),
                severity: Severity::High,
                title: "EC2 Instances Launched in Bulk".to_string(),
                description: format!(
                    ">{} EC2 RunInstances events within 10 minutes. \
                     Bulk launches may indicate cryptomining or resource abuse.",
                    threshold
                ),
                matching_record_ids: all_matching,
                metadata: meta,
                mitre_tactic: "Impact".to_string(),
                mitre_technique: "T1496".to_string(),
                query: "eventName=RunInstances".to_string(),
            }]
        }

        /// IM-02: Resource Deletion Spree (>10 Delete*/Terminate* events in 5 min by same identity)
        pub fn im_02_resource_deletion_spree(store: &Store) -> Vec<Alert> {
            // Collect all Delete* and Terminate* events
            let mut deletion_ids: Vec<u64> = vec![];

            for (event_name, ids) in &store.idx_event_name {
                if event_name.starts_with("Delete")
                    || event_name.starts_with("Terminate")
                    || event_name.starts_with("Destroy")
                    || event_name.starts_with("Remove")
                {
                    deletion_ids.extend_from_slice(ids);
                }
            }

            if deletion_ids.is_empty() {
                return vec![];
            }

            // Group by identity
            let mut by_identity: HashMap<String, Vec<(i64, u64)>> = HashMap::new();
            for &id in &deletion_ids {
                if let Some(r) = store.get_record(id) {
                    let identity = r.record.user_identity.arn
                        .clone()
                        .or_else(|| r.record.user_identity.user_name.clone())
                        .unwrap_or_else(|| "unknown".to_string());
                    by_identity.entry(identity).or_default().push((r.timestamp, id));
                }
            }

            let window_ms = 5 * 60 * 1000; // 5 minutes
            let threshold = 10;
            let mut all_matching: Vec<u64> = vec![];
            let mut offending_identities: Vec<String> = vec![];

            for (identity, mut events) in by_identity {
                events.sort_unstable_by_key(|(ts, _)| *ts);
                let mut start = 0;
                for end in 0..events.len() {
                    while events[end].0 - events[start].0 > window_ms {
                        start += 1;
                    }
                    if end - start + 1 > threshold {
                        for (_, wid) in &events[start..=end] {
                            if !all_matching.contains(wid) {
                                all_matching.push(*wid);
                            }
                        }
                        if !offending_identities.contains(&identity) {
                            offending_identities.push(identity.clone());
                        }
                        break;
                    }
                }
            }

            if all_matching.is_empty() {
                return vec![];
            }

            let mut meta = HashMap::new();
            meta.insert("identities".to_string(), offending_identities.join(", "));

            // Scope to the specific identity if single offender
            let query = if offending_identities.len() == 1 {
                let id = &offending_identities[0];
                if id.starts_with("arn:") {
                    format!("eventName=Delete* arn=\"{}\"", id)
                } else {
                    format!("eventName=Delete* userName=\"{}\"", id)
                }
            } else {
                "eventName=Delete* OR eventName=Terminate*".to_string()
            };

            vec![Alert {
                rule_id: "IM-02".to_string(),
                severity: Severity::Critical,
                title: "Resource Deletion Spree Detected".to_string(),
                description: format!(
                    ">{} destructive actions (Delete*/Terminate*) within 5 minutes by same identity. \
                     This indicates possible data destruction. Identities: {}",
                    threshold,
                    offending_identities.join(", ")
                ),
                matching_record_ids: all_matching,
                metadata: meta,
                mitre_tactic: "Impact".to_string(),
                mitre_technique: "T1485".to_string(),
                query,
            }]
        }
    }
}
