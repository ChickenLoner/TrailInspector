use std::collections::HashMap;
use crate::store::Store;
use crate::detection::{Alert, Severity, scoped_ids, jget};

/// RDS-01: RDS Deletion Protection Disabled
pub fn rds_01_deletion_protection_disabled(store: &Store) -> Vec<Alert> {
    let event_names = ["ModifyDBInstance", "ModifyDBCluster"];
    let mut matching = vec![];

    let ids = scoped_ids(store, &event_names, &["rds.amazonaws.com"], true);
    for id in ids {
        // Only an explicit `deletionProtection: false` disables it; `true` alongside an
        // unrelated `applyImmediately: false` must not fire.
        let Some(p) = store.parse_request_parameters(id) else { continue };
        if jget(&p, "deletionProtection") == Some(&serde_json::Value::Bool(false)) {
            matching.push(id);
        }
    }

    if matching.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "RDS-01".to_string(),
        severity: Severity::High,
        title: "RDS Deletion Protection Disabled".to_string(),
        description: format!(
            "{} RDS instance(s)/cluster(s) had deletion protection disabled. \
             This allows databases to be deleted without additional confirmation, \
             increasing risk of data loss.",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Impact".to_string(),
        mitre_technique: "T1485".to_string(),
        service: "RDS".to_string(),
        query: "eventName=ModifyDBInstance eventSource=rds.amazonaws.com OR eventName=ModifyDBCluster eventSource=rds.amazonaws.com".to_string(),
    }]
}

/// RDS-02: RDS Instance Restored from Public Snapshot
pub fn rds_02_public_snapshot_restore(store: &Store) -> Vec<Alert> {
    let event_names = [
        "RestoreDBInstanceFromDBSnapshot",
        "RestoreDBClusterFromSnapshot",
        "RestoreDBInstanceToPointInTime",
    ];
    let mut matching = vec![];

    let ids = scoped_ids(store, &event_names, &["rds.amazonaws.com"], true);
    for id in ids {
        if store.get_record(id).is_some() {
            let params_str = store.get_request_parameters_str(id).unwrap_or_default();
            if params_str.contains("\"publiclyAccessible\":true")
                || params_str.contains("\"publiclyAccessible\": true")
            {
                matching.push(id);
            }
        }
    }

    if matching.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "RDS-02".to_string(),
        severity: Severity::High,
        title: "RDS Instance Restored with Public Access".to_string(),
        description: format!(
            "{} RDS instance(s) were restored from snapshot with publiclyAccessible=true. \
             Publicly accessible database instances are directly exposed to the internet.",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Exfiltration".to_string(),
        mitre_technique: "T1537".to_string(),
        service: "RDS".to_string(),
        query: "eventName=RestoreDBInstanceFromDBSnapshot eventSource=rds.amazonaws.com OR eventName=RestoreDBClusterFromSnapshot eventSource=rds.amazonaws.com".to_string(),
    }]
}

/// RDS-03: RDS Master Password Changed
pub fn rds_03_master_password_changed(store: &Store) -> Vec<Alert> {
    let event_names = ["ModifyDBInstance", "ModifyDBCluster"];
    let mut matching = vec![];

    let ids = scoped_ids(store, &event_names, &["rds.amazonaws.com"], true);
    for id in ids {
        if store.get_record(id).is_some() {
            let params_str = store.get_request_parameters_str(id).unwrap_or_default();
            if params_str.contains("masterUserPassword")
                || params_str.contains("MasterUserPassword")
            {
                matching.push(id);
            }
        }
    }

    if matching.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "RDS-03".to_string(),
        severity: Severity::Medium,
        title: "RDS Master Password Changed".to_string(),
        description: format!(
            "{} RDS instance(s)/cluster(s) had their master password changed. \
             Unexpected password changes may indicate credential takeover.",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Credential Access".to_string(),
        mitre_technique: "T1098".to_string(),
        service: "RDS".to_string(),
        query: "eventName=ModifyDBInstance eventSource=rds.amazonaws.com OR eventName=ModifyDBCluster eventSource=rds.amazonaws.com".to_string(),
    }]
}
