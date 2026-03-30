use std::collections::HashMap;
use crate::store::Store;
use crate::detection::{Alert, Severity};

/// RDS-01: RDS Deletion Protection Disabled
pub fn rds_01_deletion_protection_disabled(store: &Store) -> Vec<Alert> {
    let event_names = ["ModifyDBInstance", "ModifyDBCluster"];
    let mut matching = vec![];

    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
            for &id in ids {
                if let Some(r) = store.get_record(id) {
                    let params_str = r.record.request_parameters
                        .as_ref()
                        .map(|v| v.to_string())
                        .unwrap_or_default();
                    if params_str.contains("deletionProtection") && params_str.contains("false") {
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
        rule_id: "RDS-01".to_string(),
        severity: Severity::High,
        title: "RDS Deletion Protection Disabled".to_string(),
        description: format!(
            "{} RDS instance(s)/cluster(s) had deletion protection disabled. \
             This allows databases to be deleted without additional confirmation, \
             increasing risk of data loss.",
            matching.len()
        ),
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Impact".to_string(),
        mitre_technique: "T1485".to_string(),
        service: "RDS".to_string(),
        query: "eventName=ModifyDBInstance OR eventName=ModifyDBCluster".to_string(),
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

    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
            for &id in ids {
                if let Some(r) = store.get_record(id) {
                    let params_str = r.record.request_parameters
                        .as_ref()
                        .map(|v| v.to_string())
                        .unwrap_or_default();
                    if params_str.contains("\"publiclyAccessible\":true")
                        || params_str.contains("\"publiclyAccessible\": true")
                    {
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
        rule_id: "RDS-02".to_string(),
        severity: Severity::High,
        title: "RDS Instance Restored with Public Access".to_string(),
        description: format!(
            "{} RDS instance(s) were restored from snapshot with publiclyAccessible=true. \
             Publicly accessible database instances are directly exposed to the internet.",
            matching.len()
        ),
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Exfiltration".to_string(),
        mitre_technique: "T1537".to_string(),
        service: "RDS".to_string(),
        query: "eventName=RestoreDBInstanceFromDBSnapshot OR eventName=RestoreDBClusterFromSnapshot".to_string(),
    }]
}

/// RDS-03: RDS Master Password Changed
pub fn rds_03_master_password_changed(store: &Store) -> Vec<Alert> {
    let event_names = ["ModifyDBInstance", "ModifyDBCluster"];
    let mut matching = vec![];

    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
            for &id in ids {
                if let Some(r) = store.get_record(id) {
                    let params_str = r.record.request_parameters
                        .as_ref()
                        .map(|v| v.to_string())
                        .unwrap_or_default();
                    if params_str.contains("masterUserPassword")
                        || params_str.contains("MasterUserPassword")
                    {
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
        rule_id: "RDS-03".to_string(),
        severity: Severity::Medium,
        title: "RDS Master Password Changed".to_string(),
        description: format!(
            "{} RDS instance(s)/cluster(s) had their master password changed. \
             Unexpected password changes may indicate credential takeover.",
            matching.len()
        ),
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Credential Access".to_string(),
        mitre_technique: "T1098".to_string(),
        service: "RDS".to_string(),
        query: "eventName=ModifyDBInstance OR eventName=ModifyDBCluster".to_string(),
    }]
}
