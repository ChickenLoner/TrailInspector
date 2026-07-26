use crate::store::Store;
use crate::detection::Finding;

/// RDS-01: RDS Deletion Protection Disabled
pub fn rds_01_deletion_protection_disabled(store: &Store) -> Option<Finding> {
    let event_names = ["ModifyDBInstance", "ModifyDBCluster"];
    let mut matching = vec![];

    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
            for id in ids {
                if store.get_record(id).is_some() {
                    let params_str = store.get_request_parameters_str(id).unwrap_or_default();
                    if params_str.contains("deletionProtection") && params_str.contains("false") {
                        matching.push(id);
                    }
                }
            }
        }
    }

    if matching.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} RDS instance(s)/cluster(s) had deletion protection disabled. \
             This allows databases to be deleted without additional confirmation, \
             increasing risk of data loss.",
            matching.len()
        ),
        matching,
        "eventName=ModifyDBInstance OR eventName=ModifyDBCluster",
    ))
}

/// RDS-02: RDS Instance Restored from Public Snapshot
pub fn rds_02_public_snapshot_restore(store: &Store) -> Option<Finding> {
    let event_names = [
        "RestoreDBInstanceFromDBSnapshot",
        "RestoreDBClusterFromSnapshot",
        "RestoreDBInstanceToPointInTime",
    ];
    let mut matching = vec![];

    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
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
        }
    }

    if matching.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} RDS instance(s) were restored from snapshot with publiclyAccessible=true. \
             Publicly accessible database instances are directly exposed to the internet.",
            matching.len()
        ),
        matching,
        crate::detection::field_query("eventName", &event_names),
    ))
}

/// RDS-03: RDS Master Password Changed
pub fn rds_03_master_password_changed(store: &Store) -> Option<Finding> {
    let event_names = ["ModifyDBInstance", "ModifyDBCluster"];
    let mut matching = vec![];

    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
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
        }
    }

    if matching.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} RDS instance(s)/cluster(s) had their master password changed. \
             Unexpected password changes may indicate credential takeover.",
            matching.len()
        ),
        matching,
        "eventName=ModifyDBInstance OR eventName=ModifyDBCluster",
    ))
}
