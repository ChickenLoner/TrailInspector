use crate::store::Store;
use crate::detection::Finding;

/// RS-01: EC2 AMI Made Public
pub fn rs_01_ami_made_public(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("ModifyImageAttribute")?;

    let mut matching = vec![];
    for id in ids {
        if store.get_record(id).is_some() {
            let params_str = store.get_request_parameters_str(id).unwrap_or_default();
            // Public AMI adds "all" group to launchPermission
            if (params_str.contains("launchPermission") || params_str.contains("LaunchPermission"))
                && params_str.contains("all")
            {
                matching.push(id);
            }
        }
    }

    if matching.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} EC2 AMI(s) were made publicly accessible. Public AMIs can be launched by \
             any AWS account and may expose embedded secrets or sensitive configurations.",
            matching.len()
        ),
        matching,
        "eventName=ModifyImageAttribute",
    ))
}

/// RS-02: SSM Document Made Public
pub fn rs_02_ssm_document_public(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("ModifyDocumentPermission")?;

    let mut matching = vec![];
    for id in ids {
        if store.get_record(id).is_some() {
            let params_str = store.get_request_parameters_str(id).unwrap_or_default();
            if params_str.contains("All") || params_str.contains("\"all\"") {
                matching.push(id);
            }
        }
    }

    if matching.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} SSM document(s) were shared publicly. Public SSM documents can be run \
             against EC2 instances and may contain sensitive automation logic.",
            matching.len()
        ),
        matching,
        "eventName=ModifyDocumentPermission",
    ))
}

/// RS-03: RDS Snapshot Made Public
pub fn rs_03_rds_snapshot_public(store: &Store) -> Option<Finding> {
    let event_names = [
        "ModifyDBSnapshotAttribute",
        "ModifyDBClusterSnapshotAttribute",
    ];
    let mut matching = vec![];

    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
            for id in ids {
                let params_str = store.get_request_parameters_str(id).unwrap_or_default();
                if params_str.contains("all") || params_str.contains("\"restore\"") {
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
            "{} RDS snapshot(s) were shared publicly. Publicly accessible database \
             snapshots can be restored by any AWS account, exposing all data.",
            matching.len()
        ),
        matching,
        "eventName=ModifyDBSnapshotAttribute OR eventName=ModifyDBClusterSnapshotAttribute",
    ))
}
