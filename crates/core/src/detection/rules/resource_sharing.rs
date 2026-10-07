use crate::store::Store;
use crate::detection::{Finding, adds_public_group, jget, json_has_str, scoped_ids};

/// RS-01: EC2 AMI Made Public
pub fn rs_01_ami_made_public(store: &Store) -> Option<Finding> {
    let ids = scoped_ids(store, &["ModifyImageAttribute"], &["ec2.amazonaws.com"], true);
    if ids.is_empty() {
        return None;
    }

    let mut matching = vec![];
    for id in ids {
        // Public AMI *adds* the "all" group to launchPermission.
        let Some(p) = store.parse_request_parameters(id) else { continue };
        if adds_public_group(&p, "launchPermission") {
            matching.push(id);
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
    let ids = scoped_ids(store, &["ModifyDocumentPermission"], &["ssm.amazonaws.com"], true);
    if ids.is_empty() {
        return None;
    }

    let mut matching = vec![];
    for id in ids {
        // Only sharing with "all" is public; `accountIdsToRemove: ["all"]` and document
        // names such as "AllowSSH" must not fire.
        let Some(p) = store.parse_request_parameters(id) else { continue };
        if jget(&p, "accountIdsToAdd").is_some_and(|v| json_has_str(v, "all")) {
            matching.push(id);
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

    let ids = scoped_ids(store, &event_names, &["rds.amazonaws.com"], true);
    for id in ids {
        let Some(p) = store.parse_request_parameters(id) else { continue };
        // Only an `add` of "all" to the `restore` attribute makes a snapshot public;
        // `attributeName` is always "restore" here, and `valuesToRemove` makes it private.
        let is_restore = jget(&p, "attributeName").is_some_and(|v| json_has_str(v, "restore"));
        let adds_all = jget(&p, "valuesToAdd").is_some_and(|v| json_has_str(v, "all"));
        if is_restore && adds_all {
            matching.push(id);
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
