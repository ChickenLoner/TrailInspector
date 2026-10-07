use crate::store::Store;
use crate::detection::{Finding, adds_public_group, scoped_ids};

/// EBS-02: EBS Snapshot Made Public
pub fn ebs_02_snapshot_public(store: &Store) -> Option<Finding> {
    let ids = scoped_ids(store, &["ModifySnapshotAttribute"], &["ec2.amazonaws.com"], true);
    if ids.is_empty() {
        return None;
    }

    let mut matching = vec![];
    for id in ids {
        // Public share *adds* the "all" group to createVolumePermission; removing it
        // makes the snapshot private and must not fire.
        let Some(p) = store.parse_request_parameters(id) else { continue };
        if adds_public_group(&p, "createVolumePermission") {
            matching.push(id);
        }
    }

    if matching.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} EBS snapshot(s) were made publicly accessible. Public snapshots can be \
             accessed by any AWS account and may expose sensitive data.",
            matching.len()
        ),
        matching,
        "eventName=ModifySnapshotAttribute",
    ))
}

