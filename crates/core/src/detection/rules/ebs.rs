use crate::store::Store;
use crate::detection::Finding;

/// EBS-02: EBS Snapshot Made Public
pub fn ebs_02_snapshot_public(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("ModifySnapshotAttribute")?;

    let mut matching = vec![];
    for id in ids {
        if store.get_record(id).is_some() {
            let params_str = store.get_request_parameters_str(id).unwrap_or_default();
            // Public share adds "all" as a group in createVolumePermission
            if params_str.contains("\"all\"") || params_str.contains("all") && params_str.contains("add") {
                matching.push(id);
            }
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

