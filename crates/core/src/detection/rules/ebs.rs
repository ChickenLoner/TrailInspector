use crate::store::Store;
use crate::detection::Finding;

/// EBS-01: EBS Default Encryption Disabled
pub fn ebs_01_encryption_disabled(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("DisableEbsEncryptionByDefault")?;

    Some(Finding::new(
        format!(
            "{} event(s) disabled EBS default encryption. New EBS volumes in this region will \
             be created unencrypted, exposing data at rest.",
            ids.len()
        ),
        ids.iter().collect(),
        "eventName=DisableEbsEncryptionByDefault",
    ))
}

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

/// EBS-03: EBS Volume Detached
pub fn ebs_03_volume_detached(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("DetachVolume")?;

    Some(Finding::new(
        format!(
            "{} EBS volume(s) were detached from EC2 instances. Unexpected detachments may \
             indicate data staging prior to exfiltration.",
            ids.len()
        ),
        ids.iter().collect(),
        "eventName=DetachVolume",
    ))
}

/// EBS-04: EBS Snapshot Deleted
pub fn ebs_04_snapshot_deleted(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("DeleteSnapshot")?;

    Some(Finding::new(
        format!(
            "{} EBS snapshot(s) were deleted. Snapshot deletion destroys backup copies and \
             may be used to eliminate forensic evidence.",
            ids.len()
        ),
        ids.iter().collect(),
        "eventName=DeleteSnapshot",
    ))
}

/// EBS-05: EBS Default KMS Key Changed
pub fn ebs_05_default_kms_changed(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("ModifyEbsDefaultKmsKeyId")?;

    Some(Finding::new(
        format!(
            "{} event(s) changed the default KMS key used for EBS volume encryption. \
             Changing to an attacker-controlled key can prevent data recovery.",
            ids.len()
        ),
        ids.iter().collect(),
        "eventName=ModifyEbsDefaultKmsKeyId",
    ))
}
