use std::collections::HashMap;
use crate::store::Store;
use crate::detection::{Alert, Severity};

/// EBS-01: EBS Default Encryption Disabled
pub fn ebs_01_encryption_disabled(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("DisableEbsEncryptionByDefault") {
        Some(ids) => ids.to_vec(),
        None => return vec![],
    };

    vec![Alert {
        rule_id: "EBS-01".to_string(),
        severity: Severity::High,
        title: "EBS Default Encryption Disabled".to_string(),
        description: format!(
            "{} event(s) disabled EBS default encryption. New EBS volumes in this region will \
             be created unencrypted, exposing data at rest.",
            ids.len()
        ),
        matching_count: 0,
        matching_record_ids: ids,
        metadata: HashMap::new(),
        mitre_tactic: "Defense Evasion".to_string(),
        mitre_technique: "T1486".to_string(),
        service: "EBS".to_string(),
        query: "eventName=DisableEbsEncryptionByDefault".to_string(),
    }]
}

/// EBS-02: EBS Snapshot Made Public
pub fn ebs_02_snapshot_public(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("ModifySnapshotAttribute") {
        Some(ids) => ids,
        None => return vec![],
    };

    let mut matching = vec![];
    for &id in ids {
        if store.get_record(id).is_some() {
            let params_str = store.get_request_parameters_str(id).unwrap_or_default();
            // Public share adds "all" as a group in createVolumePermission
            if params_str.contains("\"all\"") || params_str.contains("all") && params_str.contains("add") {
                matching.push(id);
            }
        }
    }

    if matching.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "EBS-02".to_string(),
        severity: Severity::Critical,
        title: "EBS Snapshot Made Public".to_string(),
        description: format!(
            "{} EBS snapshot(s) were made publicly accessible. Public snapshots can be \
             accessed by any AWS account and may expose sensitive data.",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Exfiltration".to_string(),
        mitre_technique: "T1537".to_string(),
        service: "EBS".to_string(),
        query: "eventName=ModifySnapshotAttribute".to_string(),
    }]
}

/// EBS-03: EBS Volume Detached
pub fn ebs_03_volume_detached(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("DetachVolume") {
        Some(ids) => ids.to_vec(),
        None => return vec![],
    };

    vec![Alert {
        rule_id: "EBS-03".to_string(),
        severity: Severity::Low,
        title: "EBS Volume Detached".to_string(),
        description: format!(
            "{} EBS volume(s) were detached from EC2 instances. Unexpected detachments may \
             indicate data staging prior to exfiltration.",
            ids.len()
        ),
        matching_count: 0,
        matching_record_ids: ids,
        metadata: HashMap::new(),
        mitre_tactic: "Exfiltration".to_string(),
        mitre_technique: "T1537".to_string(),
        service: "EBS".to_string(),
        query: "eventName=DetachVolume".to_string(),
    }]
}

/// EBS-04: EBS Snapshot Deleted
pub fn ebs_04_snapshot_deleted(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("DeleteSnapshot") {
        Some(ids) => ids.to_vec(),
        None => return vec![],
    };

    vec![Alert {
        rule_id: "EBS-04".to_string(),
        severity: Severity::Medium,
        title: "EBS Snapshot Deleted".to_string(),
        description: format!(
            "{} EBS snapshot(s) were deleted. Snapshot deletion destroys backup copies and \
             may be used to eliminate forensic evidence.",
            ids.len()
        ),
        matching_count: 0,
        matching_record_ids: ids,
        metadata: HashMap::new(),
        mitre_tactic: "Impact".to_string(),
        mitre_technique: "T1485".to_string(),
        service: "EBS".to_string(),
        query: "eventName=DeleteSnapshot".to_string(),
    }]
}

/// EBS-05: EBS Default KMS Key Changed
pub fn ebs_05_default_kms_changed(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("ModifyEbsDefaultKmsKeyId") {
        Some(ids) => ids.to_vec(),
        None => return vec![],
    };

    vec![Alert {
        rule_id: "EBS-05".to_string(),
        severity: Severity::Medium,
        title: "EBS Default KMS Encryption Key Changed".to_string(),
        description: format!(
            "{} event(s) changed the default KMS key used for EBS volume encryption. \
             Changing to an attacker-controlled key can prevent data recovery.",
            ids.len()
        ),
        matching_count: 0,
        matching_record_ids: ids,
        metadata: HashMap::new(),
        mitre_tactic: "Impact".to_string(),
        mitre_technique: "T1486".to_string(),
        service: "EBS".to_string(),
        query: "eventName=ModifyEbsDefaultKmsKeyId".to_string(),
    }]
}
