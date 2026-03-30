use std::collections::HashMap;
use crate::store::Store;
use crate::detection::{Alert, Severity};

/// RS-01: EC2 AMI Made Public
pub fn rs_01_ami_made_public(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("ModifyImageAttribute") {
        Some(ids) => ids,
        None => return vec![],
    };

    let mut matching = vec![];
    for &id in ids {
        if let Some(r) = store.get_record(id) {
            let params_str = r.record.request_parameters
                .as_ref()
                .map(|v| v.to_string())
                .unwrap_or_default();
            // Public AMI adds "all" group to launchPermission
            if (params_str.contains("launchPermission") || params_str.contains("LaunchPermission"))
                && params_str.contains("all")
            {
                matching.push(id);
            }
        }
    }

    if matching.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "RS-01".to_string(),
        severity: Severity::High,
        title: "EC2 AMI Made Public".to_string(),
        description: format!(
            "{} EC2 AMI(s) were made publicly accessible. Public AMIs can be launched by \
             any AWS account and may expose embedded secrets or sensitive configurations.",
            matching.len()
        ),
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Exfiltration".to_string(),
        mitre_technique: "T1537".to_string(),
        service: "EC2".to_string(),
        query: "eventName=ModifyImageAttribute".to_string(),
    }]
}

/// RS-02: SSM Document Made Public
pub fn rs_02_ssm_document_public(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("ModifyDocumentPermission") {
        Some(ids) => ids,
        None => return vec![],
    };

    let mut matching = vec![];
    for &id in ids {
        if let Some(r) = store.get_record(id) {
            let params_str = r.record.request_parameters
                .as_ref()
                .map(|v| v.to_string())
                .unwrap_or_default();
            if params_str.contains("All") || params_str.contains("\"all\"") {
                matching.push(id);
            }
        }
    }

    if matching.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "RS-02".to_string(),
        severity: Severity::High,
        title: "SSM Document Made Public".to_string(),
        description: format!(
            "{} SSM document(s) were shared publicly. Public SSM documents can be run \
             against EC2 instances and may contain sensitive automation logic.",
            matching.len()
        ),
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Exfiltration".to_string(),
        mitre_technique: "T1537".to_string(),
        service: "SSM".to_string(),
        query: "eventName=ModifyDocumentPermission".to_string(),
    }]
}

/// RS-03: RDS Snapshot Made Public
pub fn rs_03_rds_snapshot_public(store: &Store) -> Vec<Alert> {
    let event_names = [
        "ModifyDBSnapshotAttribute",
        "ModifyDBClusterSnapshotAttribute",
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
                    if params_str.contains("all") || params_str.contains("\"restore\"") {
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
        rule_id: "RS-03".to_string(),
        severity: Severity::High,
        title: "RDS Snapshot Made Public".to_string(),
        description: format!(
            "{} RDS snapshot(s) were shared publicly. Publicly accessible database \
             snapshots can be restored by any AWS account, exposing all data.",
            matching.len()
        ),
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Exfiltration".to_string(),
        mitre_technique: "T1537".to_string(),
        service: "RDS".to_string(),
        query: "eventName=ModifyDBSnapshotAttribute OR eventName=ModifyDBClusterSnapshotAttribute".to_string(),
    }]
}
