use std::collections::HashMap;
use crate::store::Store;
use crate::detection::{Alert, Severity, scoped_ids, jget, json_has_str, adds_public_group};

/// RS-01: EC2 AMI Made Public
pub fn rs_01_ami_made_public(store: &Store) -> Vec<Alert> {
    let ids = scoped_ids(store, &["ModifyImageAttribute"], &["ec2.amazonaws.com"], true);
    if ids.is_empty() {
        return vec![];
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
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Exfiltration".to_string(),
        mitre_technique: "T1537".to_string(),
        service: "EC2".to_string(),
        query: "eventName=ModifyImageAttribute eventSource=ec2.amazonaws.com".to_string(),
    }]
}

/// RS-02: SSM Document Made Public
pub fn rs_02_ssm_document_public(store: &Store) -> Vec<Alert> {
    let ids = scoped_ids(store, &["ModifyDocumentPermission"], &["ssm.amazonaws.com"], true);
    if ids.is_empty() {
        return vec![];
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
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Exfiltration".to_string(),
        mitre_technique: "T1537".to_string(),
        service: "SSM".to_string(),
        query: "eventName=ModifyDocumentPermission eventSource=ssm.amazonaws.com".to_string(),
    }]
}

/// RS-03: RDS Snapshot Made Public
pub fn rs_03_rds_snapshot_public(store: &Store) -> Vec<Alert> {
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
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Exfiltration".to_string(),
        mitre_technique: "T1537".to_string(),
        service: "RDS".to_string(),
        query: "eventName=ModifyDBSnapshotAttribute eventSource=rds.amazonaws.com OR eventName=ModifyDBClusterSnapshotAttribute eventSource=rds.amazonaws.com".to_string(),
    }]
}
