use std::collections::HashMap;
use crate::store::Store;
use crate::detection::{Alert, Severity};

/// EC-01: EC2 User Data Modified on Existing Instance
pub fn ec_01_userdata_modified(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("ModifyInstanceAttribute") {
        Some(ids) => ids,
        None => return vec![],
    };

    let mut matching = vec![];
    for &id in ids {
        if store.get_record(id).is_some() {
            let params_str = store.get_request_parameters_str(id).unwrap_or_default();
            if params_str.contains("userData") {
                matching.push(id);
            }
        }
    }

    if matching.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "EC-01".to_string(),
        severity: Severity::High,
        title: "EC2 Instance User Data Modified".to_string(),
        description: format!(
            "{} EC2 instance(s) had user data modified via ModifyInstanceAttribute. \
             Attackers inject reverse shells or backdoors into user data to execute \
             on the next instance start.",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Execution".to_string(),
        mitre_technique: "T1059".to_string(),
        service: "EC2".to_string(),
        query: "eventName=ModifyInstanceAttribute".to_string(),
    }]
}

/// EC-02: EC2 Key Pair Created
pub fn ec_02_keypair_created(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("CreateKeyPair") {
        Some(ids) => ids.to_vec(),
        None => return vec![],
    };

    if ids.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "EC-02".to_string(),
        severity: Severity::Medium,
        title: "EC2 Key Pair Created".to_string(),
        description: format!(
            "{} EC2 key pair(s) created. New key pairs establish persistent SSH access \
             to any instance configured to accept them.",
            ids.len()
        ),
        matching_count: 0,
        matching_record_ids: ids,
        metadata: HashMap::new(),
        mitre_tactic: "Persistence".to_string(),
        mitre_technique: "T1098.004".to_string(),
        service: "EC2".to_string(),
        query: "eventName=CreateKeyPair".to_string(),
    }]
}

/// EC-03: Launch Template Created or Updated with User Data
pub fn ec_03_launch_template_userdata(store: &Store) -> Vec<Alert> {
    let event_names = ["CreateLaunchTemplate", "CreateLaunchTemplateVersion"];
    let mut matching = vec![];

    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
            for &id in ids {
                if store.get_record(id).is_some() {
                    let params_str = store.get_request_parameters_str(id).unwrap_or_default();
                    if params_str.contains("userData") {
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
        rule_id: "EC-03".to_string(),
        severity: Severity::Medium,
        title: "Launch Template Created with User Data".to_string(),
        description: format!(
            "{} launch template(s) created or versioned with user data payload. \
             Malicious user data in launch templates persists execution across all \
             future instances launched from that template.",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Persistence".to_string(),
        mitre_technique: "T1059".to_string(),
        service: "EC2".to_string(),
        query: "eventName=CreateLaunchTemplate OR eventName=CreateLaunchTemplateVersion".to_string(),
    }]
}

/// EC-04: IMDSv2 Downgraded (httpTokens set to optional)
pub fn ec_04_imds_v2_downgraded(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("ModifyInstanceMetadataOptions") {
        Some(ids) => ids,
        None => return vec![],
    };

    let mut matching = vec![];
    for &id in ids {
        if store.get_record(id).is_some() {
            let params_str = store.get_request_parameters_str(id).unwrap_or_default();
            if params_str.contains("httpTokens") && params_str.contains("optional") {
                matching.push(id);
            }
        }
    }

    if matching.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "EC-04".to_string(),
        severity: Severity::High,
        title: "EC2 IMDSv2 Enforcement Disabled".to_string(),
        description: format!(
            "{} instance(s) had IMDSv2 downgraded to optional (IMDSv1 re-enabled). \
             IMDSv1 is vulnerable to SSRF attacks that allow credential theft from \
             the instance metadata service.",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Credential Access".to_string(),
        mitre_technique: "T1552.005".to_string(),
        service: "EC2".to_string(),
        query: "eventName=ModifyInstanceMetadataOptions".to_string(),
    }]
}

/// EC-05: Windows EC2 Instance Password Retrieved
pub fn ec_05_get_password_data(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("GetPasswordData") {
        Some(ids) => ids.to_vec(),
        None => return vec![],
    };

    if ids.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "EC-05".to_string(),
        severity: Severity::Medium,
        title: "EC2 Windows Instance Password Retrieved".to_string(),
        description: format!(
            "{} GetPasswordData call(s) retrieved the encrypted Windows administrator \
             password. An attacker with the instance key pair can decrypt this for \
             full RDP access.",
            ids.len()
        ),
        matching_count: 0,
        matching_record_ids: ids,
        metadata: HashMap::new(),
        mitre_tactic: "Credential Access".to_string(),
        mitre_technique: "T1078.004".to_string(),
        service: "EC2".to_string(),
        query: "eventName=GetPasswordData".to_string(),
    }]
}

/// EC-06: EC2 Instance Connect SSH Key Injected
pub fn ec_06_instance_connect(store: &Store) -> Vec<Alert> {
    let event_names = ["SendSSHPublicKey", "SendSerialConsoleSSHPublicKey"];
    let mut matching = vec![];

    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
            matching.extend_from_slice(ids);
        }
    }

    if matching.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "EC-06".to_string(),
        severity: Severity::High,
        title: "EC2 Instance Connect SSH Key Pushed".to_string(),
        description: format!(
            "{} ephemeral SSH public key(s) pushed to EC2 instances via Instance Connect. \
             Attackers use this to gain shell access without leaving persistent key pairs, \
             making it harder to detect in post-incident review.",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Lateral Movement".to_string(),
        mitre_technique: "T1098.004".to_string(),
        service: "EC2".to_string(),
        query: "eventName=SendSSHPublicKey OR eventName=SendSerialConsoleSSHPublicKey".to_string(),
    }]
}

/// EC-07: SSM Run Command Sent to EC2 Instances
pub fn ec_07_ssm_run_command(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("SendCommand") {
        Some(ids) => ids.to_vec(),
        None => return vec![],
    };

    if ids.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "EC-07".to_string(),
        severity: Severity::High,
        title: "SSM Run Command Sent".to_string(),
        description: format!(
            "{} SSM SendCommand event(s) detected. SSM Run Command provides remote code \
             execution on managed EC2 instances without requiring SSH or open ports, \
             and is commonly abused for post-compromise execution.",
            ids.len()
        ),
        matching_count: 0,
        matching_record_ids: ids,
        metadata: HashMap::new(),
        mitre_tactic: "Execution".to_string(),
        mitre_technique: "T1651".to_string(),
        service: "SSM".to_string(),
        query: "eventName=SendCommand".to_string(),
    }]
}

/// EC-08: EC2 Serial Console Access Enabled Account-Wide
pub fn ec_08_serial_console_enabled(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("EnableSerialConsoleAccess") {
        Some(ids) => ids.to_vec(),
        None => return vec![],
    };

    if ids.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "EC-08".to_string(),
        severity: Severity::Medium,
        title: "EC2 Serial Console Access Enabled".to_string(),
        description: format!(
            "{} event(s) enabled EC2 serial console access for the account. Serial console \
             bypasses all SSH key and network security controls, providing direct \
             low-level access to instance terminals.",
            ids.len()
        ),
        matching_count: 0,
        matching_record_ids: ids,
        metadata: HashMap::new(),
        mitre_tactic: "Defense Evasion".to_string(),
        mitre_technique: "T1078".to_string(),
        service: "EC2".to_string(),
        query: "eventName=EnableSerialConsoleAccess".to_string(),
    }]
}
