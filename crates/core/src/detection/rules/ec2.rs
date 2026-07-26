use crate::store::Store;
use crate::detection::Finding;

/// EC-01: EC2 User Data Modified on Existing Instance
pub fn ec_01_userdata_modified(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("ModifyInstanceAttribute")?;

    let mut matching = vec![];
    for id in ids {
        if store.get_record(id).is_some() {
            let params_str = store.get_request_parameters_str(id).unwrap_or_default();
            if params_str.contains("userData") {
                matching.push(id);
            }
        }
    }

    if matching.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} EC2 instance(s) had user data modified via ModifyInstanceAttribute. \
             Attackers inject reverse shells or backdoors into user data to execute \
             on the next instance start.",
            matching.len()
        ),
        matching,
        "eventName=ModifyInstanceAttribute",
    ))
}

/// EC-02: EC2 Key Pair Created
pub fn ec_02_keypair_created(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("CreateKeyPair")?;

    if ids.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} EC2 key pair(s) created. New key pairs establish persistent SSH access \
             to any instance configured to accept them.",
            ids.len()
        ),
        ids.iter().collect(),
        "eventName=CreateKeyPair",
    ))
}

/// EC-03: Launch Template Created or Updated with User Data
pub fn ec_03_launch_template_userdata(store: &Store) -> Option<Finding> {
    let event_names = ["CreateLaunchTemplate", "CreateLaunchTemplateVersion"];
    let mut matching = vec![];

    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
            for id in ids {
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
        return None;
    }

    Some(Finding::new(
        format!(
            "{} launch template(s) created or versioned with user data payload. \
             Malicious user data in launch templates persists execution across all \
             future instances launched from that template.",
            matching.len()
        ),
        matching,
        "eventName=CreateLaunchTemplate OR eventName=CreateLaunchTemplateVersion",
    ))
}

/// EC-04: IMDSv2 Downgraded (httpTokens set to optional)
pub fn ec_04_imds_v2_downgraded(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("ModifyInstanceMetadataOptions")?;

    let mut matching = vec![];
    for id in ids {
        if store.get_record(id).is_some() {
            let params_str = store.get_request_parameters_str(id).unwrap_or_default();
            if params_str.contains("httpTokens") && params_str.contains("optional") {
                matching.push(id);
            }
        }
    }

    if matching.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} instance(s) had IMDSv2 downgraded to optional (IMDSv1 re-enabled). \
             IMDSv1 is vulnerable to SSRF attacks that allow credential theft from \
             the instance metadata service.",
            matching.len()
        ),
        matching,
        "eventName=ModifyInstanceMetadataOptions",
    ))
}

/// EC-05: Windows EC2 Instance Password Retrieved
pub fn ec_05_get_password_data(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("GetPasswordData")?;

    if ids.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} GetPasswordData call(s) retrieved the encrypted Windows administrator \
             password. An attacker with the instance key pair can decrypt this for \
             full RDP access.",
            ids.len()
        ),
        ids.iter().collect(),
        "eventName=GetPasswordData",
    ))
}

/// EC-06: EC2 Instance Connect SSH Key Injected
pub fn ec_06_instance_connect(store: &Store) -> Option<Finding> {
    let event_names = ["SendSSHPublicKey", "SendSerialConsoleSSHPublicKey"];
    let mut matching = vec![];

    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
            matching.extend(ids);
        }
    }

    if matching.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} ephemeral SSH public key(s) pushed to EC2 instances via Instance Connect. \
             Attackers use this to gain shell access without leaving persistent key pairs, \
             making it harder to detect in post-incident review.",
            matching.len()
        ),
        matching,
        "eventName=SendSSHPublicKey OR eventName=SendSerialConsoleSSHPublicKey",
    ))
}

/// EC-07: SSM Run Command Sent to EC2 Instances
pub fn ec_07_ssm_run_command(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("SendCommand")?;

    if ids.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} SSM SendCommand event(s) detected. SSM Run Command provides remote code \
             execution on managed EC2 instances without requiring SSH or open ports, \
             and is commonly abused for post-compromise execution.",
            ids.len()
        ),
        ids.iter().collect(),
        "eventName=SendCommand",
    ))
}

/// EC-08: EC2 Serial Console Access Enabled Account-Wide
pub fn ec_08_serial_console_enabled(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("EnableSerialConsoleAccess")?;

    if ids.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} event(s) enabled EC2 serial console access for the account. Serial console \
             bypasses all SSH key and network security controls, providing direct \
             low-level access to instance terminals.",
            ids.len()
        ),
        ids.iter().collect(),
        "eventName=EnableSerialConsoleAccess",
    ))
}
