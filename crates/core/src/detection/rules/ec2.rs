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

