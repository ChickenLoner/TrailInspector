use crate::store::Store;
use crate::detection::Finding;

/// NW-01: Security Group Ingress Open to 0.0.0.0/0 or ::/0
pub fn nw_01_sg_ingress_all(store: &Store) -> Option<Finding> {
    let event_names = ["AuthorizeSecurityGroupIngress"];
    let mut matching = vec![];

    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
            for id in ids {
                if store.get_record(id).is_some() {
                    let params_str = store.get_request_parameters_str(id).unwrap_or_default();
                    if params_str.contains("0.0.0.0/0") || params_str.contains("::/0") {
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
            "{} security group rule(s) were created allowing ingress from all IPs (0.0.0.0/0 or ::/0). \
             Open security groups expose instances to internet attacks.",
            matching.len()
        ),
        matching,
        "eventName=AuthorizeSecurityGroupIngress",
    ))
}

/// NW-02: Network ACL Entry Allows All Traffic
pub fn nw_02_nacl_allows_all(store: &Store) -> Option<Finding> {
    let event_names = ["CreateNetworkAclEntry", "ReplaceNetworkAclEntry"];
    let mut matching = vec![];

    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
            for id in ids {
                if store.get_record(id).is_some() {
                    let params_str = store.get_request_parameters_str(id).unwrap_or_default();
                    // Allow rule (not deny) with broad CIDR
                    if params_str.contains("0.0.0.0/0") || params_str.contains("::/0") {
                        // Check it's an allow rule
                        let is_allow = !params_str.contains("\"ruleAction\":\"deny\"")
                            && !params_str.contains("\"ruleAction\": \"deny\"");
                        if is_allow {
                            matching.push(id);
                        }
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
            "{} network ACL entry(ies) created allowing all traffic (0.0.0.0/0). \
             Permissive NACLs reduce network segmentation effectiveness.",
            matching.len()
        ),
        matching,
        "eventName=CreateNetworkAclEntry OR eventName=ReplaceNetworkAclEntry",
    ))
}

/// NW-04: Route Table Modified with Default Route (0.0.0.0/0)
pub fn nw_04_route_to_internet(store: &Store) -> Option<Finding> {
    let event_names = ["CreateRoute", "ReplaceRoute"];
    let mut matching = vec![];

    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
            for id in ids {
                if store.get_record(id).is_some() {
                    let params_str = store.get_request_parameters_str(id).unwrap_or_default();
                    if params_str.contains("0.0.0.0/0") || params_str.contains("::/0") {
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
            "{} route table modification(s) added a default route (0.0.0.0/0). \
             Default routes can expose private subnets to internet traffic.",
            matching.len()
        ),
        matching,
        "eventName=CreateRoute OR eventName=ReplaceRoute",
    ))
}

/// NW-07: Subnet Made Public (MapPublicIpOnLaunch enabled)
pub fn nw_07_subnet_public(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("ModifySubnetAttribute")?;

    let mut matching = vec![];
    for id in ids {
        let params_str = store.get_request_parameters_str(id).unwrap_or_default();
        if params_str.contains("mapPublicIpOnLaunch") && params_str.contains("\"value\":true") {
            matching.push(id);
        }
    }

    if matching.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} subnet(s) had MapPublicIpOnLaunch enabled. Instances launched in these \
             subnets will automatically receive public IP addresses.",
            matching.len()
        ),
        matching,
        "eventName=ModifySubnetAttribute",
    ))
}

