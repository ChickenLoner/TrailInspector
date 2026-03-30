use std::collections::HashMap;
use crate::store::Store;
use crate::detection::{Alert, Severity};

/// NW-01: Security Group Ingress Open to 0.0.0.0/0 or ::/0
pub fn nw_01_sg_ingress_all(store: &Store) -> Vec<Alert> {
    let event_names = ["AuthorizeSecurityGroupIngress"];
    let mut matching = vec![];

    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
            for &id in ids {
                if let Some(r) = store.get_record(id) {
                    let params_str = r.record.request_parameters
                        .as_ref()
                        .map(|v| v.to_string())
                        .unwrap_or_default();
                    if params_str.contains("0.0.0.0/0") || params_str.contains("::/0") {
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
        rule_id: "NW-01".to_string(),
        severity: Severity::High,
        title: "Security Group Opened to All Traffic (0.0.0.0/0)".to_string(),
        description: format!(
            "{} security group rule(s) were created allowing ingress from all IPs (0.0.0.0/0 or ::/0). \
             Open security groups expose instances to internet attacks.",
            matching.len()
        ),
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Defense Evasion".to_string(),
        mitre_technique: "T1562.007".to_string(),
        service: "VPC".to_string(),
        query: "eventName=AuthorizeSecurityGroupIngress".to_string(),
    }]
}

/// NW-02: Network ACL Entry Allows All Traffic
pub fn nw_02_nacl_allows_all(store: &Store) -> Vec<Alert> {
    let event_names = ["CreateNetworkAclEntry", "ReplaceNetworkAclEntry"];
    let mut matching = vec![];

    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
            for &id in ids {
                if let Some(r) = store.get_record(id) {
                    let params_str = r.record.request_parameters
                        .as_ref()
                        .map(|v| v.to_string())
                        .unwrap_or_default();
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
        return vec![];
    }

    vec![Alert {
        rule_id: "NW-02".to_string(),
        severity: Severity::Medium,
        title: "Network ACL Allows All Traffic".to_string(),
        description: format!(
            "{} network ACL entry(ies) created allowing all traffic (0.0.0.0/0). \
             Permissive NACLs reduce network segmentation effectiveness.",
            matching.len()
        ),
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Defense Evasion".to_string(),
        mitre_technique: "T1562.007".to_string(),
        service: "VPC".to_string(),
        query: "eventName=CreateNetworkAclEntry OR eventName=ReplaceNetworkAclEntry".to_string(),
    }]
}

/// NW-03: Internet Gateway Created and Attached
pub fn nw_03_igw_created(store: &Store) -> Vec<Alert> {
    let event_names = ["CreateInternetGateway", "AttachInternetGateway"];
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
        rule_id: "NW-03".to_string(),
        severity: Severity::Info,
        title: "Internet Gateway Created or Attached".to_string(),
        description: format!(
            "{} internet gateway event(s) detected. New internet gateways may indicate \
             unauthorized VPC exposure to the internet.",
            matching.len()
        ),
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Defense Evasion".to_string(),
        mitre_technique: "T1562.007".to_string(),
        service: "VPC".to_string(),
        query: "eventName=CreateInternetGateway OR eventName=AttachInternetGateway".to_string(),
    }]
}

/// NW-04: Route Table Modified with Default Route (0.0.0.0/0)
pub fn nw_04_route_to_internet(store: &Store) -> Vec<Alert> {
    let event_names = ["CreateRoute", "ReplaceRoute"];
    let mut matching = vec![];

    for name in &event_names {
        if let Some(ids) = store.idx_event_name.get(*name) {
            for &id in ids {
                if let Some(r) = store.get_record(id) {
                    let params_str = r.record.request_parameters
                        .as_ref()
                        .map(|v| v.to_string())
                        .unwrap_or_default();
                    if params_str.contains("0.0.0.0/0") || params_str.contains("::/0") {
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
        rule_id: "NW-04".to_string(),
        severity: Severity::Medium,
        title: "Default Route Added to Route Table".to_string(),
        description: format!(
            "{} route table modification(s) added a default route (0.0.0.0/0). \
             Default routes can expose private subnets to internet traffic.",
            matching.len()
        ),
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Defense Evasion".to_string(),
        mitre_technique: "T1562.007".to_string(),
        service: "VPC".to_string(),
        query: "eventName=CreateRoute OR eventName=ReplaceRoute".to_string(),
    }]
}

/// NW-05: VPC Peering Connection Created
pub fn nw_05_vpc_peering_created(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("CreateVpcPeeringConnection") {
        Some(ids) => ids.clone(),
        None => return vec![],
    };

    if ids.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "NW-05".to_string(),
        severity: Severity::Info,
        title: "VPC Peering Connection Created".to_string(),
        description: format!(
            "{} VPC peering connection(s) created. VPC peering can extend network \
             access between previously isolated environments.",
            ids.len()
        ),
        matching_record_ids: ids,
        metadata: HashMap::new(),
        mitre_tactic: "Lateral Movement".to_string(),
        mitre_technique: "T1021".to_string(),
        service: "VPC".to_string(),
        query: "eventName=CreateVpcPeeringConnection".to_string(),
    }]
}

/// NW-06: Security Group Deleted
pub fn nw_06_sg_deleted(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("DeleteSecurityGroup") {
        Some(ids) => ids.clone(),
        None => return vec![],
    };

    if ids.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "NW-06".to_string(),
        severity: Severity::Low,
        title: "Security Group Deleted".to_string(),
        description: format!(
            "{} security group(s) deleted. Security group deletion can expose \
             instances that relied on those rules for protection.",
            ids.len()
        ),
        matching_record_ids: ids,
        metadata: HashMap::new(),
        mitre_tactic: "Defense Evasion".to_string(),
        mitre_technique: "T1562.007".to_string(),
        service: "VPC".to_string(),
        query: "eventName=DeleteSecurityGroup".to_string(),
    }]
}

/// NW-07: Subnet Made Public (MapPublicIpOnLaunch enabled)
pub fn nw_07_subnet_public(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("ModifySubnetAttribute") {
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
            if params_str.contains("mapPublicIpOnLaunch") && params_str.contains("\"value\":true") {
                matching.push(id);
            }
        }
    }

    if matching.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "NW-07".to_string(),
        severity: Severity::Medium,
        title: "Subnet Auto-Assign Public IP Enabled".to_string(),
        description: format!(
            "{} subnet(s) had MapPublicIpOnLaunch enabled. Instances launched in these \
             subnets will automatically receive public IP addresses.",
            matching.len()
        ),
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Defense Evasion".to_string(),
        mitre_technique: "T1562.007".to_string(),
        service: "VPC".to_string(),
        query: "eventName=ModifySubnetAttribute".to_string(),
    }]
}

/// NW-08: NAT Gateway Deleted
pub fn nw_08_nat_deleted(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("DeleteNatGateway") {
        Some(ids) => ids.clone(),
        None => return vec![],
    };

    if ids.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "NW-08".to_string(),
        severity: Severity::Low,
        title: "NAT Gateway Deleted".to_string(),
        description: format!(
            "{} NAT gateway(s) deleted. Removing NAT gateways can disrupt outbound \
             internet access for private subnets.",
            ids.len()
        ),
        matching_record_ids: ids,
        metadata: HashMap::new(),
        mitre_tactic: "Impact".to_string(),
        mitre_technique: "T1485".to_string(),
        service: "VPC".to_string(),
        query: "eventName=DeleteNatGateway".to_string(),
    }]
}
