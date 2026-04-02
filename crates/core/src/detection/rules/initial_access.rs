use std::collections::HashMap;
use crate::store::Store;
use crate::detection::{Alert, Severity};

/// IA-01: Console Login Without MFA
pub fn ia_01_console_login_no_mfa(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("ConsoleLogin") {
        Some(ids) => ids,
        None => return vec![],
    };

    let mut matching = vec![];
    for &id in ids {
        if let Some(r) = store.get_record(id) {
            // Check success
            let is_success = r.record.parse_response_elements()
                .and_then(|v| v.get("ConsoleLogin").and_then(|v| v.as_str()).map(|s| s == "Success"))
                .unwrap_or(false);

            if !is_success {
                continue;
            }

            // Check MFA not used
            let mfa_used = r.record.parse_additional_event_data()
                .and_then(|v| v.get("MFAUsed").and_then(|v| v.as_str()).map(|s| s.to_string()))
                .unwrap_or_else(|| "No".to_string());

            if mfa_used != "Yes" {
                matching.push(id);
            }
        }
    }

    if matching.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "IA-01".to_string(),
        severity: Severity::High,
        title: "Console Login Without MFA".to_string(),
        description: format!(
            "{} successful console login(s) occurred without MFA. \
             Accounts without MFA are vulnerable to credential theft.",
            matching.len()
        ),
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Initial Access".to_string(),
        mitre_technique: "T1078.004".to_string(),
        service: "IAM".to_string(),
        query: "eventName=ConsoleLogin".to_string(),
    }]
}

/// IA-03: Root Account Usage
pub fn ia_03_root_usage(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_identity_type.get("Root") {
        Some(ids) => ids.clone(),
        None => return vec![],
    };

    if ids.is_empty() {
        return vec![];
    }

    let mut meta = HashMap::new();
    meta.insert("count".to_string(), ids.len().to_string());

    vec![Alert {
        rule_id: "IA-03".to_string(),
        severity: Severity::Critical,
        title: "Root Account Usage Detected".to_string(),
        description: format!(
            "The root account performed {} API call(s). Root usage is a high-risk indicator \
             as root has unrestricted access to all AWS resources.",
            ids.len()
        ),
        matching_count: 0,
        matching_record_ids: ids,
        metadata: meta,
        mitre_tactic: "Initial Access".to_string(),
        mitre_technique: "T1078.004".to_string(),
        service: "IAM".to_string(),
        query: "identityType=Root".to_string(),
    }]
}

/// IA-04: Failed Login Brute Force (≥5 failures within 10 min from same IP)
pub fn ia_04_brute_force(store: &Store) -> Vec<Alert> {
    let ids = match store.idx_event_name.get("ConsoleLogin") {
        Some(ids) => ids,
        None => return vec![],
    };

    // Collect failure events grouped by source IP
    let mut by_ip: HashMap<String, Vec<(i64, u64)>> = HashMap::new();
    for &id in ids {
        if let Some(r) = store.get_record(id) {
            let is_failure = r.record.parse_response_elements()
                .and_then(|v| v.get("ConsoleLogin").and_then(|v| v.as_str()).map(|s| s == "Failure"))
                .unwrap_or(false);

            if is_failure {
                if let Some(ip) = &r.record.source_ip_address {
                    by_ip.entry(ip.clone()).or_default().push((r.timestamp, id));
                }
            }
        }
    }

    let window_ms = 10 * 60 * 1000; // 10 minutes
    let threshold = 5;
    let mut all_matching: Vec<u64> = vec![];
    let mut meta = HashMap::new();
    let mut offending_ips: Vec<String> = vec![];

    for (ip, mut events) in by_ip {
        events.sort_unstable_by_key(|(ts, _)| *ts);
        // Sliding window
        let mut start = 0;
        for end in 0..events.len() {
            while events[end].0 - events[start].0 > window_ms {
                start += 1;
            }
            let window_count = end - start + 1;
            if window_count >= threshold {
                // Collect all IDs in this window
                let window_ids: Vec<u64> = events[start..=end]
                    .iter()
                    .map(|(_, id)| *id)
                    .collect();
                for wid in &window_ids {
                    if !all_matching.contains(wid) {
                        all_matching.push(*wid);
                    }
                }
                if !offending_ips.contains(&ip) {
                    offending_ips.push(ip.clone());
                }
                break;
            }
        }
    }

    if all_matching.is_empty() {
        return vec![];
    }

    meta.insert("offending_ips".to_string(), offending_ips.join(", "));
    meta.insert("threshold".to_string(), threshold.to_string());

    // Build query: filter by IP if single offender, otherwise just eventName
    let query = if offending_ips.len() == 1 {
        format!("eventName=ConsoleLogin sourceIPAddress={}", offending_ips[0])
    } else {
        "eventName=ConsoleLogin".to_string()
    };

    vec![Alert {
        rule_id: "IA-04".to_string(),
        severity: Severity::High,
        title: "Brute Force Login Attempt Detected".to_string(),
        description: format!(
            "≥{} failed console logins within 10 minutes from the same source IP. \
             Offending IPs: {}",
            threshold,
            offending_ips.join(", ")
        ),
        matching_count: 0,
        matching_record_ids: all_matching,
        metadata: meta,
        mitre_tactic: "Initial Access".to_string(),
        mitre_technique: "T1110.001".to_string(),
        service: "IAM".to_string(),
        query,
    }]
}
