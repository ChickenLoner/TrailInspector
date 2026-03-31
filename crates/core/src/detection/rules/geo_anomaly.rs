//! Geo-based anomaly detection rules.
//! These require a loaded GeoIpEngine — skipped automatically if none is provided.

use std::collections::{HashMap, HashSet};
use crate::store::Store;
use crate::detection::{Alert, Severity};
use crate::geoip::GeoIpEngine;

/// GEO-01: Same identity accessed AWS from multiple countries
pub fn geo_01_multi_country(store: &Store, geoip: &GeoIpEngine) -> Vec<Alert> {
    // Build identity → set of countries
    let mut by_identity: HashMap<String, HashSet<String>> = HashMap::new();
    let mut identity_event_ids: HashMap<String, Vec<u64>> = HashMap::new();

    for rec in &store.records {
        let ip = match &rec.record.source_ip_address {
            Some(ip) => ip.clone(),
            None => continue,
        };
        let country = match geoip.lookup(&ip).and_then(|i| i.country_code) {
            Some(cc) => cc,
            None => continue,
        };
        let identity = rec.record.user_identity.arn
            .clone()
            .or_else(|| rec.record.user_identity.user_name.clone())
            .unwrap_or_else(|| "unknown".to_string());

        by_identity.entry(identity.clone()).or_default().insert(country);
        identity_event_ids.entry(identity).or_default().push(rec.id);
    }

    let mut matching: Vec<u64> = Vec::new();
    let mut affected: Vec<String> = Vec::new();

    for (identity, countries) in &by_identity {
        if countries.len() >= 2 {
            if let Some(ids) = identity_event_ids.get(identity) {
                matching.extend_from_slice(ids);
            }
            affected.push(format!(
                "{} ({})",
                identity,
                countries.iter().cloned().collect::<Vec<_>>().join(", ")
            ));
        }
    }

    if matching.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "GEO-01".to_string(),
        severity: Severity::Medium,
        title: "Identity Active from Multiple Countries".to_string(),
        description: format!(
            "{} identity/identities made API calls from 2+ distinct countries. \
             This may indicate credential sharing, VPN use, or account compromise. \
             Affected: {}",
            affected.len(),
            affected.join("; ")
        ),
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Initial Access".to_string(),
        mitre_technique: "T1078".to_string(),
        service: "IAM".to_string(),
        query: "eventName=ConsoleLogin".to_string(),
    }]
}

/// GEO-02: Console login from a country not seen in prior API activity for that identity
pub fn geo_02_console_unusual_country(store: &Store, geoip: &GeoIpEngine) -> Vec<Alert> {
    let login_ids = match store.idx_event_name.get("ConsoleLogin") {
        Some(ids) => ids.clone(),
        None => return vec![],
    };

    // Build per-identity baseline from non-login events
    let mut baseline: HashMap<String, HashSet<String>> = HashMap::new();
    for rec in &store.records {
        if rec.record.event_name == "ConsoleLogin" {
            continue;
        }
        let ip = match &rec.record.source_ip_address {
            Some(ip) => ip.clone(),
            None => continue,
        };
        if let Some(cc) = geoip.lookup(&ip).and_then(|i| i.country_code) {
            let identity = rec.record.user_identity.arn
                .clone()
                .or_else(|| rec.record.user_identity.user_name.clone())
                .unwrap_or_else(|| "unknown".to_string());
            baseline.entry(identity).or_default().insert(cc);
        }
    }

    let mut matching: Vec<u64> = Vec::new();
    let mut details: Vec<String> = Vec::new();

    for id in &login_ids {
        if let Some(rec) = store.get_record(*id) {
            let ip = match &rec.record.source_ip_address {
                Some(ip) => ip.clone(),
                None => continue,
            };
            let login_country = match geoip.lookup(&ip).and_then(|i| i.country_code) {
                Some(cc) => cc,
                None => continue,
            };
            let identity = rec.record.user_identity.arn
                .clone()
                .or_else(|| rec.record.user_identity.user_name.clone())
                .unwrap_or_else(|| "unknown".to_string());

            // Only flag if identity has a baseline AND login country is not in it
            if let Some(seen) = baseline.get(&identity) {
                if !seen.contains(&login_country) {
                    matching.push(*id);
                    details.push(format!("{} from {}", identity, login_country));
                }
            }
        }
    }

    if matching.is_empty() {
        return vec![];
    }

    vec![Alert {
        rule_id: "GEO-02".to_string(),
        severity: Severity::High,
        title: "Console Login from Unusual Country".to_string(),
        description: format!(
            "{} console login(s) originated from a country not seen in the identity's \
             prior API activity. This strongly suggests account compromise or credential theft. \
             Logins: {}",
            matching.len(),
            details.join("; ")
        ),
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Initial Access".to_string(),
        mitre_technique: "T1078.004".to_string(),
        service: "IAM".to_string(),
        query: "eventName=ConsoleLogin".to_string(),
    }]
}
