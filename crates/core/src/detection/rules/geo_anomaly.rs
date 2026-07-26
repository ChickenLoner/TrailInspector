//! Geo-based anomaly detection rules.
//! These require a loaded GeoIpEngine — skipped automatically if none is provided.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use crate::store::Store;
use crate::detection::Finding;
use crate::geoip::GeoIpEngine;

/// GEO-01: Same identity accessed AWS from multiple countries
pub fn geo_01_multi_country(store: &Store, geoip: &GeoIpEngine) -> Option<Finding> {
    // Build identity → set of countries
    let mut by_identity: HashMap<Arc<str>, HashSet<String>> = HashMap::new();
    let mut identity_event_ids: HashMap<Arc<str>, Vec<u32>> = HashMap::new();

    for rec in &store.records {
        let ip = match &rec.record.source_ip_address {
            Some(ip) => ip.as_ref(),
            None => continue,
        };
        let country = match geoip.lookup(ip).and_then(|i| i.country_code) {
            Some(cc) => cc,
            None => continue,
        };
        let identity = rec.record.user_identity.identity_key();

        by_identity.entry(identity.clone()).or_default().insert(country);
        identity_event_ids.entry(identity).or_default().push(rec.id);
    }

    let mut matching: Vec<u32> = Vec::new();
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
        return None;
    }

    Some(Finding::new(
        format!(
            "{} identity/identities made API calls from 2+ distinct countries. \
             This may indicate credential sharing, VPN use, or account compromise. \
             Affected: {}",
            affected.len(),
            affected.join("; ")
        ),
        matching,
        "eventName=ConsoleLogin",
    ))
}

/// GEO-02: Console login from a country not seen in prior API activity for that identity
pub fn geo_02_console_unusual_country(store: &Store, geoip: &GeoIpEngine) -> Option<Finding> {
    let login_ids = store.idx_event_name.get("ConsoleLogin")?.clone();

    // Build per-identity baseline from non-login events
    let mut baseline: HashMap<Arc<str>, HashSet<String>> = HashMap::new();
    for rec in &store.records {
        if rec.record.event_name.as_ref() == "ConsoleLogin" {
            continue;
        }
        let ip = match &rec.record.source_ip_address {
            Some(ip) => ip.as_ref(),
            None => continue,
        };
        if let Some(cc) = geoip.lookup(ip).and_then(|i| i.country_code) {
            let identity = rec.record.user_identity.identity_key();
            baseline.entry(identity).or_default().insert(cc);
        }
    }

    let mut matching: Vec<u32> = Vec::new();
    let mut details: Vec<String> = Vec::new();

    for id in &login_ids {
        if let Some(rec) = store.get_record(id) {
            let ip = match &rec.record.source_ip_address {
                Some(ip) => ip.as_ref(),
                None => continue,
            };
            let login_country = match geoip.lookup(ip).and_then(|i| i.country_code) {
                Some(cc) => cc,
                None => continue,
            };
            let identity = rec.record.user_identity.identity_key();

            // Only flag if identity has a baseline AND login country is not in it
            if let Some(seen) = baseline.get(&identity) {
                if !seen.contains(&login_country) {
                    matching.push(id);
                    details.push(format!("{} from {}", identity, login_country));
                }
            }
        }
    }

    if matching.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} console login(s) originated from a country not seen in the identity's \
             prior API activity. This strongly suggests account compromise or credential theft. \
             Logins: {}",
            matching.len(),
            details.join("; ")
        ),
        matching,
        "eventName=ConsoleLogin",
    ))
}
