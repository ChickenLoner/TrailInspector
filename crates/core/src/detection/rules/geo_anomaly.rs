//! Geo-based anomaly detection rules.
//! These require a loaded GeoIpEngine — skipped automatically if none is provided.

use std::collections::{HashMap, HashSet};
use crate::store::Store;
use crate::detection::{Alert, Severity, scoped_ids};
use crate::geoip::GeoIpEngine;

/// GEO-01: Same identity accessed AWS from multiple countries
pub fn geo_01_multi_country(store: &Store, geoip: &GeoIpEngine) -> Vec<Alert> {
    geo_01_inner(store, |ip| geoip.lookup(ip).and_then(|i| i.country_code))
}

/// GEO-01 with the IP → country lookup injected, so the grouping logic is testable
/// without an MMDB file.
fn geo_01_inner(store: &Store, country_of: impl Fn(&str) -> Option<String>) -> Vec<Alert> {
    // Build identity → set of countries
    let mut by_identity: HashMap<String, HashSet<String>> = HashMap::new();
    let mut identity_event_ids: HashMap<String, Vec<u32>> = HashMap::new();

    for rec in &store.records {
        let ip = match &rec.record.source_ip_address {
            Some(ip) => ip.as_ref(),
            None => continue,
        };
        let country = match country_of(ip) {
            Some(cc) => cc,
            None => continue,
        };
        // Identities with neither an ARN nor a user name (AWSAccount, AWSService, Unknown)
        // cannot be told apart, so lumping them under one bucket would report two unrelated
        // callers as one person travelling. Skip them.
        let identity = match rec.record.user_identity.arn.as_deref()
            .or_else(|| rec.record.user_identity.user_name.as_deref())
        {
            Some(id) => id.to_string(),
            None => continue,
        };

        by_identity.entry(identity.clone()).or_default().insert(country);
        identity_event_ids.entry(identity).or_default().push(rec.id);
    }

    let mut matching: Vec<u32> = Vec::new();
    let mut affected: Vec<String> = Vec::new();
    let mut affected_identities: Vec<&str> = Vec::new();

    for (identity, countries) in &by_identity {
        if countries.len() >= 2 {
            if let Some(ids) = identity_event_ids.get(identity) {
                matching.extend_from_slice(ids);
            }
            affected_identities.push(identity.as_str());
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

    affected_identities.sort_unstable();
    let mut metadata = HashMap::new();
    metadata.insert("identities".to_string(), affected_identities.join(";"));

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
        matching_count: 0,
        matching_record_ids: matching,
        metadata,
        mitre_tactic: "Initial Access".to_string(),
        mitre_technique: "T1078".to_string(),
        service: "IAM".to_string(),
        // The rule covers every API call by the identity, not just console logins.
        query: String::new(),
    }]
}

/// GEO-02: Console login from a country not seen in prior API activity for that identity
pub fn geo_02_console_unusual_country(store: &Store, geoip: &GeoIpEngine) -> Vec<Alert> {
    let login_ids = scoped_ids(store, &["ConsoleLogin"], &["signin.amazonaws.com"], true);
    if login_ids.is_empty() {
        return vec![];
    }

    // Build per-identity baseline from non-login events
    let mut baseline: HashMap<String, HashSet<String>> = HashMap::new();
    for rec in &store.records {
        if rec.record.event_name.as_ref() == "ConsoleLogin" {
            continue;
        }
        let ip = match &rec.record.source_ip_address {
            Some(ip) => ip.as_ref(),
            None => continue,
        };
        if let Some(cc) = geoip.lookup(ip).and_then(|i| i.country_code) {
            let identity = rec.record.user_identity.arn.as_deref()
                .or_else(|| rec.record.user_identity.user_name.as_deref())
                .unwrap_or("unknown")
                .to_string();
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
            let identity = rec.record.user_identity.arn.as_deref()
                .or_else(|| rec.record.user_identity.user_name.as_deref())
                .unwrap_or("unknown")
                .to_string();

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
        matching_count: 0,
        matching_record_ids: matching,
        metadata: HashMap::new(),
        mitre_tactic: "Initial Access".to_string(),
        mitre_technique: "T1078.004".to_string(),
        service: "IAM".to_string(),
        query: "eventName=ConsoleLogin".to_string(),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CloudTrailRecord, IndexedRecord, UserIdentity};
    use std::sync::Arc;

    fn rec(id: u32, ip: &str, arn: Option<&str>, user: Option<&str>) -> IndexedRecord {
        IndexedRecord {
            id,
            timestamp: id as i64 * 1000,
            source_file: 0,
            record: CloudTrailRecord {
                event_time: Arc::from("2024-01-15T10:00:00Z"),
                event_source: Arc::from("s3.amazonaws.com"),
                event_name: Arc::from("ListBuckets"),
                aws_region: Arc::from("us-east-1"),
                source_ip_address: Some(Arc::from(ip)),
                user_agent: None,
                user_identity: UserIdentity {
                    identity_type: Some(Arc::from("IAMUser")),
                    principal_id: None,
                    arn: arn.map(Arc::from),
                    account_id: None,
                    access_key_id: None,
                    user_name: user.map(Arc::from),
                    session_context: None,
                    invoked_by: None,
                },
                request_parameters: None,
                response_elements: None,
                additional_event_data: None,
                error_code: None,
                error_message: None,
                request_id: None,
                event_id: None,
                event_type: None,
                read_only: None,
                management_event: None,
                recipient_account_id: None,
                event_category: None,
                shared_event_id: None,
                session_credential_from_console: None,
                resources: vec![],
            },
            request_params_ref: None,
            response_elements_ref: None,
            additional_event_data_ref: None,
        }
    }

    fn store_of(records: Vec<IndexedRecord>) -> Store {
        let mut store = Store::new();
        store.blob_store.seal().unwrap();
        store.records = records;
        store
    }

    fn country(ip: &str) -> Option<String> {
        match ip {
            "1.1.1.1" => Some("US".into()),
            "2.2.2.2" => Some("DE".into()),
            _ => None,
        }
    }

    #[test]
    fn geo_01_ignores_identities_without_arn_or_user_name() {
        // Two unrelated anonymous callers in two countries must not look like one traveller.
        let store = store_of(vec![rec(0, "1.1.1.1", None, None), rec(1, "2.2.2.2", None, None)]);
        assert!(geo_01_inner(&store, country).is_empty());
    }

    #[test]
    fn geo_01_fires_for_one_identity_in_two_countries() {
        let arn = Some("arn:aws:iam::123456789012:user/alice");
        let store = store_of(vec![rec(0, "1.1.1.1", arn, Some("alice")), rec(1, "2.2.2.2", arn, Some("alice"))]);
        let alerts = geo_01_inner(&store, country);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].query, "");
        assert_eq!(
            alerts[0].metadata.get("identities").map(String::as_str),
            Some("arn:aws:iam::123456789012:user/alice")
        );
    }
}
