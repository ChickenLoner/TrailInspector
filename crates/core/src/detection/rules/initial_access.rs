use std::sync::Arc;
use crate::store::Store;
use crate::detection::Finding;
use super::window::{window_burst, Windows};

/// IA-01: Console Login Without MFA
pub fn ia_01_console_login_no_mfa(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("ConsoleLogin")?;

    let mut matching = vec![];
    for id in ids {
        if store.get_record(id).is_some() {
            // Check success
            let is_success = store.parse_response_elements(id)
                .and_then(|v| v.get("ConsoleLogin").and_then(|v| v.as_str()).map(|s| s == "Success"))
                .unwrap_or(false);

            if !is_success {
                continue;
            }

            // Check MFA not used
            let mfa_used = store.parse_additional_event_data(id)
                .and_then(|v| v.get("MFAUsed").and_then(|v| v.as_str()).map(|s| s.to_string()))
                .unwrap_or_else(|| "No".to_string());

            if mfa_used != "Yes" {
                matching.push(id);
            }
        }
    }

    if matching.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} successful console login(s) occurred without MFA. \
             Accounts without MFA are vulnerable to credential theft.",
            matching.len()
        ),
        matching,
        "eventName=ConsoleLogin",
    ))
}

/// IA-03: Root Account Usage
pub fn ia_03_root_usage(store: &Store) -> Option<Finding> {
    let ids = store.idx_identity_type.get("Root")?;

    if ids.is_empty() {
        return None;
    }

    let count = ids.len();
    Some(
        Finding::new(
            format!(
                "The root account performed {count} API call(s). Root usage is a high-risk indicator \
                 as root has unrestricted access to all AWS resources."
            ),
            ids.iter().collect(),
            "identityType=Root",
        )
        .meta("count", count.to_string()),
    )
}

/// IA-04: Failed Login Brute Force (≥5 failures within 10 min from same IP)
pub fn ia_04_brute_force(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("ConsoleLogin")?;

    // Failed logins that carry a source IP. Logins without one are dropped
    // rather than bucketed together — "no IP" is not an origin, and grouping
    // them would invent a brute-force source that does not exist.
    let failures: Vec<u32> = ids
        .iter()
        .filter(|&id| {
            store
                .get_record(id)
                .is_some_and(|r| r.record.source_ip_address.is_some())
                && store
                    .parse_response_elements(id)
                    .and_then(|v| {
                        v.get("ConsoleLogin").and_then(|v| v.as_str()).map(|s| s == "Failure")
                    })
                    .unwrap_or(false)
        })
        .collect();

    let threshold = 5;
    let burst = window_burst(
        store,
        failures,
        // Safe: `failures` only holds records with a source IP.
        |rec| Arc::clone(rec.record.source_ip_address.as_ref().unwrap()),
        threshold,
        10 * 60 * 1000,
        Windows::First,
    );

    if burst.is_empty() {
        return None;
    }

    // Build query: filter by IP if single offender, otherwise just eventName
    let query = match burst.keys.as_slice() {
        [only] => format!("eventName=ConsoleLogin sourceIPAddress={only}"),
        _ => "eventName=ConsoleLogin".to_string(),
    };

    let ips = burst.keys_joined();
    Some(
        Finding::new(
            format!(
                "≥{threshold} failed console logins within 10 minutes from the same source IP. \
                 Offending IPs: {ips}"
            ),
            burst.ids,
            query,
        )
        .meta("offending_ips", ips)
        .meta("threshold", threshold.to_string()),
    )
}
