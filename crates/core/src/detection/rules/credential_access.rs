use crate::store::Store;
use crate::detection::Finding;
use super::window::{identity_burst, Windows};

/// CA-02: Secrets Manager Bulk Access (>5 GetSecretValue in 10 min by same identity)
pub fn ca_02_secrets_bulk(store: &Store) -> Option<Finding> {
    let ids = store.idx_event_name.get("GetSecretValue")?;

    let threshold = 5;
    let burst = identity_burst(store, ids, threshold + 1, 10 * 60 * 1000, Windows::First);

    if burst.is_empty() {
        return None;
    }

    // If single offending identity, scope the query to it
    let query = burst.scoped_query("eventName=GetSecretValue");
    let identities = burst.keys_joined();

    Some(
        Finding::new(
            format!(
                "Identity accessed >{threshold}  secrets within 10 minutes. \
                 Bulk secret retrieval suggests credential harvesting. Identities: {identities}"
            ),
            burst.ids,
            query,
        )
        .meta("identities", identities),
    )
}

/// CA-05: Root Console Login (specific ConsoleLogin event from Root identity)
pub fn ca_05_root_console_login(store: &Store) -> Option<Finding> {
    let login_ids = store.idx_event_name.get("ConsoleLogin")?;

    let mut matching = vec![];
    for id in login_ids {
        if let Some(r) = store.get_record(id) {
            let is_root = r.record.user_identity.identity_type
                .as_deref()
                .map(|t| t == "Root")
                .unwrap_or(false);

            let is_success = store.parse_response_elements(id)
                .and_then(|v| v.get("ConsoleLogin").and_then(|v| v.as_str()).map(|s| s == "Success"))
                .unwrap_or(false);

            if is_root && is_success {
                matching.push(id);
            }
        }
    }

    if matching.is_empty() {
        return None;
    }

    Some(Finding::new(
        format!(
            "{} successful root account console login(s) detected. Root console access \
             should never occur in normal operations and indicates a critical security event.",
            matching.len()
        ),
        matching,
        "eventName=ConsoleLogin identityType=Root",
    ))
}

