use std::sync::Arc;
use crate::store::Store;
use crate::detection::Finding;
use super::window::{window_burst, Windows};

/// DI-03: AccessDenied Spike (≥10 AccessDenied in 10 min by same identity)
pub fn di_03_access_denied_spike(store: &Store) -> Option<Finding> {
    let ids = store.idx_error_code.get("AccessDenied")?;

    let threshold = 10;
    // Unlike the other per-identity rules this one falls back to source IP
    // before "unknown": permission probing often comes from unauthenticated or
    // partially-resolved principals, and bucketing those all together would
    // merge unrelated probers into one alert.
    let burst = window_burst(
        store,
        ids,
        |rec| {
            rec.record.user_identity.identity_name()
                .or(rec.record.source_ip_address.as_ref())
                .cloned()
                .unwrap_or_else(|| Arc::from("unknown"))
        },
        threshold,
        10 * 60 * 1000,
        Windows::First,
    );

    if burst.is_empty() {
        return None;
    }

    // Scope to the specific identity if single offender
    let query = burst.scoped_query("errorCode=AccessDenied");
    let identities = burst.keys_joined();

    Some(
        Finding::new(
            format!(
                "≥{threshold} AccessDenied errors within 10 minutes by same identity. \
                 This pattern indicates systematic permission probing. Identities: {identities}"
            ),
            burst.ids,
            query,
        )
        .meta("identities", identities),
    )
}
