//! Sliding-window burst detection, shared by the threshold rules.
//!
//! Seven rules asked the same question — "did any one actor do this N times
//! inside a T-minute window?" — and each had its own copy of the group-by,
//! sort, two-pointer scan, and dedup. This is that loop, once.

use std::collections::HashMap;
use std::sync::Arc;
use roaring::RoaringBitmap;
use crate::model::IndexedRecord;
use crate::store::Store;

/// Records implicated in at least one qualifying window, plus the actors
/// responsible.
pub(crate) struct Burst {
    /// Matching record ids, ascending. Empty when nothing met the threshold.
    pub ids: Vec<u32>,
    /// Group keys that produced a qualifying window, sorted for stable output.
    pub keys: Vec<Arc<str>>,
}

impl Burst {
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// `", "`-joined keys, for alert descriptions and metadata.
    pub fn keys_joined(&self) -> String {
        self.keys.iter().map(|k| k.as_ref()).collect::<Vec<_>>().join(", ")
    }

    /// Narrow `base` to the single responsible identity when there is exactly
    /// one, so the alert's "view evidence" query lands on just that actor's
    /// events. Falls back to `base` when several actors are involved — a query
    /// scoped to one of them would misrepresent the alert.
    ///
    /// Picks `arn=` or `userName=` by inspecting the key, matching how
    /// [`crate::model::UserIdentity::identity_name`] built it.
    pub fn scoped_query(&self, base: &str) -> String {
        match self.keys.as_slice() {
            [only] if only.starts_with("arn:") => format!("{base} arn=\"{only}\""),
            [only] => format!("{base} userName=\"{only}\""),
            _ => base.to_string(),
        }
    }
}

/// How many qualifying windows to take from each group.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Windows {
    /// Stop at the first window that qualifies. The group is already flagged;
    /// scanning on only adds overlapping ids for the same finding.
    First,
    /// Collect every qualifying window. Used where the alert is about the
    /// full extent of the activity rather than one actor crossing a line.
    All,
}

/// Group `ids` by `key_of`, then per group report the records inside windows of
/// `window_ms` holding at least `min_count` events.
///
/// `min_count` is inclusive — a rule written as `> 5` passes `6`.
///
/// Dedup goes through a `RoaringBitmap`: windows overlap heavily both within and
/// across groups, and `insert` is O(1)-ish where the previous `Vec::contains`
/// scan was linear in the matches found so far. The bitmap also fixes the id
/// order, which used to follow `HashMap` iteration and so varied between runs.
pub(crate) fn window_burst<I, K>(
    store: &Store,
    ids: I,
    key_of: K,
    min_count: usize,
    window_ms: i64,
    windows: Windows,
) -> Burst
where
    I: IntoIterator<Item = u32>,
    K: Fn(&IndexedRecord) -> Arc<str>,
{
    let mut by_key: HashMap<Arc<str>, Vec<(i64, u32)>> = HashMap::new();
    for id in ids {
        if let Some(rec) = store.get_record(id) {
            by_key.entry(key_of(rec)).or_default().push((rec.timestamp, id));
        }
    }

    let mut matched = RoaringBitmap::new();
    let mut keys: Vec<Arc<str>> = Vec::new();

    for (key, mut events) in by_key {
        events.sort_unstable_by_key(|(ts, _)| *ts);

        let mut qualified = false;
        let mut start = 0;
        for end in 0..events.len() {
            while events[end].0 - events[start].0 > window_ms {
                start += 1;
            }
            if end - start + 1 >= min_count {
                for (_, id) in &events[start..=end] {
                    matched.insert(*id);
                }
                qualified = true;
                if windows == Windows::First {
                    break;
                }
            }
        }

        if qualified {
            keys.push(key);
        }
    }

    keys.sort_unstable();
    Burst { ids: matched.iter().collect(), keys }
}

/// `window_burst` grouped by identity (ARN, else userName, else `"unknown"`) —
/// the shape six of the seven callers wanted.
pub(crate) fn identity_burst<I>(
    store: &Store,
    ids: I,
    min_count: usize,
    window_ms: i64,
    windows: Windows,
) -> Burst
where
    I: IntoIterator<Item = u32>,
{
    window_burst(
        store,
        ids,
        |rec| rec.record.user_identity.identity_key(),
        min_count,
        window_ms,
        windows,
    )
}
