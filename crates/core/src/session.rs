//! Session grouping engine.
//!
//! Groups CloudTrail events into "sessions" — continuous activity windows keyed by
//! `(identity, source_ip)`. A new session starts when the gap between consecutive
//! events for the same key exceeds `GAP_MS` (default 30 minutes).

use std::collections::{HashMap, HashSet};
use crate::store::Store;
use crate::detection::Alert;

const GAP_MS: i64 = 30 * 60 * 1_000; // 30 minutes

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: u32,
    /// ARN, userName, principalId, or "unknown"
    pub identity_key: String,
    pub source_ip: String,
    pub first_event_ms: i64,
    pub last_event_ms: i64,
    pub event_count: usize,
    /// Record IDs (in time order)
    pub event_ids: Vec<u64>,
    pub error_count: usize,
    pub unique_event_names: Vec<String>,
    pub unique_regions: Vec<String>,
}

impl Session {
    /// Duration in milliseconds
    pub fn duration_ms(&self) -> i64 {
        self.last_event_ms - self.first_event_ms
    }
}

/// Paginated session list result
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionPage {
    pub sessions: Vec<SessionSummary>,
    pub total: usize,
    pub page: usize,
    pub page_size: usize,
}

/// Lightweight summary for the list view (no event_ids)
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSummary {
    pub id: u32,
    pub identity_key: String,
    pub source_ip: String,
    pub first_event_ms: i64,
    pub last_event_ms: i64,
    pub duration_ms: i64,
    pub event_count: usize,
    pub error_count: usize,
    pub unique_event_names: Vec<String>,
    pub unique_regions: Vec<String>,
}

/// A single event in a session timeline
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionEvent {
    pub id: u64,
    pub timestamp_ms: i64,
    pub event_time: String,
    pub event_name: String,
    pub event_source: String,
    pub aws_region: String,
    pub source_ip: Option<String>,
    pub error_code: Option<String>,
    pub user_agent: Option<String>,
}

/// Full session detail with paginated events
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionDetail {
    pub id: u32,
    pub identity_key: String,
    pub source_ip: String,
    pub first_event_ms: i64,
    pub last_event_ms: i64,
    pub duration_ms: i64,
    pub event_count: usize,
    pub error_count: usize,
    pub unique_event_names: Vec<String>,
    pub unique_regions: Vec<String>,
    /// Paginated event slice
    pub events: Vec<SessionEvent>,
    pub events_page: usize,
    pub events_page_size: usize,
    pub events_total: usize,
}

// ---------------------------------------------------------------------------
// SessionIndex
// ---------------------------------------------------------------------------

pub struct SessionIndex {
    pub sessions: Vec<Session>,
    pub by_identity: HashMap<String, Vec<u32>>,
    pub by_ip: HashMap<String, Vec<u32>>,
}

impl SessionIndex {
    /// Build session index from store. O(n) over time-sorted records.
    pub fn build(store: &Store) -> Self {
        // active_sessions: (identity, ip) -> session_id
        let mut active: HashMap<(String, String), u32> = HashMap::new();
        let mut sessions: Vec<Session> = Vec::new();

        for &record_id in &store.time_sorted_ids {
            let rec = match store.get_record(record_id) {
                Some(r) => r,
                None => continue,
            };

            let identity_key = identity_key_for(rec);
            let source_ip = rec.record.source_ip_address
                .as_deref()
                .unwrap_or("unknown")
                .to_string();
            let ts = rec.timestamp;

            let key = (identity_key.clone(), source_ip.clone());

            let session_id = if let Some(&sid) = active.get(&key) {
                let sess = &sessions[sid as usize];
                if ts - sess.last_event_ms <= GAP_MS {
                    Some(sid)
                } else {
                    active.remove(&key);
                    None
                }
            } else {
                None
            };

            let sid = if let Some(sid) = session_id {
                sid
            } else {
                // New session
                let sid = sessions.len() as u32;
                sessions.push(Session {
                    id: sid,
                    identity_key: identity_key.clone(),
                    source_ip: source_ip.clone(),
                    first_event_ms: ts,
                    last_event_ms: ts,
                    event_count: 0,
                    event_ids: Vec::new(),
                    error_count: 0,
                    unique_event_names: Vec::new(),
                    unique_regions: Vec::new(),
                });
                active.insert(key, sid);
                sid
            };

            let sess = &mut sessions[sid as usize];
            sess.last_event_ms = ts;
            sess.event_count += 1;
            sess.event_ids.push(record_id);

            if rec.record.error_code.is_some() {
                sess.error_count += 1;
            }

            let event_name = &rec.record.event_name;
            if !sess.unique_event_names.contains(event_name) {
                sess.unique_event_names.push(event_name.clone());
            }
            let region = &rec.record.aws_region;
            if !sess.unique_regions.contains(region) {
                sess.unique_regions.push(region.clone());
            }
        }

        // Build secondary indexes
        let mut by_identity: HashMap<String, Vec<u32>> = HashMap::new();
        let mut by_ip: HashMap<String, Vec<u32>> = HashMap::new();
        for sess in &sessions {
            by_identity.entry(sess.identity_key.clone()).or_default().push(sess.id);
            by_ip.entry(sess.source_ip.clone()).or_default().push(sess.id);
        }

        SessionIndex { sessions, by_identity, by_ip }
    }

    // -----------------------------------------------------------------------
    // Query methods
    // -----------------------------------------------------------------------

    pub fn list_sessions(
        &self,
        page: usize,
        page_size: usize,
        sort_by: &str,
        filter_identity: Option<&str>,
        filter_ip: Option<&str>,
        time_range: Option<(i64, i64)>,
    ) -> SessionPage {
        let mut sessions: Vec<&Session> = self.sessions.iter()
            .filter(|s| {
                if let Some(id) = filter_identity {
                    if !s.identity_key.to_lowercase().contains(&id.to_lowercase()) {
                        return false;
                    }
                }
                if let Some(ip) = filter_ip {
                    if !s.source_ip.contains(ip) {
                        return false;
                    }
                }
                // Overlap check: session must overlap [start_ms, end_ms]
                if let Some((start_ms, end_ms)) = time_range {
                    if s.last_event_ms < start_ms || s.first_event_ms > end_ms {
                        return false;
                    }
                }
                true
            })
            .collect();

        match sort_by {
            "duration" => sessions.sort_by(|a, b| b.duration_ms().cmp(&a.duration_ms())),
            "events"   => sessions.sort_by(|a, b| b.event_count.cmp(&a.event_count)),
            "errors"   => sessions.sort_by(|a, b| b.error_count.cmp(&a.error_count)),
            "first"    => sessions.sort_by(|a, b| b.first_event_ms.cmp(&a.first_event_ms)),
            _          => sessions.sort_by(|a, b| b.first_event_ms.cmp(&a.first_event_ms)),
        }

        let total = sessions.len();
        let start = page * page_size;
        let page_sessions: Vec<SessionSummary> = sessions
            .into_iter()
            .skip(start)
            .take(page_size)
            .map(session_to_summary)
            .collect();

        SessionPage {
            sessions: page_sessions,
            total,
            page,
            page_size,
        }
    }

    pub fn get_session_detail(
        &self,
        store: &Store,
        session_id: u32,
        events_page: usize,
        events_page_size: usize,
    ) -> Option<SessionDetail> {
        let sess = self.sessions.get(session_id as usize)?;
        let events_total = sess.event_ids.len();
        let start = events_page * events_page_size;

        let events: Vec<SessionEvent> = sess.event_ids
            .iter()
            .skip(start)
            .take(events_page_size)
            .filter_map(|&id| store.get_record(id).map(|r| SessionEvent {
                id,
                timestamp_ms: r.timestamp,
                event_time: r.record.event_time.clone(),
                event_name: r.record.event_name.clone(),
                event_source: r.record.event_source.clone(),
                aws_region: r.record.aws_region.clone(),
                source_ip: r.record.source_ip_address.clone(),
                error_code: r.record.error_code.clone(),
                user_agent: r.record.user_agent.clone(),
            }))
            .collect();

        Some(SessionDetail {
            id: sess.id,
            identity_key: sess.identity_key.clone(),
            source_ip: sess.source_ip.clone(),
            first_event_ms: sess.first_event_ms,
            last_event_ms: sess.last_event_ms,
            duration_ms: sess.duration_ms(),
            event_count: sess.event_count,
            error_count: sess.error_count,
            unique_event_names: sess.unique_event_names.clone(),
            unique_regions: sess.unique_regions.clone(),
            events,
            events_page,
            events_page_size,
            events_total,
        })
    }

    // -----------------------------------------------------------------------
    // Correlation: sessions ↔ alerts
    // -----------------------------------------------------------------------

    /// Return lightweight alert stubs for alerts that overlap a given session's events.
    pub fn get_session_alerts(
        &self,
        session_id: u32,
        alerts: &[Alert],
    ) -> Vec<AlertStub> {
        let sess = match self.sessions.get(session_id as usize) {
            Some(s) => s,
            None => return vec![],
        };

        let session_ids: HashSet<u64> = sess.event_ids.iter().copied().collect();

        alerts
            .iter()
            .filter(|a| a.matching_record_ids.iter().any(|id| session_ids.contains(id)))
            .map(|a| AlertStub {
                rule_id: a.rule_id.clone(),
                severity: a.severity.clone(),
                title: a.title.clone(),
                service: a.service.clone(),
                mitre_tactic: a.mitre_tactic.clone(),
                mitre_technique: a.mitre_technique.clone(),
                matching_count: a.matching_record_ids
                    .iter()
                    .filter(|id| session_ids.contains(id))
                    .count(),
            })
            .collect()
    }

    /// Return sessions that contain at least one event from the given alert.
    pub fn get_alert_sessions(
        &self,
        alert: &Alert,
    ) -> Vec<SessionSummary> {
        let alert_ids: HashSet<u64> = alert.matching_record_ids.iter().copied().collect();

        self.sessions
            .iter()
            .filter(|s| s.event_ids.iter().any(|id| alert_ids.contains(id)))
            .map(session_to_summary)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Correlation types
// ---------------------------------------------------------------------------

/// Lightweight alert reference used in SessionDetail
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertStub {
    pub rule_id: String,
    pub severity: crate::detection::Severity,
    pub title: String,
    pub service: String,
    pub mitre_tactic: String,
    pub mitre_technique: String,
    /// Number of this session's events that matched the alert
    pub matching_count: usize,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn identity_key_for(rec: &crate::model::IndexedRecord) -> String {
    if let Some(arn) = &rec.record.user_identity.arn {
        return arn.clone();
    }
    if let Some(name) = &rec.record.user_identity.user_name {
        return name.clone();
    }
    if let Some(pid) = &rec.record.user_identity.principal_id {
        return pid.clone();
    }
    "unknown".to_string()
}

fn session_to_summary(s: &Session) -> SessionSummary {
    SessionSummary {
        id: s.id,
        identity_key: s.identity_key.clone(),
        source_ip: s.source_ip.clone(),
        first_event_ms: s.first_event_ms,
        last_event_ms: s.last_event_ms,
        duration_ms: s.duration_ms(),
        event_count: s.event_count,
        error_count: s.error_count,
        unique_event_names: s.unique_event_names.clone(),
        unique_regions: s.unique_regions.clone(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use crate::model::{CloudTrailRecord, IndexedRecord, UserIdentity};
    use crate::detection::{Alert, Severity};

    /// Build a minimal `IndexedRecord` suitable for session tests.
    fn make_event(id: u64, arn: &str, ip: &str, ts_ms: i64) -> IndexedRecord {
        make_event_full(id, arn, ip, ts_ms, "ListBuckets", "s3.amazonaws.com", None)
    }

    fn make_event_full(
        id: u64,
        arn: &str,
        ip: &str,
        ts_ms: i64,
        event_name: &str,
        event_source: &str,
        error_code: Option<&str>,
    ) -> IndexedRecord {
        IndexedRecord {
            id,
            timestamp: ts_ms,
            source_file: 0,
            record: CloudTrailRecord {
                event_version: None,
                event_time: "2024-01-15T10:00:00Z".to_string(),
                event_source: event_source.to_string(),
                event_name: event_name.to_string(),
                aws_region: "us-east-1".to_string(),
                source_ip_address: Some(ip.to_string()),
                user_agent: None,
                user_identity: UserIdentity {
                    identity_type: Some("IAMUser".to_string()),
                    principal_id: None,
                    arn: Some(arn.to_string()),
                    account_id: Some("123456789012".to_string()),
                    access_key_id: None,
                    user_name: None,
                    session_context: None,
                    invoked_by: None,
                    extra: HashMap::new(),
                },
                request_parameters: None,
                response_elements: None,
                additional_event_data: None,
                error_code: error_code.map(|s| s.to_string()),
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
                extra: HashMap::new(),
            },
        }
    }

    /// Build a `Store` from a vec of IndexedRecords (sorted by id).
    fn build_store(records: Vec<IndexedRecord>) -> crate::store::Store {
        let mut store = crate::store::Store::new();
        let mut records = records;
        records.sort_by_key(|r| r.id);

        for rec in &records {
            let id = rec.id;
            store.idx_event_name.entry(rec.record.event_name.clone()).or_default().push(id);
            store.idx_event_source.entry(rec.record.event_source.clone()).or_default().push(id);
            store.idx_region.entry(rec.record.aws_region.clone()).or_default().push(id);
            if let Some(ip) = &rec.record.source_ip_address {
                store.idx_source_ip.entry(ip.clone()).or_default().push(id);
            }
            if let Some(arn) = &rec.record.user_identity.arn {
                store.idx_user_arn.entry(arn.clone()).or_default().push(id);
            }
            if let Some(err) = &rec.record.error_code {
                store.idx_error_code.entry(err.clone()).or_default().push(id);
            }
        }

        let mut sorted: Vec<(i64, u64)> = records.iter().map(|r| (r.timestamp, r.id)).collect();
        sorted.sort_unstable_by_key(|(ts, _)| *ts);
        store.time_sorted_ids = sorted.into_iter().map(|(_, id)| id).collect();
        store.records = records;
        store
    }

    // -----------------------------------------------------------------------
    // Session building
    // -----------------------------------------------------------------------

    #[test]
    fn test_single_identity_single_ip_one_session() {
        let store = build_store(vec![
            make_event(0, "arn:aws:iam::123:user/alice", "1.2.3.4", 0),
            make_event(1, "arn:aws:iam::123:user/alice", "1.2.3.4", 60_000),
            make_event(2, "arn:aws:iam::123:user/alice", "1.2.3.4", 120_000),
        ]);
        let idx = SessionIndex::build(&store);
        assert_eq!(idx.sessions.len(), 1, "all events within gap → 1 session");
        assert_eq!(idx.sessions[0].event_count, 3);
        assert_eq!(idx.sessions[0].identity_key, "arn:aws:iam::123:user/alice");
        assert_eq!(idx.sessions[0].source_ip, "1.2.3.4");
    }

    #[test]
    fn test_gap_exceeds_30min_creates_new_session() {
        const GAP: i64 = 31 * 60 * 1_000; // 31 min — exceeds threshold
        let store = build_store(vec![
            make_event(0, "arn:aws:iam::123:user/bob", "5.6.7.8", 0),
            make_event(1, "arn:aws:iam::123:user/bob", "5.6.7.8", GAP),
        ]);
        let idx = SessionIndex::build(&store);
        assert_eq!(idx.sessions.len(), 2, "31-min gap must start a new session");
        assert_eq!(idx.sessions[0].event_count, 1);
        assert_eq!(idx.sessions[1].event_count, 1);
    }

    #[test]
    fn test_within_30min_gap_stays_one_session() {
        const GAP: i64 = 29 * 60 * 1_000; // 29 min — within threshold
        let store = build_store(vec![
            make_event(0, "arn:aws:iam::123:user/carol", "9.9.9.9", 0),
            make_event(1, "arn:aws:iam::123:user/carol", "9.9.9.9", GAP),
        ]);
        let idx = SessionIndex::build(&store);
        assert_eq!(idx.sessions.len(), 1, "29-min gap must stay in same session");
        assert_eq!(idx.sessions[0].event_count, 2);
    }

    #[test]
    fn test_same_identity_different_ips_two_sessions() {
        let store = build_store(vec![
            make_event(0, "arn:aws:iam::123:user/alice", "1.1.1.1", 0),
            make_event(1, "arn:aws:iam::123:user/alice", "2.2.2.2", 1_000),
        ]);
        let idx = SessionIndex::build(&store);
        assert_eq!(idx.sessions.len(), 2, "different IPs → different sessions");
    }

    #[test]
    fn test_different_identities_same_ip_two_sessions() {
        let store = build_store(vec![
            make_event(0, "arn:aws:iam::123:user/alice", "1.1.1.1", 0),
            make_event(1, "arn:aws:iam::123:user/bob", "1.1.1.1", 1_000),
        ]);
        let idx = SessionIndex::build(&store);
        assert_eq!(idx.sessions.len(), 2, "different identities → different sessions");
    }

    #[test]
    fn test_empty_store_produces_no_sessions() {
        let store = build_store(vec![]);
        let idx = SessionIndex::build(&store);
        assert!(idx.sessions.is_empty());
    }

    #[test]
    fn test_error_count_tracked() {
        let store = build_store(vec![
            make_event_full(0, "arn:aws:iam::123:user/alice", "1.2.3.4", 0, "GetObject", "s3.amazonaws.com", None),
            make_event_full(1, "arn:aws:iam::123:user/alice", "1.2.3.4", 1_000, "GetObject", "s3.amazonaws.com", Some("AccessDenied")),
            make_event_full(2, "arn:aws:iam::123:user/alice", "1.2.3.4", 2_000, "GetObject", "s3.amazonaws.com", Some("NoSuchKey")),
        ]);
        let idx = SessionIndex::build(&store);
        assert_eq!(idx.sessions[0].error_count, 2);
    }

    #[test]
    fn test_unique_event_names_deduplicated() {
        let store = build_store(vec![
            make_event_full(0, "arn:aws:iam::123:user/alice", "1.2.3.4", 0, "ListBuckets", "s3.amazonaws.com", None),
            make_event_full(1, "arn:aws:iam::123:user/alice", "1.2.3.4", 1_000, "GetObject", "s3.amazonaws.com", None),
            make_event_full(2, "arn:aws:iam::123:user/alice", "1.2.3.4", 2_000, "GetObject", "s3.amazonaws.com", None),
        ]);
        let idx = SessionIndex::build(&store);
        assert_eq!(idx.sessions[0].unique_event_names.len(), 2);
    }

    #[test]
    fn test_duration_ms() {
        let store = build_store(vec![
            make_event(0, "arn:aws:iam::123:user/alice", "1.2.3.4", 0),
            make_event(1, "arn:aws:iam::123:user/alice", "1.2.3.4", 5_000),
        ]);
        let idx = SessionIndex::build(&store);
        assert_eq!(idx.sessions[0].duration_ms(), 5_000);
    }

    // -----------------------------------------------------------------------
    // list_sessions — filtering & pagination
    // -----------------------------------------------------------------------

    #[test]
    fn test_list_sessions_returns_all() {
        let store = build_store(vec![
            make_event(0, "arn:aws:iam::123:user/alice", "1.1.1.1", 0),
            make_event(1, "arn:aws:iam::123:user/bob", "2.2.2.2", 1_000),
        ]);
        let idx = SessionIndex::build(&store);
        let page = idx.list_sessions(0, 10, "first", None, None, None);
        assert_eq!(page.total, 2);
        assert_eq!(page.sessions.len(), 2);
    }

    #[test]
    fn test_list_sessions_pagination() {
        let store = build_store(
            (0u64..5)
                .map(|i| make_event(i, &format!("arn:aws:iam::123:user/u{}", i), "1.1.1.1", i as i64 * 1_000))
                .collect(),
        );
        let idx = SessionIndex::build(&store);
        let page0 = idx.list_sessions(0, 2, "first", None, None, None);
        let page1 = idx.list_sessions(1, 2, "first", None, None, None);
        assert_eq!(page0.total, 5);
        assert_eq!(page0.sessions.len(), 2);
        assert_eq!(page1.sessions.len(), 2);
    }

    #[test]
    fn test_list_sessions_filter_by_identity() {
        let store = build_store(vec![
            make_event(0, "arn:aws:iam::123:user/alice", "1.1.1.1", 0),
            make_event(1, "arn:aws:iam::123:user/bob", "2.2.2.2", 1_000),
        ]);
        let idx = SessionIndex::build(&store);
        let page = idx.list_sessions(0, 10, "first", Some("alice"), None, None);
        assert_eq!(page.total, 1);
        assert!(page.sessions[0].identity_key.contains("alice"));
    }

    #[test]
    fn test_list_sessions_filter_by_ip() {
        let store = build_store(vec![
            make_event(0, "arn:aws:iam::123:user/alice", "10.0.0.1", 0),
            make_event(1, "arn:aws:iam::123:user/bob", "192.168.1.1", 1_000),
        ]);
        let idx = SessionIndex::build(&store);
        let page = idx.list_sessions(0, 10, "first", None, Some("10.0.0.1"), None);
        assert_eq!(page.total, 1);
        assert_eq!(page.sessions[0].source_ip, "10.0.0.1");
    }

    // -----------------------------------------------------------------------
    // get_session_detail
    // -----------------------------------------------------------------------

    #[test]
    fn test_get_session_detail_returns_events() {
        let store = build_store(vec![
            make_event(0, "arn:aws:iam::123:user/alice", "1.2.3.4", 0),
            make_event(1, "arn:aws:iam::123:user/alice", "1.2.3.4", 1_000),
        ]);
        let idx = SessionIndex::build(&store);
        let detail = idx.get_session_detail(&store, 0, 0, 10).expect("session 0 must exist");
        assert_eq!(detail.events_total, 2);
        assert_eq!(detail.events.len(), 2);
    }

    #[test]
    fn test_get_session_detail_pagination() {
        let store = build_store(
            (0u64..5)
                .map(|i| make_event(i, "arn:aws:iam::123:user/alice", "1.2.3.4", i as i64 * 1_000))
                .collect(),
        );
        let idx = SessionIndex::build(&store);
        let detail = idx.get_session_detail(&store, 0, 1, 2).expect("session exists");
        assert_eq!(detail.events_total, 5);
        assert_eq!(detail.events.len(), 2, "page 1, size 2 should return 2 events");
    }

    #[test]
    fn test_get_session_detail_nonexistent_returns_none() {
        let store = build_store(vec![]);
        let idx = SessionIndex::build(&store);
        assert!(idx.get_session_detail(&store, 99, 0, 10).is_none());
    }

    // -----------------------------------------------------------------------
    // Alert correlation
    // -----------------------------------------------------------------------

    #[test]
    fn test_get_session_alerts_correlates_correctly() {
        let store = build_store(vec![
            make_event(0, "arn:aws:iam::123:user/alice", "1.2.3.4", 0),
            make_event(1, "arn:aws:iam::123:user/alice", "1.2.3.4", 1_000),
            make_event(2, "arn:aws:iam::123:user/bob", "5.6.7.8", 0),
        ]);
        let idx = SessionIndex::build(&store);

        // Alert matching record 0 and 1 belongs to alice's session
        let alert = Alert {
            rule_id: "TEST-01".to_string(),
            severity: Severity::High,
            title: "Test".to_string(),
            description: "Test".to_string(),
            matching_record_ids: vec![0, 1],
            metadata: std::collections::HashMap::new(),
            mitre_tactic: "Test".to_string(),
            mitre_technique: "T0000".to_string(),
            service: "Test".to_string(),
            query: String::new(),
        };

        // Find alice's session (has records 0 and 1)
        let alice_session = idx.sessions.iter().find(|s| s.identity_key.contains("alice")).unwrap();
        let stubs = idx.get_session_alerts(alice_session.id, &[alert.clone()]);
        assert_eq!(stubs.len(), 1);
        assert_eq!(stubs[0].matching_count, 2);

        // Bob's session should not have the alert
        let bob_session = idx.sessions.iter().find(|s| s.identity_key.contains("bob")).unwrap();
        let bob_stubs = idx.get_session_alerts(bob_session.id, &[alert]);
        assert!(bob_stubs.is_empty());
    }

    #[test]
    fn test_get_alert_sessions_returns_owning_sessions() {
        let store = build_store(vec![
            make_event(0, "arn:aws:iam::123:user/alice", "1.2.3.4", 0),
            make_event(1, "arn:aws:iam::123:user/bob", "5.6.7.8", 0),
        ]);
        let idx = SessionIndex::build(&store);

        let alert = Alert {
            rule_id: "TEST-02".to_string(),
            severity: Severity::Medium,
            title: "Test".to_string(),
            description: "Test".to_string(),
            matching_record_ids: vec![0], // only alice's event
            metadata: std::collections::HashMap::new(),
            mitre_tactic: "Test".to_string(),
            mitre_technique: "T0000".to_string(),
            service: "Test".to_string(),
            query: String::new(),
        };

        let sessions = idx.get_alert_sessions(&alert);
        assert_eq!(sessions.len(), 1);
        assert!(sessions[0].identity_key.contains("alice"));
    }

    // -----------------------------------------------------------------------
    // Secondary indexes
    // -----------------------------------------------------------------------

    #[test]
    fn test_by_identity_index_built_correctly() {
        let store = build_store(vec![
            make_event(0, "arn:aws:iam::123:user/alice", "1.1.1.1", 0),
            make_event(1, "arn:aws:iam::123:user/alice", "2.2.2.2", 0), // different IP → 2 sessions
        ]);
        let idx = SessionIndex::build(&store);
        let alice_sessions = idx.by_identity.get("arn:aws:iam::123:user/alice").unwrap();
        assert_eq!(alice_sessions.len(), 2);
    }

    #[test]
    fn test_by_ip_index_built_correctly() {
        let store = build_store(vec![
            make_event(0, "arn:aws:iam::123:user/alice", "1.2.3.4", 0),
            make_event(1, "arn:aws:iam::123:user/bob", "1.2.3.4", 1_000),
        ]);
        let idx = SessionIndex::build(&store);
        let ip_sessions = idx.by_ip.get("1.2.3.4").unwrap();
        assert_eq!(ip_sessions.len(), 2);
    }
}
