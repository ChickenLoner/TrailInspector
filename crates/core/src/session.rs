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
