use std::path::Path;
use crate::error::CoreError;
use crate::model::{CloudTrailFile, CloudTrailRecord, IndexedRecord, LookupEventsFile};

/// What one parsed file yields: the usable records plus how many were dropped.
pub struct ParsedFile {
    pub records: Vec<IndexedRecord>,
    /// Records whose `eventTime` could not be parsed. They are dropped rather than stamped with
    /// epoch 0, which would put them in 1970 and stretch the timeline across 54 years.
    pub bad_time: usize,
}

/// Parse an `eventTime` to epoch milliseconds. Accepts RFC 3339 first, then the shapes that
/// emulators and hand-edited logs produce: space-separated, no zone (taken as UTC), and
/// numeric offsets without a colon (`+0000`).
pub fn parse_event_time(s: &str) -> Option<i64> {
    use chrono::{DateTime, NaiveDateTime};
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.timestamp_millis());
    }
    for fmt in ["%Y-%m-%dT%H:%M:%S%.f%z", "%Y-%m-%d %H:%M:%S%.f%z"] {
        if let Ok(dt) = DateTime::parse_from_str(s, fmt) {
            return Some(dt.timestamp_millis());
        }
    }
    for fmt in ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S%.f"] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(ndt.and_utc().timestamp_millis());
        }
    }
    None
}

/// Parse a CloudTrail JSON byte buffer into indexed records.
/// Uses serde_json::from_slice (NOT from_reader) — 2-5x faster.
///
/// Accepts both on-disk shapes:
/// - S3 delivery format: `{"Records": [ {...}, ... ]}`
/// - `aws cloudtrail lookup-events` export: `{"Events": [{"CloudTrailEvent": "<escaped json>"}]}`
pub fn parse_records(
    bytes: &[u8],
    path: &Path,
    file_idx: u32,
    start_id: u32,
) -> Result<ParsedFile, CoreError> {
    let json_err = |e: serde_json::Error| CoreError::Json {
        path: path.to_string_lossy().to_string(),
        source: e,
    };

    // Try the S3 delivery format first — it is the overwhelmingly common case and
    // costs nothing extra when it succeeds. Only on failure do we consider the
    // lookup-events shape; if that fails too, report the original `Records` error
    // so a genuinely malformed S3 file doesn't get a misleading message.
    let records: Vec<CloudTrailRecord> = match serde_json::from_slice::<CloudTrailFile>(bytes) {
        Ok(file) => file.records,
        Err(records_err) => match serde_json::from_slice::<LookupEventsFile>(bytes) {
            Ok(file) => file
                .events
                .into_iter()
                .map(|e| serde_json::from_str(&e.cloud_trail_event).map_err(json_err))
                .collect::<Result<Vec<_>, _>>()?,
            Err(_) => return Err(json_err(records_err)),
        },
    };

    let mut bad_time = 0usize;
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        let Some(timestamp) = parse_event_time(&record.event_time) else {
            bad_time += 1;
            continue;
        };
        out.push(IndexedRecord {
            id: start_id + out.len() as u32,
            timestamp,
            source_file: file_idx,
            record,
            request_params_ref: None,
            response_elements_ref: None,
            additional_event_data_ref: None,
        });
    }

    Ok(ParsedFile { records: out, bad_time })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_parse_minimal_record() {
        let json = r#"{
            "Records": [{
                "eventVersion": "1.08",
                "eventTime": "2023-11-02T00:00:00Z",
                "eventSource": "iam.amazonaws.com",
                "eventName": "CreateUser",
                "awsRegion": "us-east-1",
                "userIdentity": { "type": "IAMUser", "userName": "attacker" },
                "requestParameters": null,
                "responseElements": null
            }]
        }"#;
        let path = PathBuf::from("test.json");
        let records = parse_records(json.as_bytes(), &path, 0, 0).unwrap().records;
        assert_eq!(records.len(), 1);
        assert_eq!(&*records[0].record.event_name, "CreateUser");
    }

    /// `aws cloudtrail lookup-events --output json` wraps events in "Events" and
    /// escapes the real payload into the "CloudTrailEvent" string field.
    #[test]
    fn test_parse_lookup_events_export() {
        let json = r#"{
            "Events": [{
                "EventId": "c1c35c4c-7a43-49d7-b064-89d8184deab0",
                "EventName": "StopLogging",
                "ReadOnly": "false",
                "EventTime": "2026-07-25T02:21:44.450000+07:00",
                "EventSource": "cloudtrail.amazonaws.com",
                "Username": "stonepass-warden",
                "Resources": [],
                "CloudTrailEvent": "{\"eventVersion\":\"1.08\",\"eventTime\":\"2026-07-24T19:21:44Z\",\"eventSource\":\"cloudtrail.amazonaws.com\",\"eventName\":\"StopLogging\",\"awsRegion\":\"us-east-1\",\"userIdentity\":{\"type\":\"IAMUser\",\"userName\":\"stonepass-warden\"}}"
            }]
        }"#;
        let path = PathBuf::from("cloudtrail-events.json");
        let records = parse_records(json.as_bytes(), &path, 0, 7).unwrap().records;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, 7);
        assert_eq!(&*records[0].record.event_name, "StopLogging");
        // Timestamp must come from the nested payload, not the wrapper.
        assert_ne!(records[0].timestamp, 0);
        assert_eq!(
            records[0].record.user_identity.user_name.as_deref(),
            Some("stonepass-warden")
        );
    }

    /// A malformed S3-format file must report the "Records" error, not a
    /// confusing "missing field Events" from the fallback attempt.
    #[test]
    fn test_malformed_records_reports_original_error() {
        let json = r#"{"Records": [{"eventName": 42}]}"#;
        let path = PathBuf::from("bad.json");
        // Not unwrap_err() — IndexedRecord has no Debug impl.
        let msg = match parse_records(json.as_bytes(), &path, 0, 0) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected a parse failure"),
        };
        assert!(!msg.contains("Events"), "unexpected error message: {msg}");
    }

    fn record_json(event_time: &str) -> String {
        format!(r#"{{"eventVersion":"1.08","eventTime":"{event_time}","eventSource":"iam.amazonaws.com","eventName":"CreateUser","awsRegion":"us-east-1","userIdentity":{{"type":"IAMUser","userName":"a"}}}}"#)
    }

    #[test]
    fn test_event_time_fallback_formats_parse() {
        let want = parse_event_time("2024-01-15T10:00:00Z").unwrap();
        assert_eq!(parse_event_time("2024-01-15 10:00:00"), Some(want));
        assert_eq!(parse_event_time("2024-01-15T10:00:00"), Some(want));
        assert_eq!(parse_event_time("2024-01-15T10:00:00+0000"), Some(want));
        assert_eq!(parse_event_time("2024-01-15T17:00:00+0700"), Some(want));
        assert_eq!(parse_event_time("2024-01-15 10:00:00.250"), Some(want + 250));
        assert_eq!(parse_event_time("garbage"), None);
        assert_eq!(parse_event_time(""), None);
    }

    #[test]
    fn test_unparseable_event_time_is_dropped_and_counted() {
        let json = format!(
            r#"{{"Records":[{},{},{}]}}"#,
            record_json("2024-01-15 10:00:00"),
            record_json("garbage"),
            record_json("2024-01-15T10:00:01Z"),
        );
        let parsed = parse_records(json.as_bytes(), &PathBuf::from("t.json"), 0, 5).unwrap();
        assert_eq!(parsed.bad_time, 1);
        assert_eq!(parsed.records.len(), 2);
        // ids stay dense and start at start_id even though a record was dropped
        assert_eq!(parsed.records[0].id, 5);
        assert_eq!(parsed.records[1].id, 6);
        assert!(parsed.records.iter().all(|r| r.timestamp > 0));
    }
}
