use std::path::Path;
use crate::error::CoreError;
use crate::model::{CloudTrailFile, CloudTrailRecord, IndexedRecord, LookupEventsFile};

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
) -> Result<Vec<IndexedRecord>, CoreError> {
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

    let records = records
        .into_iter()
        .enumerate()
        .map(|(i, record)| {
            // Parse timestamp to epoch millis; fall back to 0 on error
            let timestamp = chrono::DateTime::parse_from_rfc3339(&record.event_time)
                .map(|dt| dt.timestamp_millis())
                .unwrap_or(0);

            IndexedRecord {
                id: start_id + i as u32,
                timestamp,
                source_file: file_idx,
                record,
                request_params_ref: None,
                response_elements_ref: None,
                additional_event_data_ref: None,
            }
        })
        .collect();

    Ok(records)
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
        let records = parse_records(json.as_bytes(), &path, 0, 0).unwrap();
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
        let records = parse_records(json.as_bytes(), &path, 0, 7).unwrap();
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
}
