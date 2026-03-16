use std::path::Path;
use crate::error::CoreError;
use crate::model::{CloudTrailFile, IndexedRecord};

/// Parse a CloudTrail JSON byte buffer into indexed records.
/// Uses serde_json::from_slice (NOT from_reader) — 2-5x faster.
pub fn parse_records(
    bytes: &[u8],
    path: &Path,
    file_idx: u32,
    start_id: u64,
) -> Result<Vec<IndexedRecord>, CoreError> {
    let file: CloudTrailFile = serde_json::from_slice(bytes).map_err(|e| CoreError::Json {
        path: path.to_string_lossy().to_string(),
        source: e,
    })?;

    let records = file
        .records
        .into_iter()
        .enumerate()
        .map(|(i, record)| {
            // Parse timestamp to epoch millis; fall back to 0 on error
            let timestamp = chrono::DateTime::parse_from_rfc3339(&record.event_time)
                .map(|dt| dt.timestamp_millis())
                .unwrap_or(0);

            IndexedRecord {
                id: start_id + i as u64,
                timestamp,
                source_file: file_idx,
                record,
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
        assert_eq!(records[0].record.event_name, "CreateUser");
    }
}
