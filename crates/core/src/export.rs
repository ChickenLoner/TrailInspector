use crate::error::CoreError;
use crate::query::{execute, parse_query, Query};
use crate::store::Store;

/// CSV-escape a field: wrap in quotes if it contains comma, quote, or newline.
fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Resolve all matching record IDs for an optional query string (no pagination — returns all).
fn resolve_ids(store: &Store, query: Option<&str>) -> Result<Vec<u32>, CoreError> {
    let parsed = match query.map(str::trim) {
        Some(q) if !q.is_empty() => parse_query(q).map_err(|e| CoreError::Query(e.to_string()))?,
        _ => Query::default(),
    };
    // page=0, page_size=usize::MAX gives all results in one shot
    let result = execute(store, &parsed, 0, usize::MAX);
    Ok(result.record_ids)
}

fn io_err(source: std::io::Error) -> CoreError {
    CoreError::Io { path: "<export>".into(), source }
}

/// Export filtered records as CSV to `w`, one row at a time. Returns the number of data rows
/// written (the header is not counted).
///
/// Columns: eventTime, eventName, eventSource, awsRegion, sourceIPAddress,
///          userName, userArn, errorCode
///
/// Streaming keeps memory flat however many records match, and the count comes from the loop
/// itself rather than from counting newlines in a finished buffer.
pub fn export_csv_to<W: std::io::Write>(
    store: &Store,
    query: Option<&str>,
    mut w: W,
) -> Result<usize, CoreError> {
    let ids = resolve_ids(store, query)?;

    w.write_all(b"eventTime,eventName,eventSource,awsRegion,sourceIPAddress,userName,userArn,errorCode\n")
        .map_err(io_err)?;

    let mut rows = 0usize;
    for &id in &ids {
        if let Some(r) = store.get_record(id) {
            let rec = &r.record;
            writeln!(
                w,
                "{},{},{},{},{},{},{},{}",
                csv_escape(&rec.event_time),
                csv_escape(&rec.event_name),
                csv_escape(&rec.event_source),
                csv_escape(&rec.aws_region),
                csv_escape(rec.source_ip_address.as_deref().unwrap_or("")),
                csv_escape(rec.user_identity.user_name.as_deref().unwrap_or("")),
                csv_escape(rec.user_identity.arn.as_deref().unwrap_or("")),
                csv_escape(rec.error_code.as_deref().unwrap_or("")),
            )
            .map_err(io_err)?;
            rows += 1;
        }
    }

    w.flush().map_err(io_err)?;
    Ok(rows)
}

/// Export filtered records as a JSON array of full `CloudTrailRecord` objects to `w`, one record
/// at a time (compact, one record per line). Returns the number of records written.
///
/// `get_full_record` loads the blob fields (requestParameters etc.) from the BlobStore so the
/// exported JSON carries the complete event payload. Only one record is materialised at a time;
/// the previous version built every full record, pretty-printed the whole array in memory, then
/// re-parsed it just to count.
pub fn export_json_to<W: std::io::Write>(
    store: &Store,
    query: Option<&str>,
    mut w: W,
) -> Result<usize, CoreError> {
    let ids = resolve_ids(store, query)?;

    w.write_all(b"[").map_err(io_err)?;
    let mut count = 0usize;
    for &id in &ids {
        let Some(rec) = store.get_full_record(id) else { continue };
        w.write_all(if count == 0 { b"\n" } else { b",\n" }).map_err(io_err)?;
        serde_json::to_writer(&mut w, &rec).map_err(|e| match e.io_error_kind() {
            Some(_) => io_err(std::io::Error::other(e.to_string())),
            None => CoreError::Json { path: "<export>".into(), source: e },
        })?;
        count += 1;
    }
    w.write_all(if count == 0 { b"]\n" } else { b"\n]\n" }).map_err(io_err)?;

    w.flush().map_err(io_err)?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_with(event_names: &[&str]) -> Store {
        let dir = tempfile::TempDir::new().unwrap();
        for (i, name) in event_names.iter().enumerate() {
            std::fs::write(
                dir.path().join(format!("f{i}.json")),
                format!(
                    r#"{{"Records":[{{"eventTime":"2024-01-15T10:00:0{i}Z","eventSource":"iam.amazonaws.com","eventName":"{name}","awsRegion":"us-east-1","userIdentity":{{"type":"IAMUser","userName":"a,b"}},"requestParameters":{{"userName":"x"}}}}]}}"#
                ),
            )
            .unwrap();
        }
        let mut store = Store::new();
        store.load_directory(dir.path(), |_| {}).unwrap();
        store
    }

    #[test]
    fn csv_export_streams_rows_and_returns_the_count() {
        let store = store_with(&["CreateUser", "DeleteUser", "CreateUser"]);
        let mut out = Vec::new();
        let rows = export_csv_to(&store, None, &mut out).unwrap();
        assert_eq!(rows, 3);
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 4, "header + 3 rows: {text}");
        assert!(text.contains("\"a,b\""), "commas are quoted: {text}");

        let mut filtered = Vec::new();
        assert_eq!(export_csv_to(&store, Some("eventName=CreateUser"), &mut filtered).unwrap(), 2);
    }

    #[test]
    fn json_export_is_a_valid_array_with_full_records() {
        let store = store_with(&["CreateUser", "DeleteUser"]);
        let mut out = Vec::new();
        let n = export_json_to(&store, None, &mut out).unwrap();
        assert_eq!(n, 2);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let arr = v.as_array().expect("a JSON array");
        assert_eq!(arr.len(), 2);
        // Blob fields are restored from the BlobStore.
        assert_eq!(arr[0]["requestParameters"]["userName"], "x");
    }

    #[test]
    fn json_export_of_no_matches_is_an_empty_array() {
        let store = store_with(&["CreateUser"]);
        let mut out = Vec::new();
        assert_eq!(export_json_to(&store, Some("eventName=Nope"), &mut out).unwrap(), 0);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 0);
    }

    #[test]
    fn csv_escape_basic() {
        assert_eq!(csv_escape("hello"), "hello");
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }
}
