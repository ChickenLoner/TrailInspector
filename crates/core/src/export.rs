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

/// Export filtered records as CSV. Returns CSV bytes.
///
/// Columns: eventTime, eventName, eventSource, awsRegion, sourceIPAddress,
///          userName, userArn, errorCode
pub fn export_csv(store: &Store, query: Option<&str>) -> Result<Vec<u8>, CoreError> {
    let ids = resolve_ids(store, query)?;

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(
        b"eventTime,eventName,eventSource,awsRegion,sourceIPAddress,userName,userArn,errorCode\n",
    );

    for &id in &ids {
        if let Some(r) = store.get_record(id) {
            let rec = &r.record;
            let row = format!(
                "{},{},{},{},{},{},{},{}\n",
                csv_escape(&rec.event_time),
                csv_escape(&rec.event_name),
                csv_escape(&rec.event_source),
                csv_escape(&rec.aws_region),
                csv_escape(rec.source_ip_address.as_deref().unwrap_or("")),
                csv_escape(rec.user_identity.user_name.as_deref().unwrap_or("")),
                csv_escape(rec.user_identity.arn.as_deref().unwrap_or("")),
                csv_escape(rec.error_code.as_deref().unwrap_or("")),
            );
            out.extend_from_slice(row.as_bytes());
        }
    }

    Ok(out)
}

/// Export filtered records as JSON. Returns pretty-printed JSON bytes.
/// The output is a JSON array of full `CloudTrailRecord` objects.
pub fn export_json(store: &Store, query: Option<&str>) -> Result<Vec<u8>, CoreError> {
    let ids = resolve_ids(store, query)?;

    // get_full_record loads blob fields (requestParameters etc.) from BlobStore so
    // the exported JSON includes the complete event payload
    let records: Vec<crate::model::CloudTrailRecord> = ids
        .iter()
        .filter_map(|&id| store.get_full_record(id))
        .collect();

    let bytes = serde_json::to_vec_pretty(&records)
        .map_err(|e| CoreError::Json { path: "<export>".into(), source: e })?;

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_escape_basic() {
        assert_eq!(csv_escape("hello"), "hello");
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }
}
