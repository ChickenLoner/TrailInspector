use tauri::State;
use trail_inspector_core::model::CloudTrailRecord;
use trail_inspector_core::query::{execute, parse_query, Query};
use crate::state::AppState;

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResult {
    pub records: Vec<RecordRow>,
    pub total: usize,
    pub page: usize,
    pub page_size: usize,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordRow {
    pub id: u64,
    pub timestamp: i64,
    pub event_time: String,
    pub event_name: String,
    pub event_source: String,
    pub aws_region: String,
    #[serde(rename = "sourceIPAddress")]
    pub source_ip_address: Option<String>,
    pub user_name: Option<String>,
    pub user_arn: Option<String>,
    pub error_code: Option<String>,
    pub raw: CloudTrailRecord,
}

/// Search the loaded dataset.
///
/// `query` supports the TrailInspector syntax:
///   `eventName=ConsoleLogin AND awsRegion=us-east-1 earliest=-24h`
#[tauri::command]
pub async fn search(
    query: Option<String>,
    page: Option<usize>,
    page_size: Option<usize>,
    state: State<'_, AppState>,
) -> Result<SearchResult, String> {
    let page = page.unwrap_or(0);
    let page_size = page_size.unwrap_or(100).min(500);

    let guard = state.store.read().map_err(|e| format!("Lock error: {e}"))?;
    let store = guard.as_ref().ok_or("No dataset loaded")?;

    let parsed = match query.as_deref().map(str::trim) {
        Some(q) if !q.is_empty() => {
            parse_query(q).map_err(|e| format!("Query error: {e}"))?
        }
        _ => Query::default(),
    };

    let result = execute(store, &parsed, page, page_size);

    let records: Vec<RecordRow> = result
        .record_ids
        .iter()
        .filter_map(|&id| store.get_record(id))
        .map(|r| RecordRow {
            id: r.id,
            timestamp: r.timestamp,
            event_time: r.record.event_time.clone(),
            event_name: r.record.event_name.clone(),
            event_source: r.record.event_source.clone(),
            aws_region: r.record.aws_region.clone(),
            source_ip_address: r.record.source_ip_address.clone(),
            user_name: r.record.user_identity.user_name.clone(),
            user_arn: r.record.user_identity.arn.clone(),
            error_code: r.record.error_code.clone(),
            raw: r.record.clone(),
        })
        .collect();

    Ok(SearchResult {
        records,
        total: result.total,
        page,
        page_size,
    })
}

#[derive(Debug, serde::Serialize)]
pub struct FieldValue {
    pub value: String,
    pub count: usize,
}

#[tauri::command]
pub async fn get_field_values(
    field: String,
    top_n: Option<usize>,
    state: State<'_, AppState>,
) -> Result<Vec<FieldValue>, String> {
    let top_n = top_n.unwrap_or(20);
    let guard = state.store.read().map_err(|e| format!("Lock error: {e}"))?;
    let store = guard.as_ref().ok_or("No dataset loaded")?;

    let idx = match field.as_str() {
        "eventName" => &store.idx_event_name,
        "eventSource" => &store.idx_event_source,
        "awsRegion" => &store.idx_region,
        "sourceIPAddress" => &store.idx_source_ip,
        "userArn" => &store.idx_user_arn,
        "userName" => &store.idx_user_name,
        "accountId" => &store.idx_account_id,
        "errorCode" => &store.idx_error_code,
        "identityType" => &store.idx_identity_type,
        "userAgent" => &store.idx_user_agent,
        "bucketName" => &store.idx_bucket_name,
        _ => return Err(format!("Unknown field: {field}")),
    };

    let mut values: Vec<FieldValue> = idx
        .iter()
        .map(|(k, v)| FieldValue {
            value: k.clone(),
            count: v.len(),
        })
        .collect();

    values.sort_unstable_by(|a, b| b.count.cmp(&a.count));
    values.truncate(top_n);

    Ok(values)
}
