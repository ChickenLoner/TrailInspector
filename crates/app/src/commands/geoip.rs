use tauri::State;
use trail_inspector_core::geoip::{GeoIpEngine, IpInfo, IpPage};
use crate::state::AppState;

// ---------------------------------------------------------------------------
// AbuseIPDB check result
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AbuseCheckResult {
    pub ip: String,
    pub is_public: bool,
    pub abuse_confidence_score: u8,
    pub country_code: Option<String>,
    pub total_reports: u32,
    pub last_reported_at: Option<String>,
    pub usage_type: Option<String>,
    pub isp: Option<String>,
    pub domain: Option<String>,
}

/// Load one or both GeoLite2 MMDB files.
/// Either path may be null (omitted). Returns the DB metadata string on success.
#[tauri::command]
pub async fn load_geoip_db(
    geo_path: Option<String>,
    asn_path: Option<String>,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let engine = GeoIpEngine::load(
        geo_path.as_deref(),
        asn_path.as_deref(),
    )?;

    let desc = match (&geo_path, &asn_path) {
        (Some(g), Some(a)) => format!("Geo: {g}, ASN: {a}"),
        (Some(g), None) => format!("Geo: {g}"),
        (None, Some(a)) => format!("ASN: {a}"),
        (None, None) => "none".to_string(),
    };

    let mut guard = state.geoip.write().map_err(|e| format!("Lock error: {e}"))?;
    *guard = Some(engine);
    Ok(desc)
}

/// Query AbuseIPDB v2 for reputation data on a single IP.
/// Requires a valid AbuseIPDB API key (free tier available at abuseipdb.com).
#[tauri::command]
pub async fn check_abuseipdb(
    api_key: String,
    ip: String,
) -> Result<AbuseCheckResult, String> {
    let client = reqwest::Client::new();
    let resp = client
        .get("https://api.abuseipdb.com/api/v2/check")
        .header("Key", &api_key)
        .header("Accept", "application/json")
        .query(&[("ipAddress", ip.as_str()), ("maxAgeInDays", "90")])
        .send()
        .await
        .map_err(|e| format!("Request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("AbuseIPDB returned {status}: {body}"));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("JSON parse error: {e}"))?;

    let data = json.get("data").ok_or("Missing 'data' in AbuseIPDB response")?;

    Ok(AbuseCheckResult {
        ip: data["ipAddress"].as_str().unwrap_or(&ip).to_string(),
        is_public: data["isPublic"].as_bool().unwrap_or(true),
        abuse_confidence_score: data["abuseConfidenceScore"].as_u64().unwrap_or(0) as u8,
        country_code: data["countryCode"].as_str().filter(|s| !s.is_empty()).map(|s| s.to_string()),
        total_reports: data["totalReports"].as_u64().unwrap_or(0) as u32,
        last_reported_at: data["lastReportedAt"].as_str().filter(|s| !s.is_empty()).map(|s| s.to_string()),
        usage_type: data["usageType"].as_str().filter(|s| !s.is_empty()).map(|s| s.to_string()),
        isp: data["isp"].as_str().filter(|s| !s.is_empty()).map(|s| s.to_string()),
        domain: data["domain"].as_str().filter(|s| !s.is_empty()).map(|s| s.to_string()),
    })
}

// ---------------------------------------------------------------------------
// ip-api.com online geo lookup (no API key required, free for non-commercial)
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnlineGeoResult {
    pub query: String,
    pub status: String,
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    pub org: Option<String>,
    /// Raw AS string from ip-api.com, e.g. "AS14907 Wikimedia Foundation, Inc."
    #[serde(rename = "as")]
    pub asn_str: Option<String>,
    pub asname: Option<String>,
}

/// Batch geo-lookup via ip-api.com (up to 100 IPs per call, HTTP free tier).
/// Private/reserved IPs are returned with status "fail" and are harmless.
#[tauri::command]
pub async fn geo_lookup_online(ips: Vec<String>) -> Result<Vec<OnlineGeoResult>, String> {
    if ips.is_empty() {
        return Ok(vec![]);
    }
    let client = reqwest::Client::new();
    let mut all_results: Vec<OnlineGeoResult> = Vec::new();

    for chunk in ips.chunks(100) {
        let body: Vec<serde_json::Value> = chunk
            .iter()
            .map(|ip| serde_json::json!({
                "query": ip,
                "fields": "status,country,countryCode,city,isp,org,as,asname,query"
            }))
            .collect();

        let resp = client
            .post("http://ip-api.com/batch")
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("ip-api.com request failed: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("ip-api.com returned HTTP {}", resp.status()));
        }

        let mut results: Vec<OnlineGeoResult> = resp
            .json()
            .await
            .map_err(|e| format!("ip-api.com parse error: {e}"))?;
        all_results.append(&mut results);
    }

    Ok(all_results)
}

/// Look up geo info for a single IP address.
#[tauri::command]
pub async fn lookup_ip(
    ip: String,
    state: State<'_, AppState>,
) -> Result<Option<IpInfo>, String> {
    let guard = state.geoip.read().map_err(|e| format!("Lock error: {e}"))?;
    match guard.as_ref() {
        None => Ok(None),
        Some(engine) => Ok(engine.lookup(&ip)),
    }
}

/// List all unique source IPs from the loaded dataset with geo enrichment.
/// Paginated, sortable by events/country/asn.
/// If start_ms/end_ms are provided, only counts events within that time range.
#[tauri::command]
pub async fn list_ips(
    page: usize,
    page_size: usize,
    sort_by: String,
    filter_country: Option<String>,
    start_ms: Option<i64>,
    end_ms: Option<i64>,
    state: State<'_, AppState>,
) -> Result<IpPage, String> {
    // Build ip→count map from store (time-filtered if range provided)
    let ip_counts = {
        let store_guard = state.store.read().map_err(|e| format!("Lock error: {e}"))?;
        let store = store_guard.as_ref().ok_or("No dataset loaded")?;
        if let (Some(s), Some(e)) = (start_ms, end_ms) {
            // Build counts only from records in range
            let ids_in_range = store.get_ids_in_range(s, e);
            let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
            for id in ids_in_range {
                if let Some(rec) = store.get_record(id) {
                    if let Some(ip) = &rec.record.source_ip_address {
                        *counts.entry(ip.to_string()).or_insert(0) += 1;
                    }
                }
            }
            counts
        } else {
            store.idx_source_ip
                .iter()
                .map(|(ip, ids)| (ip.to_string(), ids.len()))
                .collect::<std::collections::HashMap<String, usize>>()
        }
    };

    let geoip_guard = state.geoip.read().map_err(|e| format!("Lock error: {e}"))?;
    match geoip_guard.as_ref() {
        None => {
            // No GeoIP engine — return rows without geo data, sorted by events
            let mut rows: Vec<trail_inspector_core::geoip::IpRow> = ip_counts
                .iter()
                .map(|(ip, &count)| trail_inspector_core::geoip::IpRow {
                    ip: ip.clone(),
                    event_count: count,
                    country_code: None,
                    country_name: None,
                    city: None,
                    asn: None,
                    asn_org: None,
                })
                .collect();
            rows.sort_by(|a, b| b.event_count.cmp(&a.event_count));
            let total = rows.len();
            let rows = rows.into_iter().skip(page * page_size).take(page_size).collect();
            Ok(IpPage { rows, total, page, page_size })
        }
        Some(engine) => {
            Ok(engine.list_ips(
                &ip_counts,
                page,
                page_size,
                &sort_by,
                filter_country.as_deref(),
            ))
        }
    }
}
