use tauri::State;
use trail_inspector_core::geoip::{GeoIpEngine, IpInfo, IpPage};
use crate::state::AppState;

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
                        *counts.entry(ip.clone()).or_insert(0) += 1;
                    }
                }
            }
            counts
        } else {
            store.idx_source_ip
                .iter()
                .map(|(ip, ids)| (ip.clone(), ids.len()))
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
