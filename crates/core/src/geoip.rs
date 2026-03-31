//! Offline GeoIP enrichment engine.
//!
//! Wraps MaxMind's `maxminddb` crate to look up geo and ASN information for
//! source IPs found in CloudTrail logs. Both databases are optional — if not
//! loaded, lookups return `None`.
//!
//! **Required files (user-supplied):**
//! - `GeoLite2-City.mmdb` or `GeoLite2-Country.mmdb` — country / city geo
//! - `GeoLite2-ASN.mmdb` — autonomous system number / org

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpInfo {
    pub ip: String,
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub asn: Option<u32>,
    pub asn_org: Option<String>,
}

/// Paginated IP list entry with event count from the store
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpRow {
    pub ip: String,
    pub event_count: usize,
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub city: Option<String>,
    pub asn: Option<u32>,
    pub asn_org: Option<String>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpPage {
    pub rows: Vec<IpRow>,
    pub total: usize,
    pub page: usize,
    pub page_size: usize,
}

// ---------------------------------------------------------------------------
// GeoIpEngine
// ---------------------------------------------------------------------------

pub struct GeoIpEngine {
    geo_reader: Option<maxminddb::Reader<Vec<u8>>>,
    asn_reader: Option<maxminddb::Reader<Vec<u8>>>,
}

impl GeoIpEngine {
    /// Load one or both MMDB files. Either path may be `None`.
    pub fn load(
        geo_path: Option<&str>,
        asn_path: Option<&str>,
    ) -> Result<Self, String> {
        let geo_reader = geo_path
            .map(|p| maxminddb::Reader::open_readfile(p).map_err(|e| format!("Geo DB error: {e}")))
            .transpose()?;

        let asn_reader = asn_path
            .map(|p| maxminddb::Reader::open_readfile(p).map_err(|e| format!("ASN DB error: {e}")))
            .transpose()?;

        if geo_reader.is_none() && asn_reader.is_none() {
            return Err("At least one MMDB file must be provided".to_string());
        }

        Ok(GeoIpEngine { geo_reader, asn_reader })
    }

    /// Look up a single IP. Returns `None` if the IP is private/invalid or not found.
    pub fn lookup(&self, ip_str: &str) -> Option<IpInfo> {
        let ip: IpAddr = IpAddr::from_str(ip_str).ok()?;

        // Skip private / loopback / link-local
        if is_private(ip) {
            return None;
        }

        let mut info = IpInfo {
            ip: ip_str.to_string(),
            country_code: None,
            country_name: None,
            city: None,
            latitude: None,
            longitude: None,
            asn: None,
            asn_org: None,
        };

        // Geo (city or country DB)
        if let Some(reader) = &self.geo_reader {
            if let Ok(city) = reader.lookup::<maxminddb::geoip2::City>(ip) {
                info.country_code = city.country
                    .as_ref()
                    .and_then(|c| c.iso_code)
                    .map(|s| s.to_string());
                info.country_name = city.country
                    .as_ref()
                    .and_then(|c| c.names.as_ref())
                    .and_then(|n| n.get("en"))
                    .map(|s| s.to_string());
                info.city = city.city
                    .as_ref()
                    .and_then(|c| c.names.as_ref())
                    .and_then(|n| n.get("en"))
                    .map(|s| s.to_string());
                if let Some(loc) = &city.location {
                    info.latitude = loc.latitude;
                    info.longitude = loc.longitude;
                }
            }
        }

        // ASN
        if let Some(reader) = &self.asn_reader {
            if let Ok(asn) = reader.lookup::<maxminddb::geoip2::Asn>(ip) {
                info.asn = asn.autonomous_system_number;
                info.asn_org = asn.autonomous_system_organization.map(|s| s.to_string());
            }
        }

        Some(info)
    }

    /// Bulk enrich all unique IPs from the store's source-IP index.
    /// Returns a map of ip_string → IpInfo.
    pub fn enrich_all(
        &self,
        unique_ips: impl Iterator<Item = String>,
    ) -> HashMap<String, IpInfo> {
        let mut cache = HashMap::new();
        for ip in unique_ips {
            if let Some(info) = self.lookup(&ip) {
                cache.insert(ip, info);
            }
        }
        cache
    }

    // -----------------------------------------------------------------------
    // Query helpers used by IPC commands
    // -----------------------------------------------------------------------

    /// Build a paginated IP list sorted by event count (desc) from an ip→count map.
    pub fn list_ips(
        &self,
        ip_counts: &HashMap<String, usize>,
        page: usize,
        page_size: usize,
        sort_by: &str,    // "events" (default) | "country" | "asn"
        filter_country: Option<&str>,
    ) -> IpPage {
        // Collect enriched rows
        let mut rows: Vec<IpRow> = ip_counts
            .iter()
            .map(|(ip, &count)| {
                let info = self.lookup(ip);
                IpRow {
                    ip: ip.clone(),
                    event_count: count,
                    country_code: info.as_ref().and_then(|i| i.country_code.clone()),
                    country_name: info.as_ref().and_then(|i| i.country_name.clone()),
                    city: info.as_ref().and_then(|i| i.city.clone()),
                    asn: info.as_ref().and_then(|i| i.asn),
                    asn_org: info.as_ref().and_then(|i| i.asn_org.clone()),
                }
            })
            .filter(|r| {
                if let Some(cc) = filter_country {
                    r.country_code.as_deref().unwrap_or("").eq_ignore_ascii_case(cc)
                } else {
                    true
                }
            })
            .collect();

        match sort_by {
            "country" => rows.sort_by(|a, b| {
                a.country_code.as_deref().unwrap_or("ZZZ")
                    .cmp(b.country_code.as_deref().unwrap_or("ZZZ"))
            }),
            "asn" => rows.sort_by(|a, b| a.asn.cmp(&b.asn)),
            _ => rows.sort_by(|a, b| b.event_count.cmp(&a.event_count)),
        }

        let total = rows.len();
        let rows = rows.into_iter().skip(page * page_size).take(page_size).collect();

        IpPage { rows, total, page, page_size }
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local()
                || v4.is_broadcast() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}
