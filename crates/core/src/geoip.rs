//! Offline GeoIP enrichment engine.
//!
//! Wraps the `maxminddb` crate to look up geo and ASN information for
//! source IPs found in CloudTrail logs. Both databases are optional — if not
//! loaded, lookups return `None`.
//!
//! **Recommended files (user-supplied, free, no registration):**
//! - `dbip-city-lite.mmdb` or `dbip-country-lite.mmdb` — country / city geo
//! - `dbip-asn-lite.mmdb` — autonomous system number / org
//! Download from: https://db-ip.com/db/lite.php (CC BY 4.0)

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

/// Memoised lookups are capped so a dataset with millions of distinct IPs cannot grow the cache
/// without bound; past the cap, lookups simply go to the database as before.
const MAX_CACHE_ENTRIES: usize = 500_000;

pub struct GeoIpEngine {
    // Memory-mapped: a City database is over 100 MB, and reading it into a Vec made loading slow
    // and doubled the memory the page cache already holds. The mapping is read-only; replacing the
    // file on disk while it is loaded is not supported (Windows refuses, others may fault).
    geo_reader: Option<maxminddb::Reader<maxminddb::Mmap>>,
    asn_reader: Option<maxminddb::Reader<maxminddb::Mmap>>,
    /// IP -> result. GEO-01 and GEO-02 look up once per *event*, but a dataset has far fewer
    /// distinct IPs than events, and each uncached lookup walks two search trees and allocates.
    cache: dashmap::DashMap<IpAddr, Option<IpInfo>>,
}

impl GeoIpEngine {
    /// Load one or both MMDB files. Either path may be `None`.
    pub fn load(
        geo_path: Option<&str>,
        asn_path: Option<&str>,
    ) -> Result<Self, String> {
        let geo_reader = geo_path
            .map(|p| maxminddb::Reader::open_mmap(p).map_err(|e| format!("Geo DB error: {e}")))
            .transpose()?;

        let asn_reader = asn_path
            .map(|p| maxminddb::Reader::open_mmap(p).map_err(|e| format!("ASN DB error: {e}")))
            .transpose()?;

        if geo_reader.is_none() && asn_reader.is_none() {
            return Err("At least one MMDB file must be provided".to_string());
        }

        Ok(GeoIpEngine::new(geo_reader, asn_reader))
    }

    fn new(
        geo_reader: Option<maxminddb::Reader<maxminddb::Mmap>>,
        asn_reader: Option<maxminddb::Reader<maxminddb::Mmap>>,
    ) -> Self {
        GeoIpEngine { geo_reader, asn_reader, cache: dashmap::DashMap::new() }
    }

    /// Drop every memoised lookup. Called when a new dataset is loaded so the previous dataset's
    /// IPs do not stay resident.
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Look up a single IP. Returns `None` if the IP is private/invalid or not found.
    pub fn lookup(&self, ip_str: &str) -> Option<IpInfo> {
        let ip: IpAddr = IpAddr::from_str(ip_str).ok()?;

        // Skip private / loopback / link-local
        if is_private(ip) {
            return None;
        }

        // Keyed by the parsed address, so `::ffff:1.2.3.4` and other spellings share an entry.
        // A hit reports the caller's own spelling of the address.
        if let Some(hit) = self.cache.get(&ip) {
            return hit.value().clone().map(|mut info| {
                info.ip = ip_str.to_string();
                info
            });
        }
        let info = self.lookup_uncached(ip, ip_str);
        if self.cache.len() < MAX_CACHE_ENTRIES {
            self.cache.insert(ip, info.clone());
        }
        info
    }

    fn lookup_uncached(&self, ip: IpAddr, ip_str: &str) -> Option<IpInfo> {
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

        // Neither database knew this address. Returning an all-`None` record made it look like a
        // resolved public IP with an unknown country; report "no data" instead.
        if info.country_code.is_none() && info.asn.is_none() {
            return None;
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
        IpAddr::V6(v6) => {
            // `::ffff:10.0.0.1` is the private IPv4 address in IPv6 clothing.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || (first & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || (first & 0xfe00) == 0xfc00 // fc00::/7 unique local
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // GeoIpEngine::load error cases (no MMDB files needed)
    // -----------------------------------------------------------------------

    #[test]
    fn test_load_no_paths_returns_error() {
        let result = GeoIpEngine::load(None, None);
        let msg = result.err().expect("load(None, None) must return Err");
        assert!(
            msg.contains("At least one MMDB file"),
            "error message should mention MMDB requirement, got: {}", msg
        );
    }

    #[test]
    fn test_load_nonexistent_geo_path_returns_error() {
        let result = GeoIpEngine::load(Some("/nonexistent/GeoLite2-City.mmdb"), None);
        let msg = result.err().expect("load with nonexistent geo path must return Err");
        assert!(msg.contains("Geo DB error"), "error message should mention Geo DB: {}", msg);
    }

    #[test]
    fn test_load_nonexistent_asn_path_returns_error() {
        let result = GeoIpEngine::load(None, Some("/nonexistent/GeoLite2-ASN.mmdb"));
        let msg = result.err().expect("load with nonexistent ASN path must return Err");
        assert!(msg.contains("ASN DB error"), "error message should mention ASN DB: {}", msg);
    }

    // -----------------------------------------------------------------------
    // is_private helper (tested indirectly via enrich_all)
    // -----------------------------------------------------------------------

    /// Verify private/loopback IPs are recognised as such by parsing them ourselves.
    #[test]
    fn test_is_private_addresses() {
        use std::net::IpAddr;
        use std::str::FromStr;

        let private_cases = [
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.5",
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "febf::1",
            "fc00::1",
            "fd12:3456:789a::1",
            "::ffff:10.0.0.1",
            "::ffff:192.168.1.1",
            "::ffff:127.0.0.1",
        ];
        for ip_str in &private_cases {
            let ip = IpAddr::from_str(ip_str).unwrap();
            assert!(
                is_private(ip),
                "{} should be classified as private/special",
                ip_str
            );
        }
    }

    #[test]
    fn test_is_not_private_for_public_addresses() {
        use std::net::IpAddr;
        use std::str::FromStr;

        let public_cases = [
            "8.8.8.8", "1.1.1.1", "203.0.113.1", "2001:4860:4860::8888",
            "2606:4700::1111", "::ffff:8.8.8.8", "fec0::1", "fbff::1",
        ];
        for ip_str in &public_cases {
            let ip = IpAddr::from_str(ip_str).unwrap();
            assert!(
                !is_private(ip),
                "{} should NOT be classified as private",
                ip_str
            );
        }
    }

    /// With no database to answer, a lookup has nothing to report: it must be `None`, not an
    /// all-`None` record that reads as "public IP, unknown country".
    #[test]
    fn test_lookup_without_any_match_is_none() {
        let engine = GeoIpEngine::new(None, None);
        assert!(engine.lookup("8.8.8.8").is_none());
        assert!(engine.lookup("fe80::1").is_none());
        assert!(engine.lookup("not an ip").is_none());
    }

    /// Lookups are memoised per parsed address (including "not found"), private addresses never
    /// reach the cache, and `clear_cache` empties it.
    #[test]
    fn test_lookup_cache_behaviour() {
        let engine = GeoIpEngine::new(None, None);
        assert!(engine.lookup("8.8.8.8").is_none());
        assert_eq!(engine.cache.len(), 1, "a public miss is cached");
        assert!(engine.lookup("8.8.8.8").is_none());
        assert_eq!(engine.cache.len(), 1, "a repeat lookup reuses the entry");
        // Two spellings of one address share an entry.
        assert!(engine.lookup("::ffff:8.8.4.4").is_none());
        assert!(engine.lookup("::ffff:808:404").is_none());
        assert_eq!(engine.cache.len(), 2);
        // Private ranges are rejected before the cache.
        assert!(engine.lookup("10.0.0.1").is_none());
        assert!(engine.lookup("fe80::1").is_none());
        assert_eq!(engine.cache.len(), 2);
        engine.clear_cache();
        assert_eq!(engine.cache.len(), 0);
    }

    /// Per-record lookup cost, the access pattern of GEO-01/GEO-02 (one lookup per event, far
    /// fewer distinct IPs than events). Needs a real City `.mmdb`, so it does nothing unless
    /// `TRAIL_INSPECTOR_BENCH_MMDB` points at one:
    /// `TRAIL_INSPECTOR_BENCH_MMDB=/path/city.mmdb cargo test -p trail-inspector-core --release -- --ignored bench_geo_lookup --nocapture`
    #[test]
    #[ignore]
    fn bench_geo_lookup_per_record() {
        let Ok(path) = std::env::var("TRAIL_INSPECTOR_BENCH_MMDB") else {
            eprintln!("set TRAIL_INSPECTOR_BENCH_MMDB to a City .mmdb to run this benchmark");
            return;
        };
        let t = std::time::Instant::now();
        let engine = GeoIpEngine::load(Some(&path), None).unwrap();
        let load = t.elapsed();
        let ips: Vec<String> = (0..50_000u32)
            .map(|i| format!("{}.{}.{}.{}", 1 + i % 222, (i * 7) % 256, (i / 222) % 256, 1 + i % 250))
            .collect();
        let t = std::time::Instant::now();
        let mut resolved = 0usize;
        for r in 0..1_000_000usize {
            if engine.lookup(&ips[r % ips.len()]).and_then(|i| i.country_code).is_some() {
                resolved += 1;
            }
        }
        println!("GeoIP load {load:?}; 1M lookups over 50k distinct IPs: {:?} ({resolved} resolved)", t.elapsed());
        assert!(resolved > 0);
    }

    // -----------------------------------------------------------------------
    // IpPage / list_ips logic (pagination + sorting) — exercised without MMDB
    // -----------------------------------------------------------------------

    /// When both MMDB readers are absent the engine cannot be constructed, so we
    /// test list_ips indirectly through the IpRow sorting logic by verifying the
    /// data structures are correct (no engine call needed).
    #[test]
    fn test_ip_row_sort_by_events() {
        // Manually construct IpRows (same as what list_ips would produce) and
        // verify the expected ordering.
        let mut rows = vec![
            IpRow {
                ip: "1.1.1.1".to_string(),
                event_count: 5,
                country_code: None,
                country_name: None,
                city: None,
                asn: None,
                asn_org: None,
            },
            IpRow {
                ip: "2.2.2.2".to_string(),
                event_count: 20,
                country_code: None,
                country_name: None,
                city: None,
                asn: None,
                asn_org: None,
            },
            IpRow {
                ip: "3.3.3.3".to_string(),
                event_count: 1,
                country_code: None,
                country_name: None,
                city: None,
                asn: None,
                asn_org: None,
            },
        ];
        rows.sort_by(|a, b| b.event_count.cmp(&a.event_count));
        assert_eq!(rows[0].ip, "2.2.2.2");
        assert_eq!(rows[1].ip, "1.1.1.1");
        assert_eq!(rows[2].ip, "3.3.3.3");
    }

    #[test]
    fn test_ip_page_serialises() {
        let page = IpPage {
            rows: vec![],
            total: 0,
            page: 0,
            page_size: 25,
        };
        let json = serde_json::to_string(&page).unwrap();
        assert!(json.contains("pageSize"));
    }

    #[test]
    fn test_ip_info_all_none_serialises() {
        let info = IpInfo {
            ip: "8.8.8.8".to_string(),
            country_code: None,
            country_name: None,
            city: None,
            latitude: None,
            longitude: None,
            asn: None,
            asn_org: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("8.8.8.8"));
    }
}
