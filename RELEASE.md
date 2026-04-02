## TrailInspector v1.1.0 — Performance Optimization

This release eliminates OOM crashes when loading large CloudTrail datasets (1M–3M events), reducing memory usage by ~60–70%.

### What's New

- **1M–3M event support** — the app no longer crashes on large datasets
- **~60–70% memory reduction** — 1M events now uses ~500–800 MB instead of ~2.5 GB
- **JSON blob optimization** — `requestParameters`, `responseElements`, `additionalEventData`, and `sessionContext` stored as raw JSON text (`Box<RawValue>`) instead of parsed value trees; saves 500 MB–1.1 GB for 1M records
- **String interning** — all 11 inverted indexes now share `Arc<str>` keys via a `StringPool`; repeated values like `"us-east-1"` stored once instead of millions of times; saves 150–300 MB
- **No-clone query engine** — empty queries paginate directly from the sorted index without cloning the full ID vec (8 MB saved per search call)
- **Fast timeline/stats** — empty-query timeline and field stats read directly from inverted indexes; no full ID materialization (96 MB saved per refresh)
- **Lazy event detail** — `raw` payload removed from search results; only fetched on-demand when a row is clicked
- **Alert IPC cap** — alert `matchingRecordIds` capped at 100 per alert; `matchingCount` field carries the true count

### Bug Fixes / Cleanup

- Removed unused `extra: HashMap<String, Value>` fields from `CloudTrailRecord` and `UserIdentity` (saves 100–400 MB and speeds up deserialization)
- `serde(flatten)` removal improves JSON parse performance for all records

---

## TrailInspector v1.0.0 — Investigation Platform

This release evolves TrailInspector from a log viewer into a full cloud investigation platform, delivering EG-CERT's recommended enhancements: expanded detection coverage, session activity grouping, and offline IP enrichment.

### What's New

- **60 detection rules** — +42 new rules covering VPC/Network, RDS, EBS, Lambda, resource sharing, Defense Evasion, Credential Access, and Geo Anomalies (up from 18)
- **Session Grouping** — events are automatically clustered into sessions by `(identity, source IP)` with a 30-minute inactivity gap; new Sessions tab shows activity timelines
- **IP Enrichment** — offline GeoIP lookup via MaxMind GeoLite2; country, city, ASN per source IP; new IPs tab
- **Geo Anomaly Rules** — GEO-01 (same identity from multiple countries) and GEO-02 (console login from new country)
- **Session-Alert Correlation** — SessionDetail surfaces related alerts; AlertDetail surfaces owning sessions; AssumeRole chains link sessions across accounts
- **Detection UI** — severity filter chips, group-by (Severity / Service / Tactic), search box, collapsible sections
- **107 automated tests** — covering all 40+ new detection rules, session engine, and GeoIP engine

### Installation

| Platform | File |
|----------|------|
| Windows 10+ | `.exe` (NSIS installer) |
| macOS 11+ | `.dmg` disk image |
| Linux | `.deb` package or `.AppImage` |

### GeoIP Setup (Optional)

Download the free **DB-IP Lite** databases (no registration required, CC BY 4.0) from [db-ip.com/db/lite](https://db-ip.com/db/lite) and load them via the IP tab to enable IP enrichment and geo anomaly rules:
- `dbip-city-lite.mmdb`
- `dbip-asn-lite.mmdb`

### Built with

Tauri v2 · Rust · React · TypeScript · TailwindCSS

---

## TrailInspector v0.1.0 — Initial Release

First public release of TrailInspector, an offline desktop tool for investigating AWS CloudTrail logs.

### Features

- **Ingest** — load `.json.gz` files from standard AWS directory structures, or drop a ZIP archive; parallel decompression via Rayon
- **Search** — SPL-like query syntax with `AND`, `OR`, `NOT`, wildcards, and field-level filtering (`eventName=AssumeRole AND errorCode=*`)
- **Timeline** — histogram of event volume over time; field statistics breakdown
- **Detections** — 18 MITRE ATT&CK-mapped rules covering privilege escalation, credential access, persistence, and defense evasion
- **Evidence linking** — click any alert to auto-filter the event table to matching evidence
- **Export** — save filtered results as CSV or JSON
- **Session persistence** — query state and active tab survive app restarts
- **Keyboard shortcuts** — `/` to focus query bar, `Escape` to clear, `Ctrl+E` to export
- **No cloud required** — works fully offline; no AWS credentials needed

### Installation

| Platform | File |
|----------|------|
| Windows 10+ | `.exe` (NSIS installer) |
| macOS 11+ | `.dmg` disk image |
| Linux | `.deb` package or `.AppImage` |

> **Linux note:** The `.AppImage` runs on any modern distro without installation. The `.deb` targets Debian/Ubuntu.

### Built with

Tauri v2 · Rust · React · TypeScript · TailwindCSS

---

*Made by Warawut Manosong (Chicken0248)*
