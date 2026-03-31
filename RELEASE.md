## TrailInspector v0.2.0 — Investigation Platform

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
| Windows 10+ | `.msi` installer |
| macOS 11+ | `.dmg` disk image |
| Linux | `.deb` package or `.AppImage` |

### GeoIP Setup (Optional)

Download the free **GeoLite2** databases from MaxMind and load them via Settings → GeoIP to enable IP enrichment and geo anomaly rules:
- `GeoLite2-City.mmdb`
- `GeoLite2-ASN.mmdb`

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
| Windows 10+ | `.msi` installer |
| macOS 11+ | `.dmg` disk image |
| Linux | `.deb` package or `.AppImage` |

> **Linux note:** The `.AppImage` runs on any modern distro without installation. The `.deb` targets Debian/Ubuntu.

### Built with

Tauri v2 · Rust · React · TypeScript · TailwindCSS

---

*Made by Warawut Manosong (Chicken0248)*
