# TrailInspector

AWS CloudTrail log analyzer — Tauri v2 + Rust + React desktop app.

## Stack
- **Backend:** Rust (`crates/core` — pure library, `crates/app` — Tauri thin wrapper)
- **Frontend:** React + TypeScript + Vite + TailwindCSS (`ui/`)
- **Distribution:** Single binary per platform

## Hard Rules
- `crates/core` must NEVER import Tauri — testable standalone with `cargo test -p trail-inspector-core`
- All business logic (parse, index, query, detect) lives in `crates/core`; `crates/app` is IPC glue only
- Never send >500 records per IPC call — always paginate
- Use `serde_json::from_slice` after `read_to_end`, never `from_reader` (2-5x slower)
- Use `flate2` with `zlib-ng` backend, `rayon` for parallel ingestion, `walkdir` for traversal
- Error handling: `anyhow` in app crate, `thiserror` in core crate

## Build Status
- ✅ Phase 1 — Ingestion + event table
- ✅ Phase 2 — Query engine + filter panel + query bar (SPL-like syntax, OR/AND/NOT/wildcards)
- ✅ Phase 3 — Timeline histogram + field stats + identity timeline
- ✅ Phase 4 — 18 MITRE-mapped detection rules + alert UI + "View Evidence" auto-filter
- ✅ Phase 5 — Export, ZIP ingest, keyboard shortcuts, session persistence, StatusBar, CI (GitHub Actions), dark theme polish, error handling

## v1.0.0 Progress (EG-CERT Enhancements) ✅ COMPLETE
- ✅ v1.0 P1 — Detection module restructured into per-tactic files; 60 rules (+42 new: VPC/NW, RDS, EBS, Lambda, resource sharing, IAM, Defense Evasion); `service` field added to Alert
- ✅ v1.0 P2 — Detection UI: severity filter chips, group-by (Severity/Service/Tactic), search box
- ✅ v1.0 P3 — Session grouping engine (core) + Sessions UI tab; 30-min gap clustering by (identity, IP)
- ✅ v1.0 P4 — GeoIP engine (maxminddb, offline MMDB) + IpView tab (IP table, geo detail panel, loader)
- ✅ v1.0 P5 — Geo anomaly rules GEO-01/02 (multi-country identity, unusual login country) + EventDetail geo enrichment
- ✅ v1.0 P6 — Session-alert correlation: SessionDetail shows alert badges; AlertDetail shows owning sessions
- ✅ v1.0 P7 — Phase 10 polish: 107 unit tests (63 detection rule tests, 30 session tests, 10 GeoIP tests); RULES.md, CHANGELOG.md created; README.md updated for v1.0.0

## Commands
```bash
cd ui && npm run dev                  # frontend dev server (port 5500)
cargo tauri dev                       # full app (requires frontend running first)
cargo test -p trail-inspector-core    # core tests
cargo tauri build                     # production build
```

## Sample Data (`samples/`, gitignored)
- `AWSLogs/` — `.json.gz` in standard AWS directory structure
- `blizzardbreakdown/` — ~130MB compressed, multi-region
- `hbk_denouement/` — ~25MB
- `nubilum_2/` — ~7MB
