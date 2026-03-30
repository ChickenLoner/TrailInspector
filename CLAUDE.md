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

## v0.2.0 Progress (EG-CERT Enhancements)
- ✅ v0.2 P1 — Detection module restructured into per-tactic files; 38 rules (18→38, +20 new: VPC/NW, RDS, IAM PE-05/06/07, CA-05/06, DE-05..13, EX-02..05, IM-03); `service` field added to Alert
- 🔲 v0.2 P2 — Phase 3 rules batch (EBS, Lambda, resource sharing)
- 🔲 v0.2 P3 — Detections UI grouping/filtering by service
- 🔲 v0.2 P4 — Session grouping engine (core)
- 🔲 v0.2 P5 — Sessions UI tab
- 🔲 v0.2 P6 — GeoIP enrichment engine
- 🔲 v0.2 P7 — IP enrichment UI + geo anomaly rules
- 🔲 v0.2 P8 — Session-alert correlation

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
