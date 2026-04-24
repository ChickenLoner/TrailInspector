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
- `custom_rules_test/` — 13 synthetic events targeting CR-01 through CR-05 (plain `.json`, not gzipped)

## Applied Learning
When something fails repeatedly, when user has to re-explain, or when a workaround is found for a tool limitation, add one-liner bullet here. Keep each bullet under 15 words. No explaination. Only add things that will save time in future session
