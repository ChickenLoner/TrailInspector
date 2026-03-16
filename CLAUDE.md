# TrailInspector

AWS CloudTrail Log Analyzer — cross-platform desktop app (Windows/Linux/macOS).

## Stack

- **Backend:** Rust (Cargo workspace)
- **Frontend:** React + TypeScript + Vite
- **Framework:** Tauri v2
- **Distribution:** Single binary per platform

## Project Structure

```
TrailInspector/
├── crates/
│   ├── core/          # Pure Rust library — NO Tauri dependency. All parsing, indexing, query, detection logic.
│   └── app/           # Tauri v2 app crate — thin IPC wrapper over core. Commands + state management.
├── ui/                # React frontend (Vite + TypeScript + TailwindCSS)
└── samples/           # Test datasets (gitignored)
```

## Architecture Rules

- `crates/core` must NEVER depend on Tauri. It is a standalone library, testable with `cargo test -p trail-inspector-core`.
- `crates/app` is a thin adapter layer — Tauri commands call into core, nothing more.
- All business logic (parsing, indexing, querying, detection) lives in `crates/core`.
- Frontend communicates with backend ONLY via Tauri commands (invoke) and Channels.
- Never send more than 500 records per IPC call — always paginate.
- Use Tauri v2 Channels (`tauri::ipc::Channel<T>`) for streaming progress, NOT events.

## Rust Conventions

- Use `serde_json::from_slice` after `read_to_end`, never `serde_json::from_reader` (2-5x slower).
- Use `flate2` with `zlib-ng` backend for gzip decompression.
- Use `rayon` for parallel file processing.
- Use `walkdir` for recursive directory traversal.
- CloudTrail record struct uses `#[serde(rename_all = "camelCase")]` and `#[serde(flatten)]` for forward compatibility.
- Error handling: `anyhow` in the app crate, `thiserror` in the core crate.

## Frontend Conventions

- Dark theme by default (Splunk-inspired).
- Virtualized tables for large result sets (`@tanstack/react-virtual`).
- Query bar uses CodeMirror 6 for syntax highlighting.
- Filter panel and query bar stay in sync — changing one updates the other.

## Detection Rules

- Rules are plain Rust functions, not a DSL or config files.
- Each rule receives `&Store` and returns `Vec<Alert>`.
- Rules are categorized by MITRE ATT&CK tactic.
- Three rule types: stateless (single-event), threshold (windowed count), baseline (behavioral).

## Build Phases

1. **Foundation** — Ingestion + event table (MVP)
2. **Search** — Query bar + filter panel + time range
3. **Visualization** — Timeline histogram + field stats + identity view
4. **Detection** — 28 heuristic rules + alert dashboard
5. **Polish** — Export, session persistence, cross-platform CI

See `PLAN.md` for full implementation details.

## Commands

```bash
# Dev
cd ui && npm run dev          # Frontend dev server
cargo tauri dev               # Full app dev mode

# Test
cargo test -p trail-inspector-core   # Core library tests
cargo test                           # All tests

# Build
cargo tauri build             # Production build for current platform
```

## Sample Data

Test datasets in `samples/` (gitignored):
- `AWSLogs/` — Raw CloudTrail export (`.json.gz` in standard AWS directory structure)
- `blizzardbreakdown/` — Multi-region challenge dataset (~130MB compressed)
- `hbk_denouement/` — HeartBreaker challenge dataset (~25MB compressed)
- `nubilum_2/` — Smaller challenge dataset (~7MB compressed)

All are standard CloudTrail format: `{"Records": [...]}` per file, gzip compressed.
