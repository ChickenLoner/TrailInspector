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
- `idx_*` posting lists are `roaring::RoaringBitmap`; iterating a `&RoaringBitmap` yields `u32` ascending by id.
- Field→index lookup: use `Store::index_for(field)` -> `&HashMap<Arc<str>, RoaringBitmap>`, don't re-match the 11 fields.
- `RoaringBitmap::len()` is u64 — add `as usize` where a usize is expected.
- simd-json can't deserialize `Box<serde_json::value::RawValue>` — don't swap parser.rs to it.
- `IndexedRecord` has no `Debug`; use `match` not `unwrap_err()` in parser tests.
- Parser accepts both `{"Records":[...]}` and `lookup-events` `{"Events":[{"CloudTrailEvent":"..."}]}`.
- `crates/core/examples/*.rs` build on default features — feature-gated example code breaks `cargo test`.
- AWS SDK sits behind core's `aws` feature; app enables it always, core default stays offline.
- SDK errors: use `fetch::aws_message`, not `DisplayErrorContext` — latter dumps the raw response.
- LocalStack/CTF: set `endpoint_url`; S3 auto-switches to path-style addressing.
- Rust SDK sends short `X-Amz-Target`; CLI sends `com.amazonaws.*` — emulators need qualified.
- Rewrite signed headers in `modify_before_signing`, never after — signature covers them.
- Compare against `aws <cmd> --debug` before assuming an endpoint lacks an operation.
