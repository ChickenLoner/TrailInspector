# TrailInspector — Performance Optimization Plan

> **Goal:** Handle 1M–3M events without crashing.
> Current: crashes at 1M (~2–4 GB heap). Target: ~400–700 MB for 1M records.

---

## Root Causes

| Cause | Location | Impact |
|-------|----------|--------|
| `#[serde(flatten)]` `extra: HashMap<String, Value>` × 2 structs | `model.rs` | 100–400 MB overhead (never read, never used) |
| `request_parameters/response_elements` as `serde_json::Value` trees | `model.rs` | 500 MB–1.1 GB (biggest single cost) |
| 11 inverted indexes with duplicated `String` keys | `store.rs` | 150–300 MB (e.g. "us-east-1" cloned millions of times) |
| `time_sorted_ids.clone()` on every empty-query search | `engine.rs` | 8 MB per call |
| `execute(store, query, 0, usize::MAX)` for timeline/stats | `stats.rs` | 96 MB per stats refresh |
| `raw: CloudTrailRecord` in every RecordRow IPC response | `query.rs` | ~500 KB per page, unnecessary |
| All alert `matching_record_ids` serialized over IPC | `detection.rs` | Potentially MBs |

---

## Implementation Phases

### Phase A — Memory Reduction (Fix the Crash)

#### A1. Remove `extra` HashMap [x]
**Files:** `crates/core/src/model.rs`, test helpers in `detection/tests.rs` + `session.rs`
- Remove `#[serde(flatten)] pub extra: HashMap<String, serde_json::Value>` from `CloudTrailRecord` and `UserIdentity`
- Never read anywhere. Removing `flatten` also speeds up deserialization.
- **Savings: 100–400 MB**

#### A2. Store JSON blobs as `Box<RawValue>` [x]
**Files:** `crates/core/Cargo.toml` (add `raw_value` feature), `model.rs`, `store.rs` (bucket name indexing), `stats.rs` (bucketName in top_field_values), all detection rules using `.get("field")`
- Change `request_parameters`, `response_elements`, `additional_event_data`, `session_context` from `Option<serde_json::Value>` → `Option<Box<serde_json::value::RawValue>>`
- Add `parse_request_parameters()` / `parse_response_elements()` / `parse_additional_event_data()` helpers on `CloudTrailRecord` for the ~10 rules using `.get("fieldName")`
- Rules using `.to_string().contains(...)` → `.get().contains(...)` (simpler)
- **Savings: 500 MB–1.1 GB**

#### A3. String interning for inverted index keys [x]
**Files:** `crates/core/src/store/store.rs`, `crates/app/src/commands/query.rs`
- Add `StringPool` (`HashMap<Box<str>, Arc<str>>`) to `Store`
- Change all 11 index types from `HashMap<String, Vec<u64>>` → `HashMap<Arc<str>, Vec<u64>>`
- `index_push()` interns through the pool. Detection rules / query engine unchanged (Borrow trait).
- `get_field_values` in `query.rs`: `k.to_string()` on Arc<str> key (minor tweak)
- **Savings: 150–300 MB**

#### A4. Intern string fields in CloudTrailRecord [ ]
**Files:** `model.rs`, `store.rs` (post-parse interning), test helpers
- Change 7 high-repetition fields to `Arc<str>`: `event_source`, `event_name`, `aws_region`, `source_ip_address`, `error_code`, `identity_type`, `account_id`
- After `parse_records()`, replace fields with pooled versions using same StringPool from A3
- **Savings: 100–200 MB**

---

### Phase B — Eliminate Transient Allocation Spikes

#### B1. Refactor `execute()` to skip cloning for empty queries [x]
**File:** `crates/core/src/query/engine.rs`
- Empty query: paginate directly from `store.time_sorted_ids[start..end]` — no clone
- Time-range-only query: use `Cow::Borrowed` to avoid cloning the full slice
- **Saves: 8 MB per search call**

#### B2. Dedicated timeline/stats functions skipping ID materialization [x]
**Files:** `crates/core/src/stats.rs`, `crates/app/src/commands/stats.rs`
- `get_timeline` with empty query: iterate `&store.time_sorted_ids` directly
- `get_top_fields` with empty query: read counts from inverted index (`v.len()`) — O(unique_values)
- **Saves: ~96 MB per stats refresh**

#### B3. Remove `raw` from RecordRow, load on-demand [x]
**Files:** `crates/app/src/commands/query.rs`, `ui/src/lib/tauri.ts`, `ui/src/components/results/EventDetail.tsx`, `ui/src/App.tsx`
- Remove `raw: CloudTrailRecord` from `RecordRow` and from search mapping
- `EventDetail` calls existing `get_record_by_id` when user clicks a row
- **Saves: ~100–500 KB IPC per page**

---

### Phase C — Frontend Resilience

#### C1. Cap alert `matching_record_ids` in IPC response [x]
**Files:** `crates/app/src/commands/detection.rs`, `crates/core/src/detection/mod.rs`
- Add `matching_count: usize` to `Alert` struct
- Truncate `matching_record_ids` to 100 in IPC response
- **Saves: potentially MBs for large alert result sets**

---

## Implementation Order

1. **A1** — remove extra (lowest risk, immediate 100–400 MB win)
2. **B1** — execute no-clone (15 min, removes per-call spike)
3. **B3** — remove raw from RecordRow (IPC savings)
4. **A3** — intern index keys (150–300 MB)
5. **B2** — direct timeline/stats (96 MB/call)
6. **A2** — RawValue JSON blobs (biggest win, highest risk)
7. **C1** — cap alert IDs
8. **A4** — intern record strings (100–200 MB)

## Verification

After each step: `cargo test -p trail-inspector-core`
After all steps: load 1M → 2M → 3M event datasets, smoke-test all tabs.
