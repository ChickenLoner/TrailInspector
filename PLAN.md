# TrailInspector — Performance Optimization Plan

## v1.1.0 Optimizations (COMPLETE)

> **Goal:** Handle 1M–3M events without crashing.
> Result: ~60-70% memory reduction achieved.

<details>
<summary>Completed optimizations (click to expand)</summary>

| Step | Description | Savings | Status |
|------|-------------|---------|--------|
| A1 | Remove `extra` HashMap from CloudTrailRecord/UserIdentity | 100–400 MB | [x] |
| A2 | Store JSON blobs as `Box<RawValue>` instead of parsed Value trees | 500 MB–1.1 GB | [x] |
| A3 | String interning for inverted index keys (StringPool + Arc<str>) | 150–300 MB | [x] |
| B1 | Skip cloning for empty queries (Cow, direct slice) | 8 MB/call | [x] |
| B2 | Dedicated timeline/stats skipping ID materialization | 96 MB/call | [x] |
| B3 | Remove `raw` from RecordRow, load on-demand | 100–500 KB/page | [x] |
| C1 | Cap alert `matching_record_ids` to 100 in IPC | MBs | [x] |

</details>

---

## v1.1.1 Hotfix — mmap Blob Reads (COMPLETE)

> **Problem:** v1.1.0 Phase F introduced slow load times (unbuffered writes) and slow filters (seek+read per blob).
> **Fix:** BufWriter during ingestion + `seal()` → `memmap2::Mmap` after ingestion. All reads now lock-free pointer arithmetic.
> **Result:** Load time and filter speed restored to pre-v1.1.0 levels. Memory savings unchanged.

---

## v1.2.0 Optimizations — Scale to 5M–10M Events

> **Goal:** 5M events in ~2–3 GB, 10M events in ~4–6 GB.
> Current: 5M events = ~7–8 GB (unstable). Target: ~60–70% further reduction.

### Current Memory Breakdown (5M events)

| Component | Size | Why |
|-----------|------|-----|
| CloudTrailRecord owned Strings | ~3.5 GB | ~20 String fields (24 bytes stack + heap each), duplicated millions of times for values like "us-east-1", "ListBuckets" |
| RawValue blobs in memory | ~2.0 GB | request_parameters, response_elements, additional_event_data kept in RAM but only needed on-demand |
| Inverted indexes (11 × Vec<u64>) | ~500 MB | u64 IDs (8 bytes) when u32 (4 bytes) suffices |
| Sessions, time index, overhead | ~300 MB | event_ids Vec<u64>, duplicated strings |
| **Total** | **~6.3 GB** | |

### Target Budget (5M events)

| Component | Current | After | Savings |
|-----------|---------|-------|---------|
| CloudTrailRecord strings | ~3.5 GB | ~1.0 GB | ~2.5 GB (interning) |
| RawValue blobs | ~2.0 GB | ~180 MB | ~1.8 GB (disk offload) |
| Inverted indexes | ~500 MB | ~250 MB | ~250 MB (u32 IDs) |
| Sessions + other | ~300 MB | ~200 MB | ~100 MB (cleanups) |
| **Total** | **~6.3 GB** | **~1.6 GB** | **~4.7 GB** |

---

### Phase D — Use u32 Record IDs (~250 MB savings) [x]

**Simplest change, zero new dependencies.**

Change all record IDs from `u64` to `u32`. Max 4,294,967,295 records — more than enough for 10M events.

**Files:**
- `crates/core/src/model.rs` — `IndexedRecord.id: u32`
- `crates/core/src/store/store.rs` — All `Vec<u64>` → `Vec<u32>` in 11 indexes + `time_sorted_ids`
- `crates/core/src/session.rs` — `event_ids: Vec<u32>`, all u64 ID references
- `crates/core/src/query/engine.rs` — `HashSet<u32>`, query results
- `crates/core/src/detection/mod.rs` — `matching_record_ids: Vec<u32>`
- `crates/core/src/stats.rs` — ID references
- `crates/core/src/export.rs` — ID references
- `crates/app/src/commands/*.rs` — IPC ID types

**Savings:** 11 indexes × 5M × 4 bytes + time_sorted_ids 20MB + session 20MB = **~260 MB**

---

### Phase E — Intern CloudTrailRecord String Fields (~2–2.5 GB savings) [x]

**Biggest single win. CloudTrail data is extremely repetitive.**

Change all repetitive String fields in `CloudTrailRecord` and `UserIdentity` to `Arc<str>`, intern through the existing `StringPool` during ingestion.

**Cardinality analysis (typical 5M event dataset):**
- `event_source`: ~50 unique values → 5M duplicates eliminated
- `event_name`: ~200 unique → 5M duplicates eliminated
- `aws_region`: ~20 unique → 5M duplicates eliminated
- `user_agent`: ~1K–5K unique → high duplication
- `source_ip_address`: ~10K–100K unique → moderate duplication
- `identity_type`: ~5 unique → extreme duplication
- `account_id`: ~1–100 unique → extreme duplication

**Per-field savings math:**
- `String` = 24 bytes stack + N bytes heap per instance
- `Arc<str>` = 16 bytes stack, shared heap (one alloc per unique value)
- Example: `event_name` with 200 unique values across 5M events — String: 220 MB, Arc<str>: 80 MB = **140 MB saved per field**
- Across ~16 fields: **~2–2.5 GB total savings**

**Fields to intern (CloudTrailRecord):**
- `event_time`, `event_source`, `event_name`, `aws_region` — mandatory, low cardinality
- `source_ip_address`, `user_agent` — optional, medium cardinality
- `error_code`, `error_message` — optional, low cardinality
- `event_type`, `event_category`, `recipient_account_id` — optional, very low cardinality

**Fields to intern (UserIdentity):**
- `identity_type`, `arn`, `account_id`, `user_name`, `principal_id`, `invoked_by`

**Fields to leave as String (unique per event):**
- `request_id`, `event_id`, `shared_event_id`, `session_credential_from_console`

**Fields to drop entirely:**
- `event_version` — never used in queries, detection, or UI

**Implementation:**
1. Change field types in `model.rs` from `String` → `Arc<str>`, `Option<String>` → `Option<Arc<str>>`
2. serde handles `Arc<str>` deserialization natively (but won't intern — each is independent)
3. Add `CloudTrailRecord::intern(&mut self, pool: &mut StringPool)` method
4. Call `intern()` in `store.rs` load_directory (lines 178–211) where we already intern index keys
5. Update Session to use `Arc<str>` for `identity_key`, `source_ip`, `unique_event_names`, `unique_regions`
6. Update test helpers to use `Arc::from("...")` instead of `"...".to_string()`

**Files:**
- `crates/core/src/model.rs` — Field type changes + `intern()` method
- `crates/core/src/store/store.rs` — Extend interning pass to record fields
- `crates/core/src/session.rs` — Arc<str> for Session fields + identity_key_for()
- `crates/core/src/detection/tests.rs` — Update test helpers
- `crates/core/src/stats.rs` — Minor deref changes
- `crates/app/src/commands/*.rs` — Arc<str> serializes as string (minimal changes)

---

### Phase F — Offload RawValue Blobs to Disk (~1.5–2 GB savings) [x]

**Most complex change but second-biggest win.** Move request_parameters, response_elements, additional_event_data from heap to a temporary file. Keep only `(offset, len)` in memory.

**New struct:**
```rust
// crates/core/src/store/blob_store.rs (new file)
pub struct BlobStore {
    file: std::fs::File,
    mmap: Option<memmap2::Mmap>,
    write_pos: u64,
}

#[derive(Clone, Copy)]
pub struct BlobRef {
    pub offset: u64,
    pub len: u32,
}
```

**In-memory cost per blob:** 12 bytes (BlobRef) vs ~200–800 bytes (Box<RawValue>)
**For 5M events × 3 blobs:** 180 MB (BlobRefs) vs ~2 GB (RawValues) = **~1.8 GB saved**

**Changes to CloudTrailRecord:**
```rust
// Before:
pub request_parameters: Option<Box<RawValue>>,
pub response_elements: Option<Box<RawValue>>,
pub additional_event_data: Option<Box<RawValue>>,
// After:
pub request_parameters: Option<BlobRef>,
pub response_elements: Option<BlobRef>,
pub additional_event_data: Option<BlobRef>,
```

**Detection rule impact:** ~35 call sites across 12 files use `parse_request_parameters()` etc. These will need a `&BlobStore` parameter to load the blob on demand. Detection rules already filter by index first, so only matched events need blob access.

**Files:**
- `crates/core/src/store/blob_store.rs` — New: BlobStore implementation
- `crates/core/src/store/mod.rs` — Export blob_store
- `crates/core/src/model.rs` — RawValue → BlobRef fields + updated parse helpers
- `crates/core/src/store/store.rs` — Add BlobStore to Store, write blobs during ingestion
- `crates/core/src/detection/rules/*.rs` — ~35 call sites: pass &BlobStore
- `crates/app/src/commands/query.rs` — Load blobs on demand for RecordDetail
- `crates/app/src/state.rs` — BlobStore in AppState

**New dependency:** `memmap2` (or plain `File::seek` + `read_exact` for Windows compatibility)

---

### Phase G — Minor Cleanups (~100–200 MB savings) [x]

1. **SessionIndex secondary indexes** — `by_identity` and `by_ip` duplicate String keys from Session. Use `Arc<str>` (free after Phase E).
2. **Detection rule index cloning** — Rules do `ids.clone()` on full Vec<u32>. Change to borrowed iteration.
3. **Session.unique_event_names/unique_regions** — Use `Arc<str>` (free after Phase E).
4. **identity_key_for()** — Returns cloned String. Return Arc<str> from pool instead.

---

## Implementation Order

1. **Phase D** (u32 IDs) — Simplest, safest, no new deps. Good warmup.
2. **Phase E** (String interning) — Biggest savings, moderate complexity.
3. **Phase G** (Minor cleanups) — Quick wins while in the area.
4. **Phase F** (Blob offload) — Most complex, new dependency. Can defer if D+E are sufficient.

## Verification

After each phase:
- `cargo test -p trail-inspector-core` — All 107+ tests must pass
- `cargo tauri build` — Must compile

After all phases:
- Load 1M → 3M → 5M event datasets, measure RSS via Task Manager
- Verify: event detail view shows request_parameters/response_elements correctly
- Verify: all 60+ detection rules still fire
- Verify: session grouping, query, filter, timeline, export, IP view functional
- Target: 5M events < 3 GB RSS
