# TrailInspector code review (2026-10-06, HEAD fa076dd)

Scope: whole repo. `cargo test -p trail-inspector-core` passes (161 tests). `tsc --noEmit` clean. `npm ci` fails on a Vite 8 / `@tailwindcss/vite` peer conflict (needs `--legacy-peer-deps`). ESLint reports 8 errors under the react-hooks v7 rules.

Every item below was verified against the source. Priority is my judgement of impact for an analyst using the tool on real investigations.

---

## A. Bugs — fix first (wrong results shown to the analyst)

| # | Where | Problem | Scenario |
|---|---|---|---|
| A1 | `crates/core/src/detection/mod.rs:701,716` + `crates/app/src/commands/detection.rs:37` | Alert IDs are truncated to 100 **before** `filter_alerts_by_time` runs, so the time filter sees a 100-record sample. | IA-03 has 5,000 root events; user narrows to a 1-hour window that holds 300 of them, none in the first 100 → alert vanishes, `matchingCount` wrong. Filter first, then cap. |
| A2 | `detection/rules/*` (all 68 rules) | **No rule checks `errorCode`** and **no rule checks `eventSource`.** | A denied `StopLogging` by a read-only auditor fires DE-01 Critical. `CreateUser` from `transfer.amazonaws.com` / `identitystore` fires PE-01. `DeleteGroup` on Resource Groups fires CR-01. Two bitmap ops per rule fix it: `&= idx_event_source[svc]`, `-= idx_error_code[*]`. |
| A3 | `detection/rules/resource_sharing.rs:101` (RS-03) | `contains("\"restore\"")` — `attributeName` is always `restore` for `ModifyDBSnapshotAttribute`. | Every call fires, including **removing** public access. ~100 % false positive. |
| A4 | `ebs.rs:43` (EBS-02), `resource_sharing.rs:17,59` (RS-01/02), `rds.rs:15` (RDS-01), `defense_evasion.rs:289` (DE-10), `exfiltration.rs:69` (EX-01), `persistence.rs:181` (PE-04) | Substring matching on raw `requestParameters` JSON. | EBS-02 fires when a snapshot is made *private* (`remove.items[{group:"all"}]`) and on descriptions containing "install". RDS-01 fires on `{"deletionProtection":true,"applyImmediately":false}`. DE-10 fires on every `UpdateDistribution` (`TrustedSigners.Enabled:false` is always present). EX-01 flags every `PutBucketPolicy`. PE-04 misses pretty-printed `"Effect": "Allow"` and flags `Resource:"*"` with a single `s3:GetObject`. Parse to `Value` and navigate the real paths. |
| A5 | `persistence.rs:48` (PE-02) | Caller derived from `user_identity.user_name`, which is `None` for `AssumedRole`/`Root`. | Attacker on an assumed role running `CreateAccessKey --user-name admin` is never flagged. Derive from ARN. |
| A6 | `initial_access.rs:25` (IA-01) | `MFAUsed` defaults to "No"; SSO / SAML console logins always carry `MFAUsed:"No"`. | Every Identity Center login is High "no MFA". Exempt `AssumedRole` identities / `SamlProviderArn`. |
| A7 | `impact.rs:118` (IM-02) | `Delete*` prefix over all event names, including S3 data events and ENI cleanup. | Lifecycle job deleting 11 objects in 5 min = Critical "ransomware". Allow-list management-plane names. |
| A8 | `geo_anomaly.rs:24,70` (GEO-01) | Identities with no ARN collapse into one `"unknown"` bucket. | Two distinct external accounts in two countries fire one "impossible travel" alert. |
| A9 | `crates/core/src/ingest/parser.rs:42` | Unparseable `eventTime` silently becomes epoch 0. | Emulator/CTF logs with `2024-01-15 10:00:00` land in 1970: timeline span becomes 54 years and real data collapses into the last bucket; a bogus 1970 session per identity. Emit an `IngestWarning` and skip or flag. |
| A10 | `crates/core/src/query/parser.rs:113,127` | Unknown/misspelled field → `Ok(None)` → **matches everything**. | `eventname=StopLogging` (lowercase n) returns the whole dataset with no error. Return `CoreError::Query("unknown field")`. |
| A11 | `ui/src/components/search/FilterPanel.tsx:40` vs `ui/src/App.tsx:146` | Active facet filters live in the search view (unmounted on tab switch) but the derived `filterFragment` lives in App. | Tick `errorCode=AccessDenied`, visit Stats, come back: nothing shows checked, "Clear" is hidden, results stay filtered. Exactly the CLAUDE.md learning. |
| A12 | `ui/src/App.tsx:286` | Initial load ignores the query/time range restored from localStorage. | Header chip and StatusBar say filtered, table/timeline show everything until Enter; export uses the filtered query so the file does not match the table. |
| A13 | `ui/src/components/search/QueryBar.tsx:5` + `App.tsx:245` | Every keystroke lifts the draft into `activeQuery` before submit. | Half-typed query + "Next page" fetches with the unsubmitted text; FilterPanel re-fetches 9 facets per keystroke; export uses draft text. Keep draft local, lift on submit. |
| A14 | UI timestamps | UTC in `EventTable`, `SessionView`, `AlertDetail`; local in `IdentityTimeline`, `TimelineChart`, `AwsFetchPanel`; `GlobalTimeBar` reads `datetime-local` as UTC, `AwsFetchPanel` as local. | Analyst in UTC+7 sees the same event as 14:00 and 07:00 in two panes. One `formatTs` helper + a UTC/local toggle. |

## B. Bugs — data loss / crash / security

| # | Where | Problem |
|---|---|---|
| B1 | `crates/core/src/fetch/bucket.rs:220`, `lookup.rs`, `crates/app/src/commands/fetch.rs:340` | One failed `GetObject` (e.g. SSE-KMS key the role can't use on object 4,000 of 5,000) aborts the fetch and `remove_dir_all` deletes everything downloaded. Skip-and-warn per object; keep partial staging. |
| B2 | `bucket.rs:64` | S3 client built in the *requested* region; a trail bucket homed elsewhere returns `PermanentRedirect` on every object. Use `HeadBucket` / `x-amz-bucket-region` and rebuild. |
| B3 | `bucket.rs:76` | `CloudTrail-Digest/` and `CloudTrail-Insight/` objects are downloaded, counted in the pre-pull summary, then each produces an ingest warning. Filter the key path. |
| B4 | `bucket.rs:239` | Path-escape filter splits on `/` only; on Windows a key segment `..\..\evil` or `C:evil` survives and `PathBuf::push` escapes `dest`. Reject `\` and `:` or keep only `Component::Normal`. |
| B5 | `crates/core/src/ingest/decompress.rs:46` | `read_zip_entries` inflates **every** entry into RAM before any is consumed, defeating the bounded channel in `store.rs`. A 1 GB zip of `.json.gz` → ~10 GB resident. Also no size cap on gzip/zip output (zip bomb → OOM). Stream per entry; `Read::take(limit)`. |
| B6 | `crates/core/src/store/store.rs:310` | `files_done` is incremented per channel message, but a ZIP sends one message per inner entry → progress exceeds 100 %. Count per `src_idx`. |
| B7 | `crates/core/src/detection/custom_rules.rs:247` | `window_minutes as i64 * 60_000` unchecked; a huge YAML value wraps negative → the sliding-window loop indexes out of bounds and panics. Validate in `load_custom_rules`. |
| B8 | `custom_rules.rs:327` | `run_custom_rules` never calls `cap_alert_ids` → a custom rule on `GetObject` ships every matching ID over IPC (violates the 500-record rule). |
| B9 | `crates/app/src/commands/session.rs:11`, `geoip.rs:170`, `s3.rs` summary, `detection.rs` | `page_size` not clamped in `list_sessions`, `get_session_detail`, `list_ips`; `run_detections` and `get_s3_summary` return unbounded vectors. Only `search` and `get_identity_summary` clamp to 500. |
| B10 | `crates/app/src/commands/geoip.rs:131` | Online geo lookup posts to plain `http://ip-api.com` (investigation IPs leave the machine in cleartext) and the first 429 discards all rows already resolved (free tier allows 15 batches/min; 2,000 IPs = 20 batches). Return partial results. |
| B11 | `crates/core/src/geoip.rs:218` | IPv6 private ranges (`fe80::/10`, `fc00::/7`, `::ffff:10.0.0.1`) are sent to the MMDB and come back as "public, unknown country" rows feeding GEO-01/02. |
| B12 | `crates/core/src/fetch/profiles.rs:424` | `[sso-session x]` and `[services x]` sections appear in the profile picker; choosing one fails at SDK load. |
| B13 | `crates/app/src/commands/fetch.rs:288` | Overlapping Checks leak the first staged directory; no cancellation token at all for a 90-day LookupEvents run. |
| B14 | `crates/app/src/commands/detection.rs:14`, `session.rs` | `run_all_rules` / `run_geo_rules` run inline in async commands (no `spawn_blocking`, unlike ingest/fetch) while holding the store read lock; a panic in any rule poisons the lock for the session. |
| B15 | `crates/core/src/model.rs:40` + `parser.rs:28` | One malformed record (missing `awsRegion`) fails the whole file. Deserialize to `Vec<Box<RawValue>>`, then per record, collecting warnings. |
| B16 | `crates/core/src/query/parser.rs:197` | `n * 7 * 86_400 * 1_000` on user input overflows (`earliest=-99999999999999w`). Use `checked_mul`. `!=` is checked before `=`, so `userAgent=*a!=b*` misparses. Patterns are Unicode-lowercased but matched ASCII-lowercased, so non-ASCII patterns never match. |
| B17 | `store.rs:329`, `engine.rs`, `stats.rs` | `sort_unstable_by_key(ts)` with 1-second CloudTrail resolution + nondeterministic rayon arrival order → event order within a second reshuffles between loads. Key on `(ts, id)`. |
| B18 | `crates/app/src/commands/export.rs` | `export_json` materialises every full record, pretty-prints the whole array in RAM, then **re-parses the entire output** just to count records. CSV row count is a newline count. Stream to the file; count as you go. |
| B19 | `decompress.rs:27,66` | `GzDecoder` reads only the first gzip member; `cat a.gz b.gz` is silently truncated. `MultiGzDecoder` is a drop-in. |
| B20 | `ui/src/components/results/EventDetail.tsx:184`, `FieldStats.tsx:181`, `AlertDetail.tsx`, `SessionDetail.tsx`, `IpView.tsx`, `IdentityTimeline.tsx` | No request-supersession guard outside `App.fetchPage`: click row A then B quickly → A's JSON under B's header. Same for facets, alerts, sessions, IPs. |
| B21 | `ui/src/App.tsx:310`, `FilterPanel.tsx:529` | `runQuery` / `onFilterChange` called inside `setState` updaters; StrictMode runs them twice. |
| B22 | `ui/src/types/cloudtrail.ts` | Rust `Option<T>` serialises as `null` but TS declares `field?: T`; `IngestProgress.Complete` wire key is `records_total` (enum `rename_all` does not rename struct-variant fields) while TS says `recordsTotal`. |
| B23 | `crates/app/capabilities/default.json:10`, `tauri.conf.json:20` | `fs:read-all` granted but `plugin-fs` is never imported from the UI; `csp: null` disables the CSP entirely. |
| B24 | `.github/workflows/ci.yml` | Only `cargo test -p trail-inspector-core` (default features) runs on PRs; the app crate and the `aws` feature are first compiled at tag time. `crates/app/Cargo.toml` declares `anyhow` but nothing uses it. |

## C. Optimization (ordered by expected payoff)

1. **Ingest consumer parses `requestParameters` to `serde_json::Value` for every record** (`store.rs:222`). The consumer is the single-threaded bottleneck of the whole pipeline. Gate on `eventSource == s3.amazonaws.com`, deserialize into a borrowed `struct { bucketName: Option<&str>, key: Option<&str> }`, or move extraction to the parallel producer side. Likely the largest ingest win available.
2. **Custom rules materialise entire posting lists into `HashSet<u32>` per condition** (`custom_rules.rs:213`). `identity_type=AssumedRole` on 10 M records = 9 M-entry set per condition per rule. Use `RoaringBitmap` `& | -` directly; `apply_filter` becomes allocation-free.
3. **Quadratic sliding windows**: `Vec::contains` inside window loops in IM-01 (`impact.rs:74`), IA-04, CA-02, DI-03, EX-03, IM-02. 10k `RunInstances` in 10 min ≈ 10⁸ comparisons. Also no `break`. The ignored bench never hits these paths; add a burst case.
4. **Rules run sequentially** (`mod.rs:696`). All take `&Store`; `par_iter().flat_map(...)` is a one-liner.
5. **Repeated blob I/O across rules**: RDS-01/RDS-03 both load `ModifyDBInstance`; DE-01/DE-07 both scan `UpdateTrail`; IA-01/IA-04/CA-05/GEO-02 each re-parse `ConsoleLogin`. A per-run `id → Value` cache, or ingestion-time indexes like `s3_event_index`.
6. **GeoIP**: two MMDB lookups per unique IP on every page/sort of the IP tab (`geoip.rs:169`); GEO-01/02 look up per *record*. Cache `IpAddr → Option<IpInfo>` once per dataset. MMDB is `Reader<Vec<u8>>`; `memmap2` is already a dependency.
7. **Detections re-run on every tab visit** (`DetectionView.tsx:64`) and `get_session_alerts` recomputes all rules per call. Cache alerts next to `session_index`, invalidate in `ingest_path_into_state`.
8. **Memory**: `event_time`, `error_message`, assumed-role ARNs are interned although near-unique (`model.rs:77`), bloating the pool instead of saving. `event_time` is redundant with `timestamp`. `sessionContext` (300–600 B on every AssumedRole event) is never drained to the BlobStore. Three `Option<BlobRef>` pad to 48 B; UUID fields are `Option<String>`. `source_file` is written but never read.
9. **S3 fetch is one object at a time** with sync `std::fs::write` on the runtime (`bucket.rs:220`). `buffer_unordered(16)` + `tokio::fs` ≈ 10×. Listing walks the whole bucket before date-filtering; build day prefixes instead.
10. **Query engine**: full match set recomputed and re-sorted for every page of the same query (`engine.rs`). Cache last `(query → Vec<u32>)` in `AppState`.
11. **`top_field_values`** (`stats.rs:117`) builds per-thread hash maps over all ids; for indexed fields `(posting & ids).len()` per key needs no per-record work and removes the `bucketName` blob-parse special case.
12. **UI**: FilterPanel (9) and FieldStats (11) call `get_top_fields` separately for overlapping fields; one batch command. `EventTable`, `FilterPanel`, `TimelineChart`, `GlobalTimeBar` are unmemoized with inline callbacks, so typing re-renders the table. `JSON.stringify(detail.raw)` on every render; `CustomTooltip` defined inside render. `IdentityTimeline` renders 500 unvirtualized rows. Unused deps: `lucide-react` (46 MB), `@tanstack/react-table`, `react-is`, `jimp`; dead `index.css`/`App.css`.

## D. Feature opportunities (cheap given the existing structure)

**Detection coverage gaps** (all fit the `idx_event_name` + params pattern):
- Bedrock / LLMjacking: `InvokeModel*` bursts, `PutFoundationModelEntitlement`, `PutUseCaseForModelAccess`.
- STS: `GetFederationToken`, role chaining (`AssumeRole` where caller type is `AssumedRole`), AssumeRole from non-allow-listed account.
- GuardDuty/SecurityHub/Macie tampering: `UpdateDetector enable:false`, `CreateIPSet`/`CreateThreatIntelSet`, `DisableSecurityHub`, `DisableMacie`, `DeleteAnalyzer`.
- CloudTrail: `PutEventSelectors` / `PutInsightSelectors` (the classic "exclude management events").
- Lambda: `UpdateFunctionCode*`, layer injection, `AddLayerVersionPermission principal:*`, `PutFunctionConcurrency 0`.
- S3 ransomware: `PutBucketLifecycle` short expiry, `PutBucketVersioning Suspended`, `PutBucketEncryption` with foreign KMS key, `DeletePublicAccessBlock`, `PutBucketReplication` external.
- IAM: `UpdateAssumeRolePolicy` to external/`*`, `UpdateLoginProfile` on another user, `Create/UpdateSAMLProvider`, `CreateOpenIDConnectProvider`, `DeleteAccountPasswordPolicy`, permissions-boundary removal.
- Organizations: `LeaveOrganization`, `RemoveAccountFromOrganization`, SCP `DetachPolicy`/`DisablePolicyType`.
- Snapshot exfil to a *specific* foreign account (today only `all`), `CopySnapshot`/`CopyImage` cross-region.
- EC2: `GetConsoleScreenshot`, `ImportKeyPair`, IAM instance-profile swap, `RunInstances` with userData + public IP.
- Identity-aware: first-seen access key/ARN, user-agent anomaly (pacu, Kali boto strings), `sessionCredentialFromConsole`.
- Sequences: CreateUser → CreateAccessKey → AttachUserPolicy within 10 min; StopLogging → destructive actions.

**Custom-rule DSL**: `event_source` match key; `error_code: none` / `success_only`; `group_by: identity|source_ip` for thresholds (today the window is global, so 5 SG changes by 5 admins fires CR-05); `Delete*` glob on `event_name`; `request_params.<json-pointer> == value`; `read_only: false`; validate `mitre_technique` and `window_minutes` on load.

**Query / indexing**: index `principalId`, `accessKeyId`, `eventType`, `readOnly`, `recipientAccountId`, `resources[].ARN` (already interned `Arc<str>` on the record; one `HashMap` + one match arm each). `field IN (a,b,c)` (union already exists in `union_keys`). Parenthesised `NOT (...)`. Exact match is case-sensitive while wildcards are case-insensitive; document or unify.

**Fetch**: resumable/incremental pull (skip keys whose local file matches `ContentLength`), listing-only dry run with object count/bytes, assume-role (`role_arn`/`external_id`) for the audit-account case, multi-region LookupEvents, CloudTrail Lake / Athena as a `FetchSource`, non-secret saved presets beside `rules.yaml`, byte-level progress, cancel button.

**Export / UI**: export alerts (with MITRE columns), sessions and IP tables, not just records; CSV with `requestParameters` and `eventID`; streaming JSONL. Saved/named queries (one is already persisted). Click-to-pivot from EventDetail fields to filter/Identity/IP tabs (`handleFilterSelect` exists). Timeline brush-to-range. Light theme (palette is already CSS variables). UTC/local toggle. Multi-select + local tags as a facet. Expose `source_file` in the detail pane. Session gap as a parameter instead of `GAP_MS` const. Keyboard row navigation.

---

## Suggested order of work

1. A1, A2, B8, B9 — engine ordering, error/source gating, IPC caps. Small, high impact.
2. A3–A8 — rewrite the substring rules against parsed JSON; fix PE-02 caller and IA-01 SSO.
3. A9, A10, B7, B16 — input validation that currently produces silent wrong results or panics.
4. A11–A14, B20, B21 — UI state ownership, request guards, one timestamp formatter.
5. B1–B6 — fetch robustness and ZIP memory.
6. C1–C4 — ingest consumer parse, bitmap custom rules, window loops, parallel rules (bench before/after with `bench_detection_100k_records` plus a burst case).
