# Changelog

All notable changes to TrailInspector are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.6.0] — 2026-07-27

### Fixed

- **Filters survived tab switches invisibly** — excluding a value then leaving the Search tab left the filter applied but unreachable: the value vanished from the sidebar, and the Clear button hid itself. `FilterPanel` held its active filters in local state while `App` held the fragment derived from them, and switching tabs unmounts the search view, destroying the child's copy. Filters now live in `App`
- **Filtering a value emptied its own section** — including a value scoped that field's own counts to itself, so every other value dropped to zero and disappeared. Each field is now counted with its own clause removed, the standard faceted-search scoping, so an excluded value keeps a true count and you can switch between values without clearing first
- **Alerts silently lost their evidence when time-filtered** — the 100-id transport cap was applied before time filtering, so an alert whose first 100 ids fell outside the selected window vanished entirely. Capping now happens last, at the IPC boundary
- **Custom-rule alerts shipped unbounded id lists over IPC** — only built-in rules were capped
- **Session correlation matched against a truncated sample** — `get_session_alerts` and `get_alert_sessions` saw only each alert's first 100 records
- **"View evidence" showed fewer events than the alert counted** — DI-02 matched 7 event names and advertised 5; PE-04 matched 6 and advertised 4; LM-02 matched 2 and advertised 1; RDS-02 matched 3 and advertised 2. Queries are now derived from the names the rule matches on
- **Severity colours disagreed between panels** — the same Critical alert rendered `#d41f1f` in the alert list and `#f85149` in the detail panel. Both now read the `--sev-*` design tokens

### Changed

- **Alert record ids are deterministic** — burst rules collected ids in `HashMap` iteration order, so the capped 100-id preview varied between runs on identical data. Ids now come out ascending
- **AlertDetail severity colours** now match the rest of the app (see above)
- **Redundant `count` metadata removed** from DE-01, DI-02, IA-03 and PE-01 — it duplicated `matchingCount`, which the UI already displays

### Performance

- **Detection is ~8× faster** — 1.42s → 176ms on 100,000 records. IM-01 accounted for 91% of the time: it is the only rule that collects every qualifying window rather than stopping at the first, and it re-inserted the whole window on each step (~3M redundant inserts for ~7k events)
- **Detection rules run in parallel** — worth ~13% while IM-01 dominated, 2.4× once it no longer did
- **Filter sidebar counts use bitmap intersections** — each of the nine per-click queries previously executed the query, materialised every matching id, sorted it by timestamp, then walked every record. Cost now scales with distinct values in the field rather than matching records. `bucketName` stops parsing a blob per record and uses its index
- **Quadratic dedup removed from seven burst rules** — `Vec::contains` inside the sliding window became `RoaringBitmap`
- **Release profile** — fat LTO, one codegen unit, stripped
- **Dependencies optimised in dev builds** — the core test suite went from 5.66s to 0.43s

### Internal

- Rule identity (id, title, severity, MITRE, service) lives only in the registry; rules return a `Finding` and the registry stamps the rest. Previously both declared it and nothing checked they agreed
- 31 rules that were pure index lookups are now declarative `Eval::Match` specs rather than hand-written functions
- Shared `window_burst` replaces seven copies of the sliding-window loop; `UserIdentity::identity_key` replaces eight copies of the arn→userName fallback
- `crates/app` no longer reimplements query logic — field counting moved to core
- Tests: 176, up from 161

**Breaking (library):** `crates/core`'s `DetectionRule.name` is now `title`, `evaluate` is an `Eval` enum, rule functions return `Option<Finding>`, and 31 rule functions were removed. The desktop app is unaffected.

---

## [1.5.0] — 2026-07-26

### Added

- **Import from Live AWS** — pull CloudTrail logs directly from an AWS account, no AWS CLI required. Credentials entered in-app (access key / secret / session token) or picked from a named `~/.aws` profile
- **Two live sources** — `cloudtrail:LookupEvents` (last 90 days, no S3 access needed) or the trail's S3 bucket (full history, full fidelity)
- **Check before pull** — Check downloads and counts everything, reporting exact event count, time range, trails, and bucket before anything replaces the loaded dataset. Pull reuses the staged download, so the transfer is never paid for twice
- **Explicit bucket override** — name the bucket to skip `DescribeTrails`, for roles that can read a bucket but not enumerate trails
- **Endpoint URL override** — the `aws --endpoint-url` equivalent, for LocalStack, moto, and emulated AWS. S3 switches to path-style addressing automatically
- **`aws cloudtrail lookup-events` exports** — the `{"Events":[{"CloudTrailEvent":"…"}]}` shape now loads natively, no manual conversion
- **Single-file import** — "Open Single File" alongside the existing folder picker; an explicitly chosen file bypasses the extension filter
- **`aws` cargo feature** — the AWS SDK is gated so `cargo test -p trail-inspector-core` stays offline and SDK-free

### Fixed

- **Gzip detected by magic bytes, not filename** — files such as `audit.log.gz` were previously invisible to the directory walker and, if reached, returned raw compressed bytes to the parser. Affected the existing file-import path, not just live import
- **Fully-qualified `X-Amz-Target`** — the CloudTrail target header is now sent in the `com.amazonaws.cloudtrail.v20131101.…` form the AWS CLI uses. Some emulators only register that form and answer the short form with `UnknownOperationException`

### Security

- Typed AWS credentials are held in backend memory for the session only — never written to disk, browser storage, or `~/.aws`. "Clear cache" wipes them and any staged download
- `AwsCredentials` has a hand-written `Debug` that redacts secret and session token; `FetchRequest` deliberately omits `Serialize` so secrets cannot round-trip to the frontend
- Profile discovery reads INI section headers and the `region` key only — it never parses credential keys

---

## [1.3.0] — 2026-04-24

### Added

- **Custom detection rules (YAML)** — write rules in `~/.config/trail-inspector/rules.yaml` (or platform equivalent); fires alongside all 60 built-in rules
- **Recursive filter tree** — `and`, `or`, `not` operators compose arbitrarily; leaf conditions match fields: `identity_type`, `user_name`, `user_arn`, `source_ip`, `event_source`, `region`, `account_id`, `user_agent`, `bucket_name`, `error_code`
- **Multi-event matching** — `event_name` accepts a string or list of strings
- **Threshold detection** — `threshold.count` + `threshold.window_secs` sliding-window rate detector built into every rule
- **MITRE ATT&CK fields** — `tactic`, `technique`, `technique_id`, `mitre_url` per rule; surfaces in AlertDetail
- **Hot-reload** — "Reload Rules" button re-parses `rules.yaml` and re-runs detections without app restart
- **Open in editor** — "Open Rules File" button opens `rules.yaml` in the OS default text editor
- **Non-blocking error model** — parse errors show amber banner listing each bad rule; built-ins continue running
- **Duplicate ID rejection** — rules with a duplicate `id` are both rejected and individually reported
- **5 shipped example rules** — `rules.yaml` is written on first launch with CR-01 through CR-05
- **30 new unit tests** — cover filter evaluation, threshold logic, YAML parsing, and error reporting

---

## [1.2.0] — 2026-04-20

### Added

- **S3 Activity tab** — dedicated investigation surface for S3 GetObject events: total bytes out, objects accessed, unique buckets, unique identities stat cards; per-bucket table, per-identity table, top-100 objects by bytes (with total count when truncated)
- **S3 filters** — bucket, source IP, and identity filter dropdowns populated from ingested events; all filters combine with the global time bar
- **Byte unit toggle** — auto / B / KB / MB / GB selector applies to all byte values in the S3 tab
- **EX-03 enrichment** — S3 Bulk Download alert description now includes total bytes transferred; `total_bytes_out` added to alert metadata

### Fixed

- Export (CSV/JSON) on Windows — `dialog:allow-save` was missing from Tauri capability manifest; save dialog now opens correctly on Windows 10 and Windows 11

### Performance

- S3 object key and `bytesTransferredOut` extracted at ingestion time before blob drain; zero blob reads at query time for the S3 tab

---

## [1.0.0] — 2026-03-31

### Highlights

TrailInspector v1.0.0 marks the evolution from a log viewer into a full cloud investigation platform, delivering EG-CERT's recommended detection expansion, session activity grouping, and offline IP enrichment.

### Added

#### Detection Rules (+42 new rules, 60 total)

**Network / VPC (8 rules)**
- NW-01: Security Group Ingress Open to 0.0.0.0/0 or ::/0 — High
- NW-02: Network ACL Allows All Traffic — Medium
- NW-03: Internet Gateway Created or Attached — Info
- NW-04: Default Route Added to Route Table — Medium
- NW-05: VPC Peering Connection Created — Info
- NW-06: Security Group Deleted — Low
- NW-07: Subnet Auto-Assign Public IP Enabled — Medium
- NW-08: NAT Gateway Deleted — Low

**Defense Evasion — new (9 rules)**
- DE-05: VPC Flow Log Deletion — Critical
- DE-06: CloudWatch Log Group Deleted — High
- DE-07: CloudTrail S3 Logging Bucket Changed — High
- DE-08: EventBridge Rule Disabled — Medium
- DE-09: WAF Web ACL Deleted — High
- DE-10: CloudFront Distribution Logging Disabled — Medium
- DE-11: SQS Queue Encryption Removed — Medium
- DE-12: SNS Topic Encryption Removed — Medium
- DE-13: Route53 Hosted Zone Deleted — Medium

**Persistence extensions (3 rules)**
- PE-05: MFA Device Deactivated — High
- PE-06: IAM Policy Version Created and Set as Default — Medium
- PE-07: Cross-Account AssumeRole — Medium

**Credential Access (2 new rules)**
- CA-05: Root Account Console Login — Critical
- CA-06: KMS Key Scheduled for Deletion — High

**RDS (3 rules)**
- RDS-01: RDS Deletion Protection Disabled — High
- RDS-02: RDS Instance Restored with Public Access — High
- RDS-03: RDS Master Password Changed — Medium

**EBS (5 rules)**
- EBS-01: EBS Default Encryption Disabled — High
- EBS-02: EBS Snapshot Made Public — Critical
- EBS-03: EBS Volume Detached — Low
- EBS-04: EBS Snapshot Deleted — Medium
- EBS-05: EBS Default KMS Key Changed — Medium

**Lambda (2 rules)**
- LM-01: Lambda Function Granted Public Access — High
- LM-02: Lambda Environment Variables Updated — Low

**Exfiltration extensions (4 rules)**
- EX-02: S3 Bucket Deleted — Medium
- EX-03: S3 Bulk Object Download (≥50 GetObject in 5 min) — Medium
- EX-04: S3 Bucket Access Logging Disabled — Medium
- EX-05: S3 Bucket Encryption Removed — High

**Resource Sharing (3 rules)**
- RS-01: EC2 AMI Made Public — High
- RS-02: SSM Document Made Public — High
- RS-03: RDS Snapshot Made Public — High

**Geo Anomaly (2 rules — requires GeoLite2 MMDB)**
- GEO-01: Multi-Country Access by Same Identity — Medium
- GEO-02: Console Login from Unusual Country — High

**Impact (1 new rule)**
- IM-03: SES Email Identity Verified — Low

#### Detection UI

- Severity filter chips — toggle Critical / High / Medium / Low / Info independently
- Group-by toggle — organise alerts by Severity, AWS Service, or MITRE Tactic
- Collapsible group sections with per-group alert count
- Search box — filter alerts by rule title or ID in real-time
- Alert count summary badge per group
- MITRE ATT&CK external links on each alert

#### Session Grouping

- Automatic session clustering: events are grouped by `(identity, source_ip)` with a 30-minute inactivity gap
- Session card list showing identity, IP, duration, event count, error count, unique event names, and regions
- Session detail view with paginated event timeline
- New "Sessions" tab between Identity and Detections
- `list_sessions` IPC command with sort (first/duration/events/errors) and filter (identity, IP) support
- `get_session_detail` IPC command with paginated events

#### IP Enrichment (Offline GeoIP)

- MaxMind GeoLite2 integration via `maxminddb` crate — fully offline
- Lookup country, city, latitude/longitude, ASN, and ASN organisation per source IP
- New "IPs" tab listing all observed source IPs with geo detail panel
- Country and ASN columns in IP table; click-to-investigate from IP to filtered event table
- `get_ip_info` and `list_ips` IPC commands

#### Session-Alert Correlation

- SessionDetail surfaces all alerts whose matching events overlap the session
- AlertDetail surfaces all sessions that contain at least one matching event
- AssumeRole chain detection links parent and child sessions across account boundaries

#### Tests

- 107 automated tests covering all 40+ new detection rules, session engine, and GeoIP engine
- 63 new detection rule tests with both positive (fires) and negative (does not fire) cases
- 30 session engine tests covering gap logic, pagination, filtering, and alert correlation
- 10 GeoIP tests covering error handling and data structures

### Changed

- Detection module restructured from a single 1100-line file into per-tactic modules under `detection/rules/`
- `Alert` struct gains `service: String` field (AWS service category, e.g. "IAM", "S3", "VPC")
- `DetectionRule` struct gains `service: &'static str` field

### Fixed

- `run_all_rules` now returns alerts sorted by severity descending (Critical first)

---

## [0.1.0] — 2025-01-01 *(initial release — log viewer)*

### Added

- Ingest `.json.gz` files from standard AWS CloudTrail directory structures
- Drop a ZIP archive to ingest all logs in one step
- Parallel decompression via Rayon
- SPL-like query syntax: `AND`, `OR`, `NOT`, wildcards, field-level filtering
- Timeline histogram of event volume with time-range scoping
- Field statistics breakdown for pivot analysis
- Identity Timeline — per-identity activity view
- 18 MITRE ATT&CK-mapped detection rules (PE, DE, EX, DI series)
- "View Evidence" link — click an alert to auto-filter the event table to matching events
- Export filtered results as CSV or JSON
- Session persistence — query state and active tab survive app restarts
- Keyboard shortcuts: `/` focuses query bar, `Escape` clears it, `Ctrl+E` exports
- Dark theme
- GitHub Actions CI pipeline
- Fully offline — no AWS credentials or cloud dependency required
