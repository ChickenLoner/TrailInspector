# Changelog

All notable changes to TrailInspector are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

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
