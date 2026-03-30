# TrailInspector v0.2.0 — Implementation Plan

> **EG-CERT Recommendations: Detection Expansion, Session Grouping, IP Enrichment**
> Evolving TrailInspector from a log viewer into a full investigation tool.

---

## Dependency Graph

```
Phase 1 (restructure detection module)
  ├──> Phase 2 (20 new rules: VPC, RDS, IAM, Defense Evasion)
  │     └──> Phase 3 (20 more rules: EBS, Lambda, S3, encryption)
  │           └──> Phase 4 (detections UI: service grouping + filtering)
  ├──> Phase 5 (session engine in core)
  │     └──> Phase 6 (sessions UI tab)
  ├──> Phase 7 (GeoIP engine in core)
  │     └──> Phase 8 (IP enrichment UI + geo anomaly rules)
  └──> Phase 9 (session-alert correlation + AssumeRole chain linking)

Phase 10 (polish + tests + docs) — after all above
```

---

## Phase 1: Detection Module Restructuring ✅

Break monolithic `detection/mod.rs` (~1100 lines) into per-tactic files.

- `crates/core/src/detection/rules/` directory with one file per tactic
- Add `service: &'static str` to `DetectionRule`, `service: String` to `Alert`
- `all_rules()` registry stays in `detection/mod.rs`, importing from submodules

---

## Phase 2: Detection Rules Batch 1 — Network/VPC + Defense Evasion + RDS + IAM (20 rules) ✅

| ID | Rule | Severity | Service |
|----|------|----------|---------|
| DE-05 | VPC Flow Log Deletion | Critical | VPC |
| DE-06 | CloudWatch Log Group Deletion | High | CloudWatch |
| DE-07 | CloudTrail S3 Bucket Changed | High | CloudTrail |
| DE-08 | EventBridge Rule Disabled | Medium | EventBridge |
| DE-09 | WAF Web ACL Deletion | High | WAF |
| NW-01 | Security Group Ingress 0.0.0.0/0 | High | VPC |
| NW-02 | Network ACL Allows All Traffic | Medium | VPC |
| NW-03 | Internet Gateway Created | Info | VPC |
| NW-04 | Route to 0.0.0.0/0 Modified | Medium | VPC |
| NW-05 | VPC Peering Created | Info | VPC |
| NW-06 | Security Group Deleted | Low | VPC |
| NW-07 | Subnet Made Public | Medium | VPC |
| NW-08 | NAT Gateway Deleted | Low | VPC |
| PE-05 | MFA Device Deactivated | High | IAM |
| PE-06 | IAM Policy Version Created (SetAsDefault) | Medium | IAM |
| PE-07 | Cross-Account AssumeRole | Medium | STS |
| CA-05 | Root Console Login | Critical | IAM |
| RDS-01 | RDS Deletion Protection Disabled | High | RDS |
| RDS-02 | RDS Public Snapshot Restore | High | RDS |
| RDS-03 | RDS Master Password Changed | Medium | RDS |

---

## Phase 3: Detection Rules Batch 2 — EBS, Lambda, S3, Encryption, Resource Sharing (20 rules) ✅

| ID | Rule | Severity | Service |
|----|------|----------|---------|
| EBS-01 | EBS Default Encryption Disabled | High | EBS |
| EBS-02 | EBS Snapshot Made Public | Critical | EBS |
| EBS-03 | EBS Volume Detached | Low | EBS |
| EBS-04 | EBS Snapshot Deleted | Medium | EBS |
| EBS-05 | EBS Default KMS Key Changed | Medium | EBS |
| LM-01 | Lambda Public Access via Resource Policy | High | Lambda |
| LM-02 | Lambda Env Variables Updated | Low | Lambda |
| EX-02 | S3 Bucket Deleted | Medium | S3 |
| EX-03 | S3 Bulk Download (50+ GetObject in 5min) | Medium | S3 |
| EX-04 | S3 Bucket Logging Disabled | Medium | S3 |
| EX-05 | S3 Bucket Encryption Removed | High | S3 |
| RS-01 | EC2 AMI Made Public | High | EC2 |
| RS-02 | SSM Document Made Public | High | SSM |
| RS-03 | RDS Snapshot Made Public | High | RDS |
| DE-10 | CloudFront Logging Disabled | Medium | CloudFront |
| DE-11 | SQS Queue Encryption Removed | Medium | SQS |
| DE-12 | SNS Topic Encryption Removed | Medium | SNS |
| CA-06 | KMS Key Scheduled for Deletion | High | KMS |
| DE-13 | Route53 Hosted Zone Deleted | Medium | Route53 |
| IM-03 | SES Email Identity Verification | Low | SES |

---

## Phase 4: Enhanced Detections UI — Service Grouping + Filtering ✅

- Group-by toggle: Severity | Service | MITRE Tactic with collapsible sections
- Severity filter chips (Critical/High/Medium/Low/Info toggle)
- Search box to filter by title or rule ID
- Summary counts, MITRE ATT&CK external links

---

## Phase 5: Session Grouping Engine (Core) ✅

Compute sessions from `(identity, source_ip, time_gap)` — O(n) over time-sorted records.

```rust
pub struct Session {
    pub id: u32,
    pub identity_key: String,
    pub source_ip: String,
    pub first_event_ms: i64,
    pub last_event_ms: i64,
    pub event_count: usize,
    pub event_ids: Vec<u64>,
    pub error_count: usize,
    pub unique_event_names: Vec<String>,
    pub unique_regions: Vec<String>,
    pub alert_count: usize,
}
```

New IPC commands: `list_sessions`, `get_session_detail`.

---

## Phase 6: Sessions UI Tab ✅

New "Sessions" tab between Identity and Detections:
- `SessionView.tsx` — session card list (identity, IP, duration, event/error/alert counts, top events)
- `SessionDetail.tsx` — paginated event timeline, reuses IdentityTimeline patterns

---

## Phase 7: IP Enrichment Engine (Offline GeoIP)

`maxminddb` crate for offline MMDB lookup. User provides GeoLite2 files or bundled ip2location-lite CSV.

```rust
pub struct IpInfo {
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub city: Option<String>,
    pub asn: Option<u32>,
    pub asn_org: Option<String>,
}
```

New IPC commands: `get_ip_info`, `list_ips`.

---

## Phase 8: IP Enrichment UI + Geo Anomaly Rules

- Country column in EventTable, geo panel in EventDetail/SessionDetail
- IdentityTimeline highlights multi-country activity
- New `IpView.tsx` — all IPs with geo info and click-to-investigate
- GEO-01: Same identity from multiple countries (Medium)
- GEO-02: Console login from new country (High)

---

## Phase 9: Session-Alert Correlation + Cross-Session Linking

- Annotate sessions with `alert_ids` by intersecting event IDs
- AssumeRole chain detection → `session_links` between parent/child sessions
- AlertDetail shows owning sessions; SessionDetail shows related alerts

---

## Phase 10: Polish, Tests, Documentation

- Unit tests for all 40+ new detection rules
- Session engine and GeoIP tests
- Performance benchmark: 58+ rules on 500K records < 2s
- Update CLAUDE.md, README.md; create RULES.md, CHANGELOG.md
