# TrailInspector — Technical Implementation Plan

> **CloudTrail Log Analyzer Desktop Application**
> A cross-platform (Windows/Linux/macOS) standalone tool for analyzing AWS CloudTrail JSON exports with built-in detection rules, modeled after Splunk's investigation workflow.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Project Structure](#2-project-structure)
3. [Rust Backend Design](#3-rust-backend-design)
4. [React Frontend Design](#4-react-frontend-design)
5. [Data Flow & IPC](#5-data-flow--ipc)
6. [Built-in Detection Rules](#6-built-in-detection-rules)
7. [Phased Build Order](#7-phased-build-order)
8. [Known Technical Risks](#8-known-technical-risks)

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                   Tauri v2 Shell                     │
│  ┌───────────────────────┐  ┌─────────────────────┐ │
│  │    React Frontend      │  │    Rust Backend      │ │
│  │    (Webview)           │◄─┤    (Core Library)    │ │
│  │                        │  │                      │ │
│  │  - Query Bar           │  │  - File Discovery    │ │
│  │  - Filter Panel        │  │  - GZip Decompress   │ │
│  │  - Timeline Histogram  │  │  - JSON Parsing      │ │
│  │  - Event Table         │  │  - In-Memory Index   │ │
│  │  - Detection Alerts    │  │  - Query Engine      │ │
│  │  - Field Statistics    │  │  - Detection Engine   │ │
│  │  - Identity Timeline   │  │  - Export Engine     │ │
│  └───────────┬───────────┘  └──────────┬──────────┘ │
│              │      Tauri IPC           │            │
│              └──────────────────────────┘            │
└─────────────────────────────────────────────────────┘
```

**Key Decisions:**
- **Tauri v2** — Rust-native desktop framework, single binary output, ~5-10MB bundle
- **Cargo workspace** — Core parsing/query logic lives in a standalone `core` crate (testable without Tauri), Tauri app crate wraps it
- **In-memory indexed store** — Records loaded into memory with HashMap indexes on hot fields (eventName, sourceIPAddress, userIdentity, awsRegion, eventTime). For 1GB+ datasets, records stored in a `Vec<Record>` with indexes pointing to indices
- **Streaming ingestion** — Files processed in parallel via rayon, progress streamed to frontend via Tauri v2 Channels (`tauri::ipc::Channel<T>`) for ordered, high-throughput progress updates
- **Query engine** — Supports both structured filters AND a mini query language (`eventName=CreateUser AND sourceIPAddress!=10.*`)

---

## 2. Project Structure

```
TrailInspector/
├── Cargo.toml                    # Workspace root
├── PLAN.md
├── README.md
├── LICENSE
├── .gitignore
│
├── crates/
│   ├── core/                     # Pure Rust library — no Tauri dependency
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── model.rs          # CloudTrail record structs
│   │       ├── ingest/
│   │       │   ├── mod.rs
│   │       │   ├── discovery.rs  # Recursive file finder (.json, .json.gz, .zip)
│   │       │   ├── decompress.rs # GZip + ZIP handling
│   │       │   └── parser.rs     # JSON → Record parsing
│   │       ├── store/
│   │       │   ├── mod.rs
│   │       │   ├── index.rs      # In-memory field indexes
│   │       │   └── store.rs      # Record store (Vec<Record> + indexes)
│   │       ├── query/
│   │       │   ├── mod.rs
│   │       │   ├── filter.rs     # Structured filter logic
│   │       │   ├── parser.rs     # Query language parser
│   │       │   └── engine.rs     # Query execution against store
│   │       ├── detection/
│   │       │   ├── mod.rs
│   │       │   ├── engine.rs     # Rule evaluation engine
│   │       │   └── rules/        # Individual rule definitions
│   │       │       ├── mod.rs
│   │       │       ├── initial_access.rs
│   │       │       ├── persistence.rs
│   │       │       ├── privilege_escalation.rs
│   │       │       ├── defense_evasion.rs
│   │       │       ├── credential_access.rs
│   │       │       ├── discovery.rs
│   │       │       ├── exfiltration.rs
│   │       │       └── impact.rs
│   │       ├── stats.rs          # Field statistics / aggregations
│   │       └── export.rs         # CSV/JSON export
│   │
│   └── app/                      # Tauri application crate
│       ├── Cargo.toml
│       ├── tauri.conf.json
│       ├── build.rs
│       ├── icons/
│       ├── capabilities/         # Tauri v2 permission capabilities
│       └── src/
│           ├── main.rs           # Tauri entry point
│           ├── commands/         # Tauri IPC command handlers
│           │   ├── mod.rs
│           │   ├── ingest.rs     # load_directory, load_zip, get_progress
│           │   ├── query.rs      # search, filter, get_field_values
│           │   ├── stats.rs      # get_timeline, get_top_fields, get_identity_summary
│           │   ├── detection.rs  # run_detections, get_alerts
│           │   └── export.rs     # export_csv, export_json
│           └── state.rs          # Tauri managed state (RwLock<Store> for concurrent reads)
│
├── ui/                           # React frontend (Vite + TypeScript)
│   ├── package.json
│   ├── vite.config.ts
│   ├── tsconfig.json
│   ├── index.html
│   └── src/
│       ├── main.tsx
│       ├── App.tsx
│       ├── types/
│       │   └── cloudtrail.ts     # TypeScript types mirroring Rust model
│       ├── hooks/
│       │   ├── useIngest.ts      # File loading + progress
│       │   ├── useQuery.ts       # Search/filter state
│       │   ├── useDetections.ts  # Detection results
│       │   └── useStats.ts       # Statistics/aggregations
│       ├── components/
│       │   ├── layout/
│       │   │   ├── AppShell.tsx       # Main layout with sidebar + content
│       │   │   ├── Sidebar.tsx        # Navigation + loaded dataset info
│       │   │   └── StatusBar.tsx      # Record count, load time, memory usage
│       │   ├── ingest/
│       │   │   ├── DropZone.tsx       # Drag-and-drop folder/zip loader
│       │   │   └── ProgressBar.tsx    # Ingestion progress
│       │   ├── search/
│       │   │   ├── QueryBar.tsx       # Free-text query input (SPL-like)
│       │   │   ├── FilterPanel.tsx    # Structured dropdown filters
│       │   │   └── TimeRangePicker.tsx # Time window selection
│       │   ├── results/
│       │   │   ├── EventTable.tsx     # Virtualized event list
│       │   │   ├── EventDetail.tsx    # Expandable raw JSON view
│       │   │   └── Pagination.tsx     # Cursor-based pagination
│       │   ├── viz/
│       │   │   ├── TimelineChart.tsx  # Events-over-time histogram
│       │   │   ├── FieldStats.tsx     # Top-N field value bar charts
│       │   │   └── IdentityTimeline.tsx # Per-principal activity timeline
│       │   └── detection/
│       │       ├── AlertPanel.tsx     # Detection results with severity
│       │       └── AlertDetail.tsx    # Alert explanation + matching events
│       ├── lib/
│       │   ├── tauri.ts          # Typed wrappers around invoke/listen
│       │   └── queryLanguage.ts  # Client-side query syntax highlighting
│       └── styles/
│           └── globals.css       # Dark theme (Splunk-inspired)
│
└── samples/                      # Test data (gitignored)
```

---

## 3. Rust Backend Design

### 3.1 Data Model (`crates/core/src/model.rs`)

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

/// Top-level CloudTrail file wrapper
#[derive(Debug, Deserialize)]
pub struct CloudTrailFile {
    #[serde(rename = "Records")]
    pub records: Vec<CloudTrailRecord>,
}

/// Raw CloudTrail record — deserialize all known fields, capture extras
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudTrailRecord {
    pub event_version: Option<String>,
    pub event_time: String,                   // ISO 8601, indexed
    pub event_source: String,                 // e.g., "iam.amazonaws.com", indexed
    pub event_name: String,                   // e.g., "CreateUser", indexed
    pub aws_region: String,                   // indexed
    pub source_ip_address: Option<String>,    // indexed
    pub user_agent: Option<String>,
    pub user_identity: UserIdentity,
    pub request_parameters: Option<serde_json::Value>,  // keep as raw JSON
    pub response_elements: Option<serde_json::Value>,   // keep as raw JSON
    pub additional_event_data: Option<serde_json::Value>, // contains MFAUsed, etc.
    pub error_code: Option<String>,           // indexed
    pub error_message: Option<String>,
    pub request_id: Option<String>,
    #[serde(rename = "eventID")]
    pub event_id: Option<String>,
    pub event_type: Option<String>,
    pub read_only: Option<bool>,
    pub management_event: Option<bool>,
    pub recipient_account_id: Option<String>, // indexed
    pub event_category: Option<String>,
    pub shared_event_id: Option<String>,
    pub session_credential_from_console: Option<String>,
    #[serde(default)]
    pub resources: Vec<Resource>,             // present in data events

    // Capture any fields not explicitly modeled
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserIdentity {
    #[serde(rename = "type")]
    pub identity_type: Option<String>,        // indexed
    pub principal_id: Option<String>,
    pub arn: Option<String>,                  // indexed
    pub account_id: Option<String>,           // indexed
    pub access_key_id: Option<String>,        // indexed
    pub user_name: Option<String>,            // indexed
    pub session_context: Option<serde_json::Value>,
    pub invoked_by: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resource {
    pub account_id: Option<String>,
    #[serde(rename = "type")]
    pub resource_type: Option<String>,
    #[serde(rename = "ARN")]
    pub arn: Option<String>,
}

/// Internal record with parsed timestamp and assigned ID
pub struct IndexedRecord {
    pub id: u64,
    pub timestamp: i64,          // epoch millis, for fast range queries
    pub source_file: u32,        // index into file path table (saves memory)
    pub record: CloudTrailRecord,
}
```

### 3.2 Ingestion Pipeline (`crates/core/src/ingest/`)

```
Directory/ZIP path
    │
    ▼
┌─────────────┐    Parallel (rayon)    ┌──────────────┐
│  discovery   │ ──────────────────►   │  per-file     │
│  .json.gz    │                       │  decompress   │
│  .json       │                       │  + parse      │
│  .zip        │                       │  Records[]    │
└─────────────┘                        └──────┬───────┘
                                              │
                                              ▼
                                       ┌──────────────┐
                                       │  Store.ingest │
                                       │  index fields │
                                       │  emit progress│
                                       └──────────────┘
```

**Crate dependencies for ingestion:**
| Crate | Purpose |
|-------|---------|
| `serde` + `serde_json` | JSON deserialization |
| `flate2` (with `zlib-ng` backend) | GZip decompression (~30-60% faster than default pure-Rust backend) |
| `zip` | ZIP archive extraction |
| `rayon` | Parallel file processing |
| `walkdir` | Recursive directory traversal |
| `chrono` | Timestamp parsing |

**Design notes:**
- Files processed in parallel batches (rayon thread pool, default = num_cpus)
- Each file: open → detect gzip/json → decompress to `Vec<u8>` → `serde_json::from_slice` (2-5x faster than `from_reader`) → yield individual records
- Progress reported via Tauri Channel: `Channel<ProgressEvent>` where `ProgressEvent { files_total, files_done, records_total }`
- **Performance note:** Always use `read_to_end` + `serde_json::from_slice` instead of `serde_json::from_reader`. The reader approach does many small reads and is significantly slower.
- Memory estimate: ~1KB per record overhead (struct + index entries). 1M records ≈ 1GB RAM. For datasets exceeding available RAM, future phase adds memory-mapped backing store.

### 3.3 In-Memory Store & Indexes (`crates/core/src/store/`)

```rust
pub struct Store {
    records: Vec<IndexedRecord>,
    file_paths: Vec<String>,   // deduped file path table

    // Inverted indexes: field_value → Vec<record_id>
    idx_event_name: HashMap<String, Vec<u64>>,
    idx_event_source: HashMap<String, Vec<u64>>,
    idx_region: HashMap<String, Vec<u64>>,
    idx_source_ip: HashMap<String, Vec<u64>>,
    idx_user_arn: HashMap<String, Vec<u64>>,
    idx_user_name: HashMap<String, Vec<u64>>,
    idx_account_id: HashMap<String, Vec<u64>>,
    idx_error_code: HashMap<String, Vec<u64>>,
    idx_identity_type: HashMap<String, Vec<u64>>,

    // Sorted by timestamp for range queries
    time_sorted_ids: Vec<u64>,
}
```

**Query execution strategy:**
1. Parse query → set of `FieldFilter` predicates + time range
2. For each predicate, look up matching record IDs from the appropriate index
3. Intersect all ID sets (start with smallest set for efficiency)
4. Apply time range filter on the intersection
5. Sort results by timestamp (default) or requested field
6. Return paginated slice (page_size=100 default, cursor-based)

### 3.4 Query Language (`crates/core/src/query/parser.rs`)

Minimal SPL-inspired syntax:

```
# Equality
eventName=CreateUser

# Inequality
sourceIPAddress!=10.0.0.1

# Wildcard (prefix/suffix)
eventName=Create*
userAgent=*boto3*

# AND (implicit or explicit)
eventName=CreateUser sourceIPAddress=1.2.3.4
eventName=CreateUser AND sourceIPAddress=1.2.3.4

# OR
eventName=CreateUser OR eventName=CreateAccessKey

# NOT
NOT eventName=GetBucketAcl

# Parentheses for grouping
(eventName=CreateUser OR eventName=CreateAccessKey) AND sourceIPAddress=1.2.3.4

# Time shorthand (applied as additional filter)
eventName=ConsoleLogin earliest=-24h

# Field existence
errorCode=*        # has errorCode
errorCode!=*       # no errorCode
```

Parser built with a hand-written recursive descent parser (no external grammar dependency — keeps the binary small and avoids proc-macro compile times).

### 3.5 Detection Engine (`crates/core/src/detection/`)

```rust
pub struct DetectionRule {
    pub id: &'static str,           // e.g., "TA0001.console_login_no_mfa"
    pub name: &'static str,
    pub description: &'static str,
    pub severity: Severity,          // Info, Low, Medium, High, Critical
    pub mitre_tactic: &'static str,
    pub mitre_technique: &'static str,
    pub evaluate: fn(&Store) -> Vec<Alert>,
}

pub struct Alert {
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub matching_record_ids: Vec<u64>,  // links to evidence
    pub metadata: HashMap<String, String>,
}
```

Rules are plain Rust functions registered in a static array — no DSL, no config files. This keeps them fast, type-safe, and easy to audit. Each rule function receives a `&Store` reference and returns alerts.

Two rule types:
- **Single-event rules** — scan records matching a filter condition (e.g., `ConsoleLogin` where `mfaAuthenticated != true`)
- **Correlation rules** — query multiple event types and correlate by identity/IP/time window (e.g., `CreateAccessKey` → `different sourceIP uses that key within 1h`)

---

## 4. React Frontend Design

### 4.1 Tech Stack

| Library | Purpose |
|---------|---------|
| React 18 | UI framework |
| TypeScript | Type safety |
| Vite | Build tooling (Tauri default) |
| @tauri-apps/api v2 | IPC with Rust backend |
| @tanstack/react-table | Virtualized event table |
| @tanstack/react-virtual | Virtual scrolling for large lists |
| recharts or visx | Timeline histogram + charts |
| tailwindcss | Styling (dark theme) |
| cmdk or similar | Command palette for power users |
| codemirror 6 | Query bar with syntax highlighting |

### 4.2 Key Views

#### View 1: Ingest / Home
- Drag-and-drop zone for folder or ZIP file
- Shows ingestion progress (files parsed, records loaded, time elapsed)
- Recent sessions list (if session persistence enabled)

#### View 2: Search & Explore (main view, Splunk-inspired)
```
┌─────────────────────────────────────────────────────┐
│  [Query Bar: eventName=ConsoleLogin AND ...]   [Go] │
├────────────┬────────────────────────────────────────┤
│ Filters    │  Timeline Histogram                    │
│            │  ████▅▂▁▃▇████▅▂                       │
│ Time Range │────────────────────────────────────────│
│ [last 24h] │  Events (1,247 of 523,891)            │
│            │  ┌──────────────────────────────────┐  │
│ Event Name │  │ Time  │ EventName │ User │ IP    │  │
│ ☑ Console  │  │ 21:18 │ GetTrail  │ iam… │ 185…  │  │
│ ☑ Create…  │  │ 21:19 │ GetTrail  │ iam… │ 185…  │  │
│ ☐ Get…     │  │ ▶ expanded: raw JSON             │  │
│            │  │ 21:20 │ CreateUs… │ att… │ 203…  │  │
│ Region     │  └──────────────────────────────────┘  │
│ ☑ us-east  │                                        │
│ ☐ eu-west  │  [◀ 1 2 3 ... 124 ▶]                  │
│            │                                        │
│ Source IP  │                                        │
│ [search…]  │                                        │
│ 185.202…(3)│                                        │
│ 203.0.1…(1)│                                        │
└────────────┴────────────────────────────────────────┘
```

#### View 3: Field Statistics
- Top-N values for selected field (bar chart)
- Click a value → auto-populates query bar filter
- Fields: eventName, eventSource, sourceIPAddress, userName, awsRegion, errorCode

#### View 4: Identity Investigation
- Select a principal (by ARN, userName, or accessKeyId)
- See all their actions across all regions, chronologically
- Highlight anomalies (new IP, new region, new action type)

#### View 5: Detection Dashboard
- Summary cards: X Critical, Y High, Z Medium alerts
- Alert list sorted by severity
- Click alert → shows explanation + linked evidence records
- Each alert links to pre-filtered search view showing matching events

### 4.3 UI/UX Notes
- **Dark theme by default** — dark background, monospace for data fields, Splunk-esque color palette
- **Virtualized table** — must handle 500K+ rows without lag (render only visible rows)
- **Pagination** — backend returns pages of 100-500 records; frontend paginates. No sending 500K records over IPC.
- **Keyboard shortcuts** — Ctrl+K for query bar focus, Ctrl+Enter to run query, arrow keys to navigate results
- **Responsive column widths** — auto-size based on content, user-resizable

---

## 5. Data Flow & IPC

### 5.1 Tauri v2 IPC Pattern

All communication uses **Tauri commands** (invoke) for request/response and **Tauri v2 Channels** (`tauri::ipc::Channel<T>`) for streaming progress. Channels guarantee message ordering and are tied to the command invocation lifetime.

```
Frontend                              Backend (Rust)
   │                                      │
   │── invoke("load_directory",           │
   │         {path, onProgress}) ────────►│
   │                                      │── process files (rayon)
   │◄── channel.send(Progress{...}) ─────│   (ordered, per-file updates)
   │◄── channel.send(Progress{...}) ─────│
   │◄── channel.send(Complete{...}) ─────│
   │◄── Ok(summary) ─────────────────────│   (command returns final result)
   │                                      │
   │── invoke("search", {query, page}) ──►│
   │◄── {records: [...], total, page} ────│   (paginated response)
   │                                      │
   │── invoke("get_timeline", {query}) ──►│
   │◄── {buckets: [{time, count},...]} ───│   (histogram data)
   │                                      │
   │── invoke("run_detections") ─────────►│
   │◄── {alerts: [...]} ─────────────────│
   │                                      │
   │── invoke("get_field_values",         │
   │         {field, query, top_n}) ─────►│
   │◄── {values: [{val, count},...]} ─────│
   │                                      │
   │── invoke("export_csv",               │
   │         {query, path}) ─────────────►│
   │◄── {rows_written: 12345} ───────────│
```

### 5.2 State Management

```rust
// Backend: Tauri managed state
struct AppState {
    store: RwLock<Option<Store>>,  // RwLock for concurrent reads during queries
}

// Registered in main.rs:
fn main() {
    tauri::Builder::default()
        .manage(AppState { store: RwLock::new(None) })
        .invoke_handler(tauri::generate_handler![
            commands::ingest::load_directory,
            commands::ingest::load_zip,
            commands::query::search,
            commands::query::get_field_values,
            commands::stats::get_timeline,
            commands::stats::get_identity_summary,
            commands::detection::run_detections,
            commands::export::export_csv,
            commands::export::export_json,
        ])
        .run(tauri::generate_context!())
        .expect("error running TrailInspector");
}
```

Frontend state: React context + useReducer for search state, or Zustand if state grows complex. No Redux — overkill for this.

---

## 6. Built-in Detection Rules

### Initial Access
| ID | Rule | eventName(s) | Logic | MITRE |
|----|------|-------------|-------|-------|
| IA-01 | Console Login Without MFA | `ConsoleLogin` | `responseElements.ConsoleLogin=Success` AND `additionalEventData.MFAUsed!=Yes` | T1078.004 |
| IA-02 | Console Login From Unusual IP | `ConsoleLogin` | Success login from IP not seen in prior logins for this user (baseline) | T1078.004 |
| IA-03 | Root Account Usage | Any | `userIdentity.type=Root` | T1078.004 |
| IA-04 | Failed Login Brute Force | `ConsoleLogin` | ≥5 `responseElements.ConsoleLogin=Failure` within 10min from same `sourceIPAddress` | T1110.001 |

### Persistence
| ID | Rule | eventName(s) | Logic | MITRE |
|----|------|-------------|-------|-------|
| PE-01 | IAM User Created | `CreateUser` | Any CreateUser event | T1136.003 |
| PE-02 | Access Key Created for Another User | `CreateAccessKey` | `requestParameters.userName != userIdentity.userName` (creator ≠ target) | T1098.001 |
| PE-03 | Login Profile Created | `CreateLoginProfile` | Console access added to IAM user | T1098 |
| PE-04 | Backdoor Policy Attached | `AttachUserPolicy`, `AttachRolePolicy`, `PutUserPolicy`, `PutRolePolicy` | Admin policy (`*:*` or `AdministratorAccess`) attached | T1098.003 |
| PE-05 | Lambda Function Created | `CreateFunction20150331` | New Lambda — potential persistence | T1525 |
| PE-06 | EC2 Key Pair Created | `CreateKeyPair`, `ImportKeyPair` | SSH key created/imported | T1098.004 |

### Privilege Escalation
| ID | Rule | eventName(s) | Logic | MITRE |
|----|------|-------------|-------|-------|
| PV-01 | IAM Policy Escalation | `CreatePolicyVersion`, `SetDefaultPolicyVersion` | Policy modified to grant broader permissions | T1484 |
| PV-02 | AssumeRole Cross-Account | `AssumeRole` | Role assumed from different accountId | T1550.001 |
| PV-03 | STS Token via New Method | `GetSessionToken`, `GetFederationToken` | Temporary creds obtained | T1550.001 |

### Defense Evasion
| ID | Rule | eventName(s) | Logic | MITRE |
|----|------|-------------|-------|-------|
| DE-01 | CloudTrail Stopped/Deleted | `StopLogging`, `DeleteTrail`, `UpdateTrail` | Logging tampered with | T1562.008 |
| DE-02 | GuardDuty Disabled | `DeleteDetector`, `StopMonitoringMembers` | GuardDuty turned off | T1562.001 |
| DE-03 | S3 Logging Disabled | `PutBucketLogging` (empty config) | Access logging removed | T1562.008 |
| DE-04 | Config Recorder Stopped | `StopConfigurationRecorder`, `DeleteConfigurationRecorder` | AWS Config disabled | T1562.001 |
| DE-05 | VPC Flow Logs Deleted | `DeleteFlowLogs` | Network logging removed | T1562.008 |
| DE-06 | Event Selectors Modified | `PutEventSelectors` | CloudTrail scope narrowed | T1562.008 |

### Credential Access
| ID | Rule | eventName(s) | Logic | MITRE |
|----|------|-------------|-------|-------|
| CA-01 | Access Key Used From New IP | `CreateAccessKey` → any API call | Key created then used from different IP | T1528 |
| CA-02 | Secrets Manager Accessed | `GetSecretValue` | Bulk secret retrieval (>5 in 10min window) | T1555 |
| CA-03 | SSM Parameter Store Accessed | `GetParameter`, `GetParameters` | Bulk parameter retrieval | T1555 |
| CA-04 | Password Policy Weakened | `UpdateAccountPasswordPolicy` | Password requirements reduced | T1556 |

### Discovery / Reconnaissance
| ID | Rule | eventName(s) | Logic | MITRE |
|----|------|-------------|-------|-------|
| DI-01 | Enumeration Burst | Multiple `List*`, `Describe*`, `Get*` | >20 unique read-only API calls in 5min from same identity | T1580 |
| DI-02 | IAM Enumeration | `ListUsers`, `ListRoles`, `ListPolicies`, `GetAccountAuthorizationDetails` | IAM recon pattern | T1087.004 |
| DI-03 | AccessDenied Spike | Any | ≥10 `errorCode=AccessDenied` within 10min by same identity (permission probing) | T1580 |

### Exfiltration
| ID | Rule | eventName(s) | Logic | MITRE |
|----|------|-------------|-------|-------|
| EX-01 | S3 Bucket Made Public | `PutBucketPolicy`, `PutBucketAcl` | Policy/ACL grants public access | T1537 |
| EX-02 | S3 Bucket Policy Changed | `PutBucketPolicy` | Cross-account access granted | T1537 |
| EX-03 | EC2 Snapshot Shared | `ModifySnapshotAttribute` | Snapshot shared with external account | T1537 |
| EX-04 | RDS Snapshot Shared | `ModifyDBSnapshotAttribute` | DB snapshot shared externally | T1537 |

### Impact
| ID | Rule | eventName(s) | Logic | MITRE |
|----|------|-------------|-------|-------|
| IM-01 | EC2 Instances Launched in Bulk | `RunInstances` | >5 instances launched in 10min (crypto mining indicator) | T1496 |
| IM-02 | Resource Deletion Spree | `Terminate*`, `Delete*` | >10 destructive actions in 5min from same identity | T1485 |
| IM-03 | S3 Objects Mass Deleted | `DeleteObject`, `DeleteBucket` | Bulk deletion pattern | T1485 |

---

## 7. Phased Build Order

### Phase 1: Foundation (MVP — "It loads and searches")
**Goal:** Load CloudTrail logs, display events in a table, basic filtering.

| Task | Details |
|------|---------|
| 1.1 | Scaffold Tauri v2 project with Cargo workspace (`crates/core`, `crates/app`, `ui/`) |
| 1.2 | Implement `model.rs` — CloudTrail record struct with serde |
| 1.3 | Implement `ingest/discovery.rs` — recursive directory walker (walkdir) |
| 1.4 | Implement `ingest/decompress.rs` — gzip + plain JSON detection (flate2) |
| 1.5 | Implement `ingest/parser.rs` — parse `{"Records": [...]}` into `Vec<IndexedRecord>` |
| 1.6 | Implement `store.rs` — basic `Vec<IndexedRecord>` with field indexes |
| 1.7 | Wire ingestion as Tauri command with progress events |
| 1.8 | React: DropZone component for folder selection (Tauri dialog API) |
| 1.9 | React: EventTable with virtual scrolling + pagination |
| 1.10 | React: Basic column display (time, eventName, user, IP, region, error) |
| 1.11 | React: EventDetail panel — click row to expand raw JSON |

**Verification:** Load BlizzardBreakdown dataset, see all records in table, click to expand.

### Phase 2: Search & Filter ("Now you can investigate")
**Goal:** Query bar + filter panel, time range selection.

| Task | Details |
|------|---------|
| 2.1 | Implement `query/parser.rs` — recursive descent parser for query language |
| 2.2 | Implement `query/engine.rs` — execute parsed query against Store indexes |
| 2.3 | Implement `query/filter.rs` — structured filter predicates |
| 2.4 | Wire search as Tauri command (paginated results) |
| 2.5 | React: QueryBar component with CodeMirror (syntax highlighting) |
| 2.6 | React: FilterPanel with checkboxes populated from index data |
| 2.7 | React: TimeRangePicker (absolute datetime or relative shorthand) |
| 2.8 | React: FilterPanel ↔ QueryBar sync (clicking filter updates query, and vice versa) |
| 2.9 | Implement `get_field_values` command — returns top-N values for a field |

**Verification:** Run `eventName=ConsoleLogin AND awsRegion=us-east-1` — see filtered results. Use filter panel — see query bar update.

### Phase 3: Visualization ("See the story")
**Goal:** Timeline histogram, field statistics, identity investigation.

| Task | Details |
|------|---------|
| 3.1 | Implement `stats.rs` — time bucketing (auto-bucket by data range), field value aggregation |
| 3.2 | Wire `get_timeline` Tauri command |
| 3.3 | React: TimelineChart histogram (recharts) — click a time bucket to narrow time range |
| 3.4 | React: FieldStats view — top-N bar charts per field, click to filter |
| 3.5 | Implement identity correlation in Store — group all events by userIdentity ARN |
| 3.6 | React: IdentityTimeline view — per-principal chronological activity |
| 3.7 | React: AppShell layout with sidebar navigation between views |

**Verification:** Load dataset, see histogram. Click bar — zoom into that time window. Open identity view — see attacker's timeline.

### Phase 4: Detection Engine ("Find the bad")
**Goal:** Built-in heuristic rules, alert dashboard.

| Task | Details |
|------|---------|
| 4.1 | Implement `detection/engine.rs` — rule registry, evaluation loop |
| 4.2 | Implement single-event rules (IA-01 through DE-06) |
| 4.3 | Implement correlation rules (CA-01, DI-01, IM-01, IM-02) |
| 4.4 | Wire `run_detections` Tauri command |
| 4.5 | React: AlertPanel — severity cards + alert list |
| 4.6 | React: AlertDetail — explanation + "View Evidence" button (links to pre-filtered search) |
| 4.7 | Auto-run detections on dataset load (background, non-blocking) |

**Verification:** Load BlizzardBreakdown — should fire multiple detection rules. Click alert — see matching events.

### Phase 5: Polish & Export ("Ship it")
**Goal:** Export, session persistence, dark theme polish, cross-platform builds.

| Task | Details |
|------|---------|
| 5.1 | Implement `export.rs` — CSV and JSON export of filtered results |
| 5.2 | Wire export Tauri commands with file save dialog |
| 5.3 | Session persistence — save last dataset path + query to local storage |
| 5.4 | ZIP archive support — extract to temp dir, ingest, cleanup |
| 5.5 | Keyboard shortcuts (Ctrl+K, Ctrl+Enter, etc.) |
| 5.6 | Dark theme polish — consistent Splunk-inspired color palette |
| 5.7 | StatusBar — record count, memory usage, query execution time |
| 5.8 | Cross-platform CI — GitHub Actions for Windows (.msi), Linux (.deb/.AppImage), macOS (.dmg) |
| 5.9 | Error handling polish — graceful handling of malformed files, permission errors |
| 5.10 | App icon and branding |

**Verification:** Full workflow test on all 3 sample datasets. Export results as CSV. Build on all 3 platforms.

---

## 8. Known Technical Risks

### Risk 1: Memory Usage at Scale
**Problem:** 1GB compressed CloudTrail ≈ 5-10GB uncompressed ≈ 5-10M records ≈ 5-10GB RAM with indexes.
**Mitigation (Phase 1):** Start with in-memory. Add a "dataset too large" warning at >2GB uncompressed.
**Mitigation (Future):** Swap to memory-mapped storage (redb or SQLite) for records, keep only indexes in memory. This is a Phase 6 concern — don't over-engineer the MVP.

### Risk 2: IPC Serialization Overhead
**Problem:** Sending large result sets over Tauri IPC (JSON serialization) can be slow.
**Mitigation:** Always paginate — never send more than 500 records per IPC call. Timeline/stats are pre-aggregated server-side (small payloads). Use Tauri channels for streaming if needed.

### Risk 3: Query Language Ambiguity
**Problem:** Users may expect full SPL but we only support a subset.
**Mitigation:** Clear query bar placeholder text showing supported syntax. Autocomplete for field names. Error messages suggesting corrections.

### Risk 4: Cross-Platform Build Complexity
**Problem:** Tauri builds require platform-specific toolchains (MSVC on Windows, GTK on Linux, Xcode on macOS).
**Mitigation:** GitHub Actions matrix build. Document local dev setup per platform.

### Risk 5: Detection Rule False Positives
**Problem:** Rules like "enumeration burst" may fire on legitimate admin activity.
**Mitigation:** Every alert shows full evidence. Rules have tunable thresholds. Severity levels help triage. Consider adding a "suppress" feature in future phase.

---

## Appendix: Key Crate Versions (as of 2026-03)

```toml
# crates/core/Cargo.toml
[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
flate2 = { version = "1", features = ["zlib-ng"], default-features = false }
zip = "2"
walkdir = "2"
rayon = "1"
chrono = { version = "0.4", features = ["serde"] }

# crates/app/Cargo.toml
[dependencies]
trail-inspector-core = { path = "../core" }
tauri = { version = "2", features = [] }
tauri-plugin-dialog = "2"    # file/folder picker
tauri-plugin-fs = "2"        # filesystem access
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

```json
// ui/package.json (key deps)
{
  "@tauri-apps/api": "^2",
  "@tauri-apps/plugin-dialog": "^2",
  "@tanstack/react-table": "^8",
  "@tanstack/react-virtual": "^3",
  "recharts": "^2",
  "@codemirror/view": "^6",
  "tailwindcss": "^4"
}
```
