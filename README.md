<p align="center">
  <img src="assets/banner.jpg" alt="TrailInspector" width="100%"/>
</p>

<h1 align="center">TrailInspector</h1>

<p align="center">
  A fast, offline desktop tool for investigating AWS CloudTrail logs — built for blue teamers, incident responders, and cloud security engineers.
</p>

<p align="center">
  <a href="https://github.com/ChickenLoner/TrailInspector/releases"><img src="https://img.shields.io/github/v/release/ChickenLoner/TrailInspector?style=flat-square&color=green" alt="Latest Release"/></a>
  <a href="https://github.com/ChickenLoner/TrailInspector/actions"><img src="https://img.shields.io/github/actions/workflow/status/ChickenLoner/TrailInspector/release.yml?style=flat-square" alt="Build Status"/></a>
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue?style=flat-square" alt="Platform"/>
  <img src="https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square" alt="License"/>
</p>

---

## Overview

TrailInspector loads raw CloudTrail exports — `.json`, `.json.gz`, or ZIP archives — entirely in memory and lets you search, visualize, and triage threats without sending data to any external service. The investigation workflow is modeled after Splunk: a query bar with SPL-like syntax, a timeline histogram for scoping time windows, field statistics for pivoting on values, and a detections panel that fires 18 MITRE ATT&CK-mapped rules automatically.

## Screenshots

### Search & Event Table
Filter events with SPL-like queries (`AND`, `OR`, `NOT`, wildcards). Results stream into a paginated table with inline time scoping via the timeline histogram.

![Search UI](assets/search_ui.png)

### Field Statistics
One click reveals value distributions for every field in the current result set — event names, regions, source IPs, error codes.

![Field Statistics](assets/stats_ui.png)

### Detections — MITRE ATT&CK Mapped Rules
18 built-in detection rules fire automatically. Each alert shows severity, tactic/technique, a plain-English description, and the exact search query used — click **View Evidence** to jump straight to matching events.

![Detections UI](assets/rule_ui.png)

### Identity Timeline
Pivot to any IAM identity and see every action it took in chronological order — first seen, last seen, active span, and a full event list.

![Identity Timeline](assets/identity_ui.png)

---

## Features

| Capability | Details |
|---|---|
| **Ingest** | `.json`, `.json.gz`, `.zip`, and nested directory trees |
| **Search** | SPL-like query bar — `AND` / `OR` / `NOT`, field matching, wildcards, time presets |
| **Visualize** | Timeline histogram, field statistics, identity activity timeline |
| **Detect** | 18 MITRE ATT&CK-mapped rules (PE, DE, EX, DI series) with severity levels |
| **Investigate** | One-click "View Evidence" jumps from alert → filtered event table |
| **Export** | Save filtered results as JSON or ZIP archive |
| **Offline** | No telemetry, no cloud dependency — all processing happens locally |

---

## Installation

Download the latest installer for your platform from the [Releases](https://github.com/ChickenLoner/TrailInspector/releases) page:

| Platform | Format |
|---|---|
| Windows | `.msi` installer |
| Linux | `.AppImage` / `.deb` |
| macOS | `.dmg` |

---

## Build from Source

### Prerequisites

- [Rust](https://rustup.rs/) (stable toolchain)
- [Node.js](https://nodejs.org/) 18+
- [Tauri v2 prerequisites](https://tauri.app/start/prerequisites/) for your platform

### Development

```bash
# Install frontend dependencies
cd ui && npm install

# Start frontend dev server (port 5500)
npm run dev

# In a second terminal — launch the full Tauri app
cargo tauri dev
```

### Run Tests

```bash
cargo test -p trail-inspector-core
```

### Production Build

```bash
cargo tauri build
```

Installers are written to `crates/app/target/release/bundle/`.

---

## Architecture

```
TrailInspector/
├── crates/
│   ├── core/          # Pure Rust library — parse, index, query, detect (no Tauri)
│   └── app/           # Tauri v2 IPC glue — thin command wrappers only
└── ui/                # React + TypeScript + Vite + TailwindCSS frontend
```

`crates/core` has zero Tauri dependency and is fully testable as a standalone library. All business logic — ingestion, indexing, the query engine, and detection rules — lives there.

---

## Detection Rules

Rules are evaluated in-memory against the loaded event set and mapped to MITRE ATT&CK tactics and techniques:

| ID | Rule | Severity | Tactic |
|---|---|---|---|
| PE-04 | Administrative Policy Attached | Critical | Persistence |
| DE-01 | CloudTrail Logging Tampered | Critical | Defense Evasion |
| EX-01 | S3 Bucket Policy/ACL Modified | High | Exfiltration |
| PE-01 | IAM User Created | Medium | Persistence |
| DI-02 | IAM Enumeration Detected | Medium | Discovery |
| … | 13 additional rules | Various | Various |

---

## License

MIT © [ChickenLoner](https://github.com/ChickenLoner)
