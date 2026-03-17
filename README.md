![TrailInspector](assets/banner.jpg)

# TrailInspector

A cross-platform standalone desktop application for analyzing AWS CloudTrail JSON exports with built-in detection rules, modeled after Splunk's investigation workflow.

## Features

- **Analyze** — Load CloudTrail JSON or `.json.gz` / ZIP archives and query events with an SPL-like syntax (AND/OR/NOT/wildcards)
- **Visualize** — Timeline histogram, field statistics, and identity activity timeline
- **Detect** — 18 MITRE ATT&CK-mapped detection rules with alert panel and one-click "View Evidence" filtering
- **Export** — Save filtered results as JSON or ZIP archive

## Stack

- **Backend:** Rust (`crates/core` — pure library, `crates/app` — Tauri v2 IPC wrapper)
- **Frontend:** React + TypeScript + Vite + TailwindCSS
- **Distribution:** Single binary — Windows (MSI), Linux (AppImage/deb), macOS (dmg)

## Getting Started

### Prerequisites

- [Rust](https://rustup.rs/) (stable)
- [Node.js](https://nodejs.org/) 18+
- [Tauri CLI](https://tauri.app/start/prerequisites/)

### Development

```bash
# Install frontend dependencies
cd ui && npm install

# Start frontend dev server (port 5500)
npm run dev

# In another terminal — run the full Tauri app
cargo tauri dev
```

### Run Core Tests

```bash
cargo test -p trail-inspector-core
```

### Production Build

```bash
cargo tauri build
```

Installers are output to `src-tauri/target/release/bundle/`.

## CI

GitHub Actions builds and tests on every push to `main` across Windows, Linux, and macOS.

## License

MIT
