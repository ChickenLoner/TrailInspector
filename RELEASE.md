## TrailInspector v0.1.0 — Initial Release

First public release of TrailInspector, an offline desktop tool for investigating AWS CloudTrail logs.

### Features

- **Ingest** — load `.json.gz` files from standard AWS directory structures, or drop a ZIP archive; parallel decompression via Rayon
- **Search** — SPL-like query syntax with `AND`, `OR`, `NOT`, wildcards, and field-level filtering (`eventName=AssumeRole AND errorCode=*`)
- **Timeline** — histogram of event volume over time; field statistics breakdown
- **Detections** — 18 MITRE ATT&CK-mapped rules covering privilege escalation, credential access, persistence, and defense evasion
- **Evidence linking** — click any alert to auto-filter the event table to matching evidence
- **Export** — save filtered results as CSV or JSON
- **Session persistence** — query state and active tab survive app restarts
- **Keyboard shortcuts** — `/` to focus query bar, `Escape` to clear, `Ctrl+E` to export
- **No cloud required** — works fully offline; no AWS credentials needed

### Installation

| Platform | File |
|----------|------|
| Windows 10+ | `.msi` installer |
| macOS 11+ | `.dmg` disk image |
| Linux | `.deb` package or `.AppImage` |

> **Linux note:** The `.AppImage` runs on any modern distro without installation. The `.deb` targets Debian/Ubuntu.

### Built with

Tauri v2 · Rust · React · TypeScript · TailwindCSS

---

*Made by Warawut Manosong (Chicken0248)*
