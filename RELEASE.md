## TrailInspector v1.3.0 — Custom Detection Rules

This release lets users write their own YAML detection rules without touching Rust code, alongside the existing 60 built-in rules.

### What's New

- **Custom rules (YAML)** — define your own detection rules in `rules.yaml` using a recursive AND/OR/NOT filter tree; rules fire alongside built-in rules in the Detection tab
- **Event name matching** — `event_name` accepts a single string or a list; match any of multiple API calls in one rule
- **Threshold detection** — optional sliding-window threshold (`count` events within `window_secs`) turns any rule into a frequency-based detector
- **MITRE ATT&CK metadata** — each rule carries optional `tactic`, `technique`, `technique_id`, and `mitre_url` fields surfaced in the alert detail panel
- **Hot-reload** — edit `rules.yaml`, click "Reload Rules" in the Detection tab; no app restart required
- **Open in editor** — "Open Rules File" button launches `rules.yaml` in your default text editor
- **Parse error reporting** — invalid rules show an amber banner listing each error; built-in rules continue running unaffected
- **Duplicate ID detection** — rules sharing an `id` are both rejected and reported as errors
- **5 example rules** — `rules.yaml` is pre-populated with CR-01 through CR-05 on first launch

### Schema

```yaml
rules:
  - id: CR-01
    name: "Human-readable rule name"
    enabled: true
    severity: High        # Critical | High | Medium | Low | Info
    tactic: Persistence
    technique: "Valid Accounts"
    technique_id: T1078
    match_spec:
      event_name: DeleteGroup          # or a list: [DeleteGroup, DeleteUser]
      event_source: iam.amazonaws.com  # optional
    filters:                           # optional recursive AND/OR/NOT tree
      and:
        - field: user_name
          value: "alice"
        - not:
            field: user_agent
            value: "terraform/*"
    threshold:                         # optional — fires only if count within window
      count: 5
      window_secs: 300
```

### Installation

| Platform | File |
|----------|------|
| Windows 10+ | `.exe` (NSIS installer) |
| macOS 11+ | `.dmg` disk image |
| Linux | `.deb` package or `.AppImage` |

### Built with

Tauri v2 · Rust · React · TypeScript · TailwindCSS

---

*Made by Warawut Manosong (Chicken0248)*
