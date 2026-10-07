## TrailInspector v1.6.0 — Filters that stay put, detection 8× faster

A maintenance release: three filter bugs that made the sidebar lie to you, four rules whose "view evidence" link under-reported, and a detection pass that spent 91% of its time in one rule.

### Fixed

**Filters**

- **An excluded value could become unreachable.** Exclude a user, switch to another tab, come back — the filter was still narrowing your results, but the value had vanished from the sidebar and the Clear button had hidden itself. There was no way to undo it from the panel. The search view is unmounted on every tab switch, and the filter state lived inside it while the query fragment derived from it lived in the parent; the child's copy died and the parent kept filtering. Filters now live in one place
- **Filtering a value emptied its own section.** Clicking a user to include them scoped that field's own counts to that user, so everyone else dropped to zero and disappeared — you had to clear before you could pick someone else. Each field is now counted with its own clause removed, so an excluded value keeps a real count and stays clickable, while other fields still narrow as you'd expect

**Alerts**

- **Alerts vanished when you narrowed the time range.** Only the first 100 matching records are sent to the UI, but that cap was applied *before* the time filter — so an alert whose first 100 records fell outside your window disappeared entirely, even when it had thousands of matches inside it
- **Custom-rule alerts sent unbounded record lists** over IPC; only built-in rules were capped
- **Session ↔ alert correlation used a truncated sample** — it matched against each alert's first 100 records rather than all of them
- **"View evidence" showed fewer events than the alert counted.** DI-02 matched 7 event names but its query listed 5; PE-04 matched 6 and listed 4; LM-02 matched 2 and listed 1; RDS-02 matched 3 and listed 2. Queries are now derived from what the rule actually matches
- **The same alert had two different severity colours** depending on whether you looked at the list or the detail panel

### Performance

- **Detection is ~8× faster** — 1.42s → 176ms on 100,000 records. Nearly all of it was IM-01: it is the only rule that reports every burst rather than stopping at the first, and it was re-collecting the entire window on every step
- **Rules now run in parallel** — worth 2.4× once IM-01 stopped dominating
- **The filter sidebar is much quicker to respond.** Each click fires nine count queries; each one used to execute the query, materialise every matching record id, sort it by time, then walk every record. They now intersect compressed bitmaps instead, so cost scales with how many distinct values a field has rather than how many records matched. S3 bucket counts stop reading a JSON blob per record
- **Faster dev builds** — dependencies are optimised while your own crates stay quick to compile; the core test suite dropped from 5.66s to 0.43s
- **Release builds** use fat LTO and a single codegen unit

### Changed

- Alert record ids come out in a stable order. They previously followed hash-map iteration order, so the 100-record preview could differ between runs on identical data
- The detail panel's severity colours now match the alert list
- Removed a redundant `count` field from four alerts' metadata — it repeated the record count already shown

### For developers

Rule identity — id, title, severity, MITRE mapping, service — now lives only in the registry. Rules return what they found and the registry stamps the rest, so a rule can no longer disagree with the table it is registered in. 31 rules that were plain index lookups became declarative specs; the sliding-window logic that seven rules had each copied is now shared.

**Breaking for `trail-inspector-core` consumers:** `DetectionRule.name` is now `title`, `evaluate` is an `Eval` enum, rule functions return `Option<Finding>`, and 31 rule functions were removed. The desktop app is unaffected.
