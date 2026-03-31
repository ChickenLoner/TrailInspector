# TrailInspector v1.1.0 — Implementation Plan

> **Sustainability + Investigation Improvements**
> Replace MaxMind dependency with free DB-IP Lite. Add global time-range filter across all tabs.

---

## Dependency Graph

```
Part 1 (DB-IP Lite text swap — no code changes)
Part 2 (Global time filter)
  ├──> Backend: store.get_ids_in_range() helper
  ├──> Backend: session/detection/geoip/stats commands + time params
  ├──> Frontend: tauri.ts bindings + GlobalTimeRange type
  ├──> Frontend: GlobalTimeBar component
  ├──> App.tsx + AppShell refactor
  └──> Tab components: SessionView, IpView, DetectionView, IdentityTimeline
```

---

## Part 1: Replace MaxMind with DB-IP Lite ✅

No code logic changes — the `maxminddb` crate reads DB-IP Lite `.mmdb` files natively.

| File | Change |
|------|--------|
| `crates/core/src/geoip.rs` | Update doc comments |
| `ui/src/components/ip/IpView.tsx` | File names → `dbip-city-lite.mmdb`, `dbip-asn-lite.mmdb` |
| `README.md` | GeoIP setup section |
| `RELEASE.md` | GeoIP setup section |
| `CHANGELOG.md` | Add v1.1.0 entry |

---

## Part 2: Global Time-Range Filter

### Backend

#### `crates/core/src/store/store.rs` ✅
- `pub fn get_ids_in_range(&self, start_ms: i64, end_ms: i64) -> Vec<u64>` — binary search on `time_sorted_ids`

#### `crates/core/src/session.rs` ✅
- `list_sessions()` + `time_range: Option<(i64, i64)>` overlap filter

#### `crates/core/src/detection/mod.rs` ✅
- `pub fn filter_alerts_by_time(store, alerts, start_ms, end_ms) -> Vec<Alert>`

#### `crates/app/src/commands/session.rs` ✅
- `list_sessions`: add `start_ms: Option<i64>`, `end_ms: Option<i64>`

#### `crates/app/src/commands/detection.rs` ✅
- `run_detections`: add `start_ms: Option<i64>`, `end_ms: Option<i64>`

#### `crates/app/src/commands/geoip.rs` ✅
- `list_ips`: add `start_ms: Option<i64>`, `end_ms: Option<i64>`, build ip_counts from time-filtered IDs

#### `crates/app/src/commands/stats.rs` ✅
- `get_identity_summary_cmd`: add `start_ms: Option<i64>`, `end_ms: Option<i64>`

### Frontend

#### `ui/src/types/cloudtrail.ts` ✅
- Add `GlobalTimeRange` interface

#### `ui/src/lib/tauri.ts` ✅
- Add `startMs?`, `endMs?` to `listSessions`, `listIps`, `runDetections`, `getIdentitySummary`

#### `ui/src/components/layout/GlobalTimeBar.tsx` ✅ (new)
- Preset buttons (All, 1h, 6h, 24h, 7d) + Custom date picker

#### `ui/src/App.tsx` ✅
- Replace `timePreset` with `globalTimeRange`, render `<GlobalTimeBar>` above `<AppShell>`

#### `ui/src/components/layout/AppShell.tsx` ✅
- Accept + pass `startMs?`, `endMs?` to tab components

#### Tab components ✅
- `SessionView.tsx`, `IpView.tsx`, `DetectionView.tsx`, `IdentityTimeline.tsx`
