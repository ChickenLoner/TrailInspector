# Remediation plan: October 2026 code review

Companion to `docs/plans/2026-10-code-review.md` (the findings). This file is the
**execution contract** for the session doing the work. Read this whole file and
`CLAUDE.md` before touching code.

## 0. How to work this plan

**Scope lock.** Do exactly the tasks below, in order, one commit per task
(task id in the commit subject, e.g. `fix(detection): P1.1 filter alerts by time before capping`).
Anything you notice that is not a listed task goes into §9 "Deferred" as a one-line
bullet. Do not fix it. Do not refactor around it. Do not add features. Do not add
dependencies except the ones a task names.

**Verification before every commit.**

```bash
cargo test -p trail-inspector-core
cargo test -p trail-inspector-core --features aws
cargo check -p trail-inspector-app
cd ui && npx tsc --noEmit -p tsconfig.app.json
```

Run all four for every Rust task and the last one for every UI task. If `npm ci`
fails on the Vite peer conflict, use `npm ci --legacy-peer-deps`; do not change
`package.json` to make it pass (that is task P4.7).

**Tests are part of every task.** Each task lists the tests it must add. A task is
not done until its tests exist, fail on the old code (check by stashing or
reasoning from the diff), and pass on the new code. Use the existing helpers in
`crates/core/src/detection/tests.rs` (`make_indexed`, `make_indexed_ts`,
`with_params`, `with_resp`, `build_store`). Add a `with_error(rec, code)` helper
and a `with_identity(rec, identity_type, arn, user_name)` helper in P1.2.

**When a test fails that you did not write.** Decide which it is:
- The fixture is wrong (for example, an `event_source` that does not match the
  event name). Fix the fixture.
- The rule's old behaviour was the bug. Update the assertion and say so in the
  commit body.
- Neither. Stop, do not force it green, write what you found in §10 and move to
  the next task.

**Never**: skip, `#[ignore]`, or delete a test to get green; change a severity or
threshold that a task does not name; touch `RULES.md` wording except where a task
says to; push anything that fails the verification block.

**Progress log.** §10 at the bottom is a checklist. Tick each task when its commit
exists. Record the bench numbers from P0 and P6 there.

**Branch.** All work goes on the branch the session was given. Push after each
phase (not each task) with `git push -u origin <branch>`. Open one draft PR for
the branch if none exists; update its description with the §10 checklist state
after each phase.

---

## 1. Phase 0: Baseline (no code changes)

### P0.1 Record the baseline
1. Run the verification block. All four must pass before you start. If one does
   not, record the output in §10 and stop; the plan assumes a green baseline.
2. Run the ignored bench three times and record the median in §10:
   ```bash
   cargo test -p trail-inspector-core --release -- --ignored bench_detection_100k_records --nocapture
   ```
3. Count rules: `grep -c 'id: "' crates/core/src/detection/mod.rs` and record it.
   (`custom_rules.rs:3`, `tests.rs:949`, the default `rules.yaml` template and `RULES.md`
   each quote a different number. P1.6 fixes them.)

---

## 2. Phase 1: Detection engine correctness

Files: `crates/core/src/detection/mod.rs`, `crates/core/src/detection/custom_rules.rs`,
`crates/core/src/detection/tests.rs`, `crates/app/src/commands/detection.rs`,
`crates/app/src/commands/session.rs`.

### P1.1 Filter alerts by time before capping IDs
**Bug.** `run_all_rules` and `run_geo_rules` call `cap_alert_ids` (truncate to 100),
then the Tauri command calls `filter_alerts_by_time` on the truncated list.

**Change.**
- In `mod.rs`, make `run_all_rules`, `run_geo_rules` and `custom_rules::run_custom_rules`
  return **uncapped** alerts. Remove the `cap_alert_ids` calls from them.
- Make `cap_alert_ids` `pub`.
- Add `pub fn finalize_alerts(store: &Store, alerts: Vec<Alert>, time_range: Option<(i64, i64)>) -> Vec<Alert>`
  in `mod.rs` that does, in this order: optional `filter_alerts_by_time`, then
  `cap_alert_ids`, then sort by severity descending, then by `rule_id` ascending
  as a tiebreak (stable ordering).
- In `crates/app/src/commands/detection.rs::run_detections` and in
  `crates/app/src/commands/session.rs` wherever rules are run, replace the local
  cap/sort/filter sequence with one `finalize_alerts` call. Check `grep -rn "cap_alert_ids\|filter_alerts_by_time\|sort_by(|a, b| b.severity" crates/` afterwards: the only callers must be `finalize_alerts` and tests.

**Tests** (in `tests.rs`):
- `finalize_filters_before_cap`: 150 `StopLogging` records with timestamps `i * 60_000`,
  time range covering only ids 120..=149. Assert the DE-01 alert survives with
  `matching_count == 30` and 30 ids, all inside the range.
- `finalize_caps_at_100`: 150 records, no time range, `matching_count == 150`,
  `matching_record_ids.len() == 100`.

### P1.2 Engine-wide scoping: event source and error code
**Bug.** No rule checks `eventSource` or `errorCode`.

**Change.** Add to `mod.rs`:

```rust
/// Candidate ids for a rule: the union of the named events, restricted to the given
/// event sources, minus every record that carries an errorCode (failed calls are
/// not completed actions). `sources` empty means "any source".
pub fn scoped_ids(store: &Store, event_names: &[&str], sources: &[&str], exclude_errors: bool) -> RoaringBitmap
```

Implementation: union `store.idx_event_name[name]` for each name; if `sources` is
non-empty, `&=` the union of `store.idx_event_source[src]`; if `exclude_errors`,
`-=` the union of **all** posting lists in `store.idx_error_code` (cache that
union once per call; it is cheap). Return the bitmap.

Then convert **every** built-in rule in `rules/*.rs` to obtain its initial ids via
`scoped_ids(store, &[...names...], &[...sources...], true)` instead of
`store.idx_event_name.get(...)`. Where a rule iterates several names in a loop,
collapse into one `scoped_ids` call. Where a rule already does its own union
(IM-02 prefix scan over `idx_event_name`), keep the scan but `&=`/`-=` the same
way via a second helper `pub fn restrict(store, ids: RoaringBitmap, sources, exclude_errors) -> RoaringBitmap`.

Source mapping (use exactly these):

| Rules | `sources` |
|---|---|
| IA-01, IA-04, CA-05, GEO-02 (ConsoleLogin) | `["signin.amazonaws.com"]` |
| IA-03 | none (identity-type rule; still `exclude_errors = true`) |
| PE-01..PE-06, CA-04, DI-02 | `["iam.amazonaws.com"]` |
| PE-07 | `["sts.amazonaws.com"]` |
| DE-01, DE-07 | `["cloudtrail.amazonaws.com"]` |
| DE-02 | `["guardduty.amazonaws.com"]` |
| DE-04 | `["config.amazonaws.com"]` |
| DE-05, NW-*, EBS-*, EC-01..EC-06, EC-08, IM-01, IM-04..IM-06, RS-01 | `["ec2.amazonaws.com"]` |
| DE-06 | `["logs.amazonaws.com"]` |
| DE-08 | `["events.amazonaws.com"]` |
| DE-09 | `["waf.amazonaws.com", "wafv2.amazonaws.com", "waf-regional.amazonaws.com"]` |
| DE-10 | `["cloudfront.amazonaws.com"]` |
| DE-11 | `["sqs.amazonaws.com"]` |
| DE-12 | `["sns.amazonaws.com"]` |
| DE-13 | `["route53.amazonaws.com"]` |
| CA-02 | `["secretsmanager.amazonaws.com"]` |
| CA-06 | `["kms.amazonaws.com"]` |
| EX-01..EX-05 | `["s3.amazonaws.com"]` |
| IM-03 | `["ses.amazonaws.com"]` |
| RDS-01..RDS-03, RS-03 | `["rds.amazonaws.com"]` |
| EC-07, RS-02 | `["ssm.amazonaws.com"]` |
| LM-01, LM-02 | `["lambda.amazonaws.com"]` |
| DI-03 (AccessDenied spike) | none, and `exclude_errors = false` (it is *about* errors) |
| IM-02 | none for sources (multi-service by design), `exclude_errors = true` |
| GEO-01 | none; see P2.8 |

Each rule's `query` string must gain ` AND eventSource=<src>` for single-source
rules (so "View evidence" in the UI shows the same set the rule evaluated).
Multi-source rules append `AND (eventSource=a OR eventSource=b)` — check first
that the query parser handles parentheses; it does **not** today (see
`crates/core/src/query/parser.rs`). So for multi-source rules leave the query
unchanged and note it in §9.

**Fixtures.** The bench (`tests.rs::bench_detection_100k_records`) sets
`event_source` to `ec2.amazonaws.com` for all 14 event names. Replace the
`event_names` array with `(name, source)` pairs using the table above so the
bench still exercises every rule. Scan the other tests for the same mismatch.

**Tests:**
- `scoped_ids_excludes_errors`: two `StopLogging` records from
  `cloudtrail.amazonaws.com`, one with `error_code = Some("AccessDenied")`.
  DE-01 fires with exactly one id.
- `scoped_ids_filters_source`: `CreateUser` from `transfer.amazonaws.com` must not
  fire PE-01; from `iam.amazonaws.com` must.
- `di_03_still_counts_errors`: DI-03 continues to fire on AccessDenied bursts.

### P1.3 Cap custom-rule alert IDs
`run_custom_rules` output goes through `finalize_alerts` after P1.1, so the cap now
applies. Add test `custom_rule_ids_capped` with 150 matching records asserting 100
ids and `matching_count == 150`.

### P1.4 Validate custom-rule `window_minutes`
In `load_custom_rules`, after the `min_count == 0` check, reject
`window_minutes > 527_040` (one year in minutes) with the message
`Rule '<id>': threshold.window_minutes must be <= 527040 (1 year)`. In
`check_threshold` use `window_minutes as i64 * 60_000` only after that validation,
and change the inner loop guard to `while left < right && ts[right] - ts[left] > window_ms`.
Also validate `mitre_technique` when non-empty against `^T\d{4}(\.\d{3})?$` with a
hand-written check (no regex crate). Add tests for both rejections in the
existing custom-rule test module.

### P1.5 Clamp every paginated IPC payload
In `crates/app/src/commands/session.rs::list_sessions` and `get_session_detail`,
and `crates/app/src/commands/geoip.rs::list_ips`, clamp `page_size` with
`.clamp(1, 500)`. In `crates/core/src/s3.rs::get_s3_summary`, truncate the
`buckets` and `identities` vectors to 500 after sorting (check the struct field
names in the file; truncate whatever is unbounded). No new tests required; add a
one-line doc comment on each clamp referencing the CLAUDE.md rule.

### P1.6 Fix the rule count in prose
Use the number from P0.1 step 3 in `custom_rules.rs` module doc, the
`DEFAULT_RULES_YAML` header comment, `tests.rs` bench comment, and the first
paragraph of `RULES.md`. Nothing else in `RULES.md` changes in this task.

---

## 3. Phase 2: Rule logic rewrites

All in `crates/core/src/detection/rules/`. Pattern for every rule below: replace
`get_request_parameters_str(...).contains(...)` with
`store.parse_request_parameters(id)` and navigate the JSON. Add a small private
helper per file where it helps readability. Each task: one commit, tests listed.

Reference request shapes (CloudTrail camelCases the first letter of each key):

### P2.1 RS-03 RDS snapshot made public
`ModifyDBSnapshotAttribute` / `ModifyDBClusterSnapshotAttribute` params:
`{"attributeName":"restore","valuesToAdd":["all"]}`. Fire only when
`attributeName == "restore"` **and** `valuesToAdd` contains `"all"`
(case-insensitive). `valuesToRemove` never fires. Tests: fires on add-all; does
not fire on remove-all; does not fire on add-specific-account.

### P2.2 EBS-02 snapshot public and RS-01 AMI public
`ModifySnapshotAttribute`: `{"createVolumePermission":{"add":{"items":[{"group":"all"}]}}}`.
`ModifyImageAttribute`: `{"launchPermission":{"add":{"items":[{"group":"all"}]}}}`
(also accept `{"attributeType":"launchPermission","operationType":"add","userGroups":{"items":[{"group":"all"}]}}`).
Fire only when an `add` item has `group == "all"`. `remove` never fires. Tests:
add-all fires; remove-all does not; add `userId` does not; description containing
"install" does not.

### P2.3 RS-02 SSM document public
`ModifyDocumentPermission`: `{"name":"...","permissionType":"Share","accountIdsToAdd":["all"]}`.
Fire only when `accountIdsToAdd` contains `"all"` (case-insensitive). Tests:
add-all fires; `accountIdsToRemove:["all"]` does not; document named `AllowSSH`
with a specific account does not.

### P2.4 RDS-01 deletion protection disabled
Fire only when `params["deletionProtection"] == Value::Bool(false)`. Tests: `false`
fires; `true` with `applyImmediately:false` does not; absent does not.

### P2.5 DE-10 CloudFront logging disabled
Fire only when `params["distributionConfig"]["logging"]["enabled"] == false`.
Test: that shape fires; `trustedSigners.enabled:false` alone does not.

### P2.6 EX-01 S3 bucket made public
Rewrite `is_public_grant`:
- `PutBucketAcl`: fire if any grant's `grantee.URI` is the AllUsers or
  AuthenticatedUsers group URI, or `x-amz-acl` / `accessControlList` header value
  is `public-read`, `public-read-write`, or `authenticated-read`.
- `PutBucketPolicy`: `bucketPolicy` may be a string or an object. Parse it; for
  each statement with `Effect == "Allow"`, fire if `Principal == "*"` or
  `Principal.AWS` is `"*"` or contains `"*"`, **and** the statement has no
  `Condition` key. Statements with a `Condition` are logged into `metadata`
  under `conditional_wildcard_count` but do not fire.
- Remove the unconditional "has bucketPolicy → fire" fallback.
Tests: ACL AllUsers fires; policy `Principal:"*"` no condition fires; policy
`Principal:{"AWS":"arn:aws:iam::111:root"}` does not; policy with wildcard plus
`Condition` does not.

### P2.7 PE-04 admin policy attached
Rewrite `check_admin_policy`:
- Managed ARNs: fire on `arn:aws:iam::aws:policy/AdministratorAccess`,
  `.../PowerUserAccess`, `.../IAMFullAccess`.
- Inline `policyDocument`: parse the string as JSON (it is URL-encoded in some
  trails; try `percent-decoding` manually only for `%` followed by two hex digits,
  no crate). Fire if any statement has `Effect == "Allow"` and `Action` equals
  `"*"` or `"iam:*"` (string or array containing it) **and** `Resource` is `"*"`
  or contains `"*"`.
- Add `AttachGroupPolicy` and `PutGroupPolicy` to the event list and the `query`.
Tests: pretty-printed admin inline doc fires; `s3:GetObject` on `*` does not;
`PowerUserAccess` fires; group variants fire.

### P2.8 PE-02 caller derivation
Derive `caller` as: `user_identity.user_name` if present; else the last path
segment of `user_identity.arn` after `:user/`; else (AssumedRole, Root, anything
else) an empty string **that counts as "other"**. Fire when `target` is non-empty
and (`caller` is empty or `caller != target`). Tests: IAMUser creating a key for
self does not fire; AssumedRole creating a key for `admin` fires; IAMUser `alice`
creating for `bob` fires.

### P2.9 IA-01 SSO exemption
Skip the record if `user_identity.identity_type == Some("AssumedRole")` or the
`additionalEventData` has a `SamlProviderArn` key. Keep the `MFAUsed != "Yes"`
logic otherwise. Test: AssumedRole ConsoleLogin with MFAUsed No does not fire;
IAMUser with MFAUsed No fires.

### P2.10 IM-02 deletion spree allow-list
Replace the prefix scan with an explicit list of management-plane destructive
event names (put it in a `const DESTRUCTIVE_EVENTS: &[&str]` in `impact.rs`):
`DeleteBucket, DeleteDBInstance, DeleteDBCluster, DeleteDBSnapshot, DeleteDBClusterSnapshot, TerminateInstances, DeleteVolume, DeleteSnapshot, DeregisterImage, DeleteVpc, DeleteSubnet, DeleteSecurityGroup, DeleteRouteTable, DeleteInternetGateway, DeleteNatGateway, DeleteLoadBalancer, DeleteTargetGroup, DeleteFunction20150331, DeleteFunction, DeleteTable, DeleteStack, DeleteCluster, DeleteService, DeleteRepository, DeleteKeyPair, DeleteUser, DeleteRole, DeleteGroup, DeletePolicy, DeleteTrail, DeleteLogGroup, DeleteAlarms, DeleteFileSystem, DeleteBackupVault, DeleteRecoveryPoint, DeleteHostedZone, DeleteDistribution, DeleteStream, DeleteTopic, DeleteQueue, DeleteSecret, ScheduleKeyDeletion, DeleteDomain, DeleteElasticsearchDomain, DeleteCacheCluster, DeleteReplicationGroup, DeleteWorkspaces, DeleteEnvironment, DeleteApplication, DeleteDeployment`.
Also skip records where `read_only == Some(true)`. Threshold and window are
unchanged. Tests: 11 `DeleteObject` in 5 min does not fire; 11 `TerminateInstances`
does.

### P2.11 GEO-01 unknown identities
Skip records whose identity resolves to neither an ARN nor a `user_name` (do not
bucket them as `"unknown"`). The alert `query` is currently `eventName=ConsoleLogin`,
which is wrong because the rule covers every API call; set it to the empty string
so "View evidence" shows the full event set, and put the affected identities in
`metadata["identities"]` joined by `;`. Test: two ARN-less records from two
countries do not fire; one ARN from two countries does.

### P2.12 Update RULES.md for the rewritten rules
For each rule touched in P2.1 to P2.11, update its `####` section's detection
logic paragraph in `RULES.md` to describe the new condition in one or two
sentences. Do not touch other rules.

---

## 4. Phase 3: Input validation and silent wrong results

### P3.1 Unknown query field is an error
`crates/core/src/query/parser.rs::parse_filter_token`: return
`Err(CoreError::Query(format!("Unknown field '{field_str}'. Known fields: eventName, eventSource, awsRegion, sourceIPAddress, userArn, userName, accountId, errorCode, identityType, userAgent, bucketName")))`
instead of `Ok(None)` when `FieldName::from_str` fails. Make `from_str` accept
field names case-insensitively (ASCII) so `eventname` still works. Update the
existing `test_unknown_field_skipped` test to assert the error, and add
`test_field_case_insensitive`. Check `ui/src/App.tsx::fetchPage` already surfaces
a search error (it only `console.error`s). Add a `queryError: string | null` state
in App, set it from the rejected promise, and render it as a one-line red bar
under the QueryBar (reuse the existing warning banner styling). Clear it on the
next successful search.

### P3.2 Unparseable eventTime
`crates/core/src/ingest/parser.rs`: try `parse_from_rfc3339`, then
`NaiveDateTime::parse_from_str` with `"%Y-%m-%d %H:%M:%S"` and `"%Y-%m-%dT%H:%M:%S"`
treated as UTC. If all fail, **drop the record** and count it. `parse_records`
returns `Result<(Vec<IndexedRecord>, usize /*dropped*/), CoreError>`; the store
consumer adds one `IngestWarning { message: "<n> record(s) with unparseable eventTime skipped", file: Some(path) }`
per file with `n > 0`. Update the three callers (`store.rs`, `fetch/mod.rs::summarize_staged`,
any test). Remove the `timestamp == 0` special case in `summarize_staged`.
Tests: a record with `"2024-01-15 10:00:00"` parses; a record with `"garbage"` is
dropped and counted.

### P3.3 Relative time overflow and `!=` tokenizing
`parser.rs::parse_time_value`: use `checked_mul` / `checked_sub`, returning
`CoreError::Query("relative time out of range")`. `parse_filter_token`: only treat
`!=` as the operator when it appears **before** the first `=`
(`token.find("!=") == token.find('=').map(|p| p.saturating_sub(1))` style check;
write it clearly). Tests: `earliest=-99999999999999w` errors; `userAgent=*a!=b*`
parses as a non-negated Contains filter.

### P3.4 Deterministic sort within a second
Everywhere `sort_unstable_by_key(|(ts, _)| *ts)` appears on `(i64, u32)` pairs
(`store.rs` time index, `query/engine.rs::reorder_to_time`, `stats.rs`,
`session.rs`, rule window loops), sort by the tuple `(ts, id)` instead. One grep,
one commit. No new tests; the existing ones must stay green.

### P3.5 Per-record parse fallback
`parser.rs`: deserialize `{"Records": [...]}` to a struct whose `records` is
`Vec<Box<RawValue>>`, then parse each element to `CloudTrailRecord`. A failing
element is skipped and counted into the same `dropped` counter from P3.2 (extend
the warning message: `"<n> record(s) skipped: <m> unparseable eventTime, <k> malformed"`).
Keep the lookup-events fallback path as is. Test: a file with one good and one
bad record yields one record and a warning.

### P3.6 Online geo lookup: HTTPS and partial results
`crates/app/src/commands/geoip.rs::geo_lookup_online`: ip-api's free tier does not
serve HTTPS, so keep the host but return partial results. Change the return type
to a struct `{ results: Vec<OnlineGeoResult>, error: Option<String> }`; on a
non-2xx or transport error, stop and return what was collected plus the message.
Honour the `X-Rl` / `X-Ttl` headers: if `X-Rl` is `0`, stop with the message
`"ip-api.com rate limit reached; retry in <X-Ttl>s"`. Update `ui/src/lib/tauri.ts`
and the caller in `IpView.tsx` to display `error` as a non-blocking notice.
Add a one-line note in `README.md` under the GeoIP section that the online lookup
sends IPs in cleartext to ip-api.com and should not be used for sensitive cases.

### P3.7 IPv6 private ranges
`crates/core/src/geoip.rs` private-IP check: add `fe80::/10`, `fc00::/7`,
`::1`, `::`, and IPv4-mapped (`to_ipv4_mapped()` then apply the v4 check).
Return `None` from `lookup` when **both** the country and ASN lookups yield
nothing. Tests for each range.

### P3.8 Profile picker sections
`crates/core/src/fetch/profiles.rs`: skip sections whose name starts with
`sso-session ` or `services `. Test with a config containing both.

---

## 5. Phase 4: UI state and consistency

Files under `ui/src/`. Run `npx tsc --noEmit -p tsconfig.app.json` and
`npx eslint src` after each task; eslint must not gain new errors.

### P4.1 Lift facet filter state to App
Move `filters: Record<string, ActiveFilter | null>` out of `FilterPanel` into `App`
(`App.tsx` next to `filterFragment`). `FilterPanel` receives `filters` and
`onFiltersChange(next)` as props; `App` derives `filterFragment` from `filters`
with the existing `buildFragment` logic (move `buildFragment` into a new
`ui/src/lib/query.ts`). Delete `filterFragment` state; make it a `useMemo`.
Export `ActiveFilter` from `ui/src/types/cloudtrail.ts`. Acceptance: tick a facet,
switch to Stats tab, come back, facet still shows ticked and Clear is visible.

### P4.2 Draft query stays local until submit
`QueryBar`: remove the `onChange` prop entirely. The input edits `localValue`
only; `onSubmit` fires on Enter and on Clear/Escape. `App`: delete `setQueryText`
calls that were driven by typing; `queryText` changes only in `handleQuerySubmit`,
`handleFilterSelect`, `handleViewEvidence`. Acceptance: typing does not trigger
facet reloads or change the export query.

### P4.3 Apply the restored query on load
In `handleLoaded`, call `runQuery(queryText, filterFragment, globalTimeRange)`
instead of `fetchPage(0, ""); fetchTimeline("")`. Add `queryText`,
`filterFragment`, `globalTimeRange` to its dependency array.

### P4.4 No side effects in setState updaters
`App.tsx::handleFilterSelect` and `FilterPanel` toggle handlers: compute `next`
from current state first (read the value from the state variable, which is in the
closure), call `runQuery`/`onFiltersChange`, then `setState(next)`. Confirm with a
grep that no `set*((prev) => { ...runQuery...` remains.

### P4.5 One timestamp formatter
Create `ui/src/lib/time.ts` exporting `formatTs(ms: number | string, opts?: { seconds?: boolean; suffix?: boolean }): string`
that renders **UTC** as `YYYY-MM-DD HH:MM[:SS]` with a trailing ` UTC` only when
`opts.suffix` is true, and `parseLocalInputAsUtc(value: string): number` for
`datetime-local` inputs. Replace every ad-hoc formatter listed below with it:
`EventTable.tsx:39`, `SessionView.tsx:18`, `SessionDetail.tsx:22`,
`AlertDetail.tsx` (the local `fmt`), `IdentityTimeline.tsx:335`,
`TimelineChart.tsx:18-36` (axis labels keep the short forms but in UTC),
`GlobalTimeBar.tsx:17,24,136,138`, `AwsFetchPanel.tsx:37,42`.
Add a `UTC` label to the StatusBar right side so the convention is visible.
Do **not** add a local/UTC toggle (deferred).

### P4.6 Request guards on every async view
Add the same monotonic-ref pattern `App.fetchPage` uses to: `EventDetail`
(record + ip lookups), `FieldStats` (one ref per field or one shared ref keyed
by query), `FilterPanel` section loads, `AlertDetail`, `SessionDetail`,
`SessionView`, `IpView`, `IdentityTimeline`. Write one tiny hook
`ui/src/lib/useLatest.ts`:

```ts
export function useLatestRequest() {
  const ref = useRef(0);
  return () => { const id = ++ref.current; return () => id === ref.current; };
}
```

Usage: `const begin = useLatestRequest(); ... const isCurrent = begin(); const r = await invoke(); if (!isCurrent()) return;`.
Acceptance: `grep -rn "useLatestRequest" ui/src | wc -l` ≥ 9.

### P4.7 Dependencies and dead files
Remove from `ui/package.json`: `lucide-react`, `@tanstack/react-table`, `react-is`,
`jimp`. Delete `ui/src/index.css` and `ui/src/App.css` after confirming with grep
that nothing imports them. Resolve the Vite / `@tailwindcss/vite` peer conflict by
moving to the versions that satisfy each other (pick the newest `@tailwindcss/vite`
that lists the installed Vite major as a peer; if none exists, pin Vite to the
major it supports). `npm ci` must then succeed without `--legacy-peer-deps`.
Regenerate `package-lock.json` with the repo's npm, never by hand.

### P4.8 TypeScript types match serde
`ui/src/types/cloudtrail.ts`: change every optional field that is an `Option<T>`
on the Rust side to `T | null` (keep `?` only where the Rust side uses
`skip_serializing_if`). Fix the `complete` variant of `IngestProgressEvent`: the
Rust enum uses `rename_all = "camelCase"` on **variants**, so struct-variant
fields keep snake_case. Either add `#[serde(rename_all = "camelCase")]` on the
`Complete` variant in `crates/app/src/commands/ingest.rs` (preferred; do that and
leave TS as `recordsTotal`) or change TS. Also add the missing `CloudTrailRecord`
fields (`requestId`, `eventType`, `managementEvent`, `recipientAccountId`,
`eventCategory`, `sharedEventId`, `sessionCredentialFromConsole`, `resources`,
`additionalEventData`) as `T | null`. `tsc` must pass; fix call sites with `??`.

### P4.9 Unhandled rejections and keys
`DropZone.tsx` and `IpView.tsx`: move `await open(...)` inside the `try`.
`AlertPanel.tsx` list key: use `${alert.ruleId}-${index}` and compare selection by
`ruleId` **and** `title`. `EventTable.tsx`: render `page 1 of 1` when `total === 0`
and clamp `page` to `max(0, totalPages - 1)` when `results.total` shrinks.

---

## 6. Phase 5: Fetch and ingest robustness

### P5.1 Per-object fetch errors are warnings
`crates/core/src/fetch/bucket.rs` download loop: on a `GetObject` error, push
`format!("{key}: {msg}")` to a `skipped: Vec<String>` and continue. Add
`pub skipped: Vec<String>` to `FetchOutcome`. `crates/app/src/commands/fetch.rs`:
only `remove_dir_all(dest)` when `files_written == 0`; surface `skipped` in the
Check summary (add a `skipped: number` and `skippedSample: string[]` (first 10) to
the summary struct and show a count in `AwsFetchPanel`). Same treatment for
`LookupEvents` pages in `lookup.rs`: a page error after at least one successful
page ends the fetch with what was written plus a warning.

### P5.2 Skip digest and insight objects
`bucket.rs::key_in_window`: return `false` when the key contains
`/CloudTrail-Digest/` or `/CloudTrail-Insight/`. Test both.

### P5.3 Bucket region
After building the client, call `head_bucket` and read the
`x-amz-bucket-region` header from the response (or the error's raw response on
301). If it differs from `req.region`, rebuild `sdk_config` with that region and
recreate the client. Report the discovered region in a `Listing` progress message.
Test offline with moto (`uvx --from 'moto[server]' moto_server -p 5055`) per the
CLAUDE.md note; if moto does not return the header, document that in §10 and keep
the code path.

### P5.4 Windows-safe key to path
Replace the `split('/')` filter with: split on `/`, reject the whole key (push to
`skipped`) if any segment contains `\` or `:` or equals `.`/`..` or is empty
after trimming. Test with `a/..\\b.json.gz` and `C:x/y.json.gz`.

### P5.5 Stream ZIP entries and cap decompression
`crates/core/src/ingest/decompress.rs`: change `read_zip_entries` into
`pub fn for_each_zip_entry(path, mut f: impl FnMut(Vec<u8>) -> ControlFlow<()>) -> Result<(), CoreError>`
so entries are inflated one at a time; the producer in `store.rs` sends each
batch inside the callback. Add `const MAX_DECOMPRESSED_BYTES: u64 = 2 * 1024 * 1024 * 1024`
and wrap both gzip paths and zip entry reads in `.take(MAX_DECOMPRESSED_BYTES + 1)`;
if the output hits the cap, return `CoreError::CorruptGzip` with a message that
says `exceeds 2 GiB decompressed`. Switch `GzDecoder` to `MultiGzDecoder` in both
places. Update `summarize_staged` to the callback API. Tests: multi-member gzip
reads both members; a zip with two entries sends two batches.

### P5.6 ZIP progress accounting
`store.rs` consumer: track `files_seen: HashSet<u32>` of `src_idx`; increment
`files_done` only when a `src_idx` is first seen. For the producer, after the
zip loop, send a sentinel `Ok((path_str, src_idx, Vec::new()))` so a zip with zero
matching entries still completes. Test: a zip with 3 entries reports
`files_done == 1`, `files_total == 1`.

### P5.7 Heavy work off the async runtime
`crates/app/src/commands/detection.rs::run_detections`,
`session.rs::get_session_alerts`, `export.rs::export_csv/export_json`: wrap the
synchronous body in `tokio::task::spawn_blocking`, acquiring the `RwLock` read
guards **inside** the blocking closure. `crates/app/src/lib.rs:22` currently does
`app.manage(AppState::new(...))`; change it to `app.manage(Arc::new(AppState::new(...)))`
and every command signature from `State<'_, AppState>` to `State<'_, Arc<AppState>>`
(one grep, mechanical). Inside a command, `let state = Arc::clone(&state);` then
move it into the closure. Verify nothing holds a guard across an `.await`.

### P5.8 Streaming exports
`crates/core/src/export.rs`: change both functions to
`pub fn export_csv_to<W: Write>(store, query, w: W) -> Result<usize, CoreError>`
and `export_json_to` writing one record at a time (JSON: write `[`, then
`serde_json::to_writer` per record with `,` separators, then `]`; not pretty).
Return the record count directly. The app command opens a `BufWriter<File>` and
passes it. Delete the newline-counting and the re-parse. Tests: CSV count equals
records; JSON output parses and has the right length.

### P5.9 CI covers the app crate and aws feature
`.github/workflows/ci.yml`: add steps `cargo test -p trail-inspector-core --features aws`
and `cargo check -p trail-inspector-app` (install the Linux Tauri deps the release
workflow already lists). Remove `anyhow` from `crates/app/Cargo.toml` (nothing uses it).
Set `app.security.csp` in `tauri.conf.json` to
`"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self' ipc: http://ipc.localhost"`
and run the app once (`cargo tauri dev`) to confirm no console CSP errors; if any
resource is blocked, widen only that directive and note it in §10. Remove
`fs:read-all` from `crates/app/capabilities/default.json` after confirming with
grep that `@tauri-apps/plugin-fs` is not imported in `ui/src`.

---

## 7. Phase 6: Performance

Measure before and after each task with the bench from P0.1 and record in §10.
If a task does not improve its target measurably, keep the code only if it is
simpler; otherwise revert that commit and note it.

### P6.1 Ingest consumer parses only S3 request parameters
`crates/core/src/store/store.rs` consumer loop: replace the `serde_json::Value`
parse with

```rust
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct S3Params<'a> { #[serde(borrow)] bucket_name: Option<&'a str>, #[serde(borrow)] key: Option<&'a str> }
```

parsed **only** when `rec.record.event_source.as_ref() == "s3.amazonaws.com"`.
Note the `bucketName` index then only covers S3 events; confirm by grep that no
rule or query relies on `bucketName` for other services (none should). Measure
ingest time on `samples/blizzardbreakdown` before/after if the samples directory
exists; otherwise generate a 500k-record synthetic directory with a small Rust
example under `crates/core/examples/` and **delete the example before committing**
(CLAUDE.md learning).

### P6.2 Bitmap custom-rule filters
`custom_rules.rs::apply_filter`: operate on `RoaringBitmap` throughout.
`Condition` → `candidates & idx[value]` (empty bitmap if absent); `And` → fold
`&`; `Or` → fold `|` of each sub-result then `& candidates`; `Not` →
`candidates - inner`. `evaluate_custom_rule` builds `candidates` with
`scoped_ids` from P1.2 (sources empty, `exclude_errors` false to preserve current
semantics; see §9 for the `success_only` feature). Convert to `Vec<u32>` only at
the end. Existing custom-rule tests must stay green.

### P6.3 Sliding windows without `Vec::contains`
In IM-01, IM-02, IA-04, CA-02, DI-03, EX-03 and `mass_ec2_op_inner`, collect
window members into a `RoaringBitmap` (or `HashSet<u32>`) and convert once.
Add `break` after the first qualifying window in IM-01 (matching IM-02). Add a
burst case to the bench: 20,000 `RunInstances` within 10 minutes from one
identity; the bench assertion stays `< 2s`.

### P6.4 Parallel rule evaluation
`run_all_rules`: `all_rules().par_iter().flat_map_iter(|r| (r.evaluate)(store)).collect()`.
`Store` is already `Sync` (it is shared behind `RwLock`); confirm `cargo check`.
Record the bench delta.

### P6.5 GeoIP lookup cache
`crates/core/src/geoip.rs::GeoIpEngine`: add
`cache: dashmap::DashMap<IpAddr, Option<IpInfo>>` (add `dashmap` to core
`Cargo.toml`) consulted by `lookup`. Clear it in `ingest_path_into_state`
(expose `pub fn clear_cache`). Switch the two `maxminddb::Reader::open_readfile`
calls in `geoip.rs` (lines ~71 and ~75) to `Reader::open_mmap` by enabling the
`mmap` feature on the existing `maxminddb = "0.24"` line in `crates/core/Cargo.toml`.
GEO-01/GEO-02 then need no change.

### P6.6 Cache detection results
`AppState`: add `alerts_cache: RwLock<Option<Vec<Alert>>>` holding the
**uncapped, unfiltered** result of built-in + geo + custom rules. `run_detections`
and `get_session_alerts` populate it on miss and run `finalize_alerts` on a clone.
Invalidate in `ingest_path_into_state`, on custom-rule reload, and on GeoIP load.
`DetectionView.tsx` then no longer needs its own guard; leave the UI alone.

### P6.7 Drop redundant interning and drain sessionContext
`crates/core/src/model.rs::CloudTrailRecord::intern`: stop interning
`event_time` and `error_message` (keep them `Arc<str>`; just do not pool them).
Add `session_context_ref: Option<BlobRef>` to `IndexedRecord`, drain
`user_identity.session_context` in `drain_blobs`, and restore it in
`get_full_record`. Update test constructors (`source_file: 0` sites) to include the
new field. Measure RSS on the sample directory if available.

---

## 8. Phase 7: Wrap-up

### P7.1 Changelog and learnings
Add an "Unreleased" section to `CHANGELOG.md` listing each task id with one line.
Add to `CLAUDE.md` "Applied Learning" only bullets that meet its rule (under 15
words, saves time next session). Candidates: "Rule fixtures must use the real
`eventSource`; `scoped_ids` filters on it." and "serde `rename_all` on an enum
does not rename struct-variant fields."

### P7.2 Final PR description
Replace the draft PR body with: summary, the §10 checklist, bench numbers
before/after, and the §9 deferred list.

---

## 9. Deferred (do not do in this plan)

Listed so the executor does not drift into them. These are candidates for a
follow-up plan.

- New detection rules (Bedrock, PutEventSelectors, GuardDuty UpdateDetector, role
  chaining, UpdateAssumeRolePolicy, S3 lifecycle/versioning, Organizations, SES,
  Lambda layers, snapshot share to specific account).
- Custom-rule DSL: `group_by`, `success_only`, `event_name` glob,
  `request_params` JSON pointer, `read_only`.
- Query parser: parentheses, `IN (...)`, new indexed fields (`accessKeyId`,
  `principalId`, `readOnly`, `eventType`, `recipientAccountId`, `resources`).
- Fetch: concurrency (`buffer_unordered`), day-prefix listing, resumable pull,
  cancel token, assume-role, multi-region LookupEvents, Lake/Athena, presets.
- Exports for alerts/sessions/IPs; JSONL.
- UI: UTC/local toggle, saved queries, pivot from EventDetail, timeline brush,
  light theme, virtualized IdentityTimeline, memoization of EventTable and
  friends, facet batch command, accessibility pass.
- `IndexedRecord` packing (BlobRef layout, UUID fields), query result cache,
  bitmap-based `top_field_values`, `parking_lot::RwLock`.
- Pin GitHub Actions by SHA; dedupe `reqwest`/TLS stacks.

---

## 10. Progress log (executor updates this)

Baseline (P0.1):
- Verification block: [x] green (needed `apt-get install libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev patchelf` for the app-crate check; core 161 tests, 169 with aws)
- Bench median (100k, release): 753 ms (717/754/761), 11 alerts
- Rule count: 68

Phase 1: [x] P1.1  [x] P1.2  [ ] P1.3  [x] P1.4  [ ] P1.5  [ ] P1.6
Phase 2: [ ] P2.1  [ ] P2.2  [ ] P2.3  [ ] P2.4  [ ] P2.5  [ ] P2.6  [ ] P2.7  [ ] P2.8  [ ] P2.9  [ ] P2.10  [ ] P2.11  [ ] P2.12
Phase 3: [ ] P3.1  [ ] P3.2  [ ] P3.3  [ ] P3.4  [ ] P3.5  [ ] P3.6  [ ] P3.7  [ ] P3.8
Phase 4: [ ] P4.1  [ ] P4.2  [ ] P4.3  [ ] P4.4  [ ] P4.5  [ ] P4.6  [ ] P4.7  [ ] P4.8  [ ] P4.9
Phase 5: [ ] P5.1  [ ] P5.2  [ ] P5.3  [ ] P5.4  [ ] P5.5  [ ] P5.6  [ ] P5.7  [ ] P5.8  [ ] P5.9
Phase 6: [ ] P6.1  [ ] P6.2  [ ] P6.3  [ ] P6.4  [ ] P6.5  [ ] P6.6  [ ] P6.7
Phase 7: [ ] P7.1  [ ] P7.2

Bench after Phase 6: ____ ms (burst case included)

Notes / blockers (task id, what, why):
- P1.2 deviation: IA-04 (failed-login brute force) uses `exclude_errors = false`, like DI-03, because failure is its subject.
- P1.2 correction: EC-06 events come from `ec2-instance-connect.amazonaws.com`, not `ec2.amazonaws.com`; the plan table was wrong.
- P1.2: evidence `query` strings gain `eventSource=` per OR clause (appending `AND` to an OR query would change its meaning in this parser). They do not exclude errored events, so evidence can show denied calls the rule skipped.
- P1.2: rule tests were sparse; added `event_name_only_rules_are_scoped_to_their_service` covering 27 (rule, event, source) cases.
