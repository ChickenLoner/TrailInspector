## TrailInspector v1.5.0 — Import from Live AWS

Pull CloudTrail logs straight from an AWS account without leaving the app. No AWS CLI required.

### What's New

**Import from Live AWS**
- **Two sources** — `cloudtrail:LookupEvents` (last 90 days, needs no S3 access) or the trail's S3 bucket (full history, full fidelity)
- **Credentials your way** — type an access key, secret, and optional session token directly, or pick a named profile from `~/.aws`
- **Check before you pull** — Check downloads and counts everything first, reporting the exact event count, time range, trails, and bucket; nothing replaces your loaded dataset until you press Pull. Pull reuses the staged download, so the ~2 req/s LookupEvents rate limit is never paid twice
- **Explicit bucket override** — name the bucket to skip `DescribeTrails`, for roles that can read a bucket but not enumerate trails
- **Endpoint URL override** — the `aws --endpoint-url` equivalent for LocalStack, moto, and emulated AWS; S3 switches to path-style addressing automatically

**Ingest**
- **`aws cloudtrail lookup-events` exports load natively** — the `{"Events":[{"CloudTrailEvent":"…"}]}` shape no longer needs manual conversion
- **Single-file import** — "Open Single File" alongside the folder picker; an explicitly chosen file bypasses the extension filter

### Fixed

- **Gzip is detected by magic bytes, not filename.** Files such as `audit.log.gz` were invisible to the directory walker, and if reached at all were handed to the parser as raw compressed bytes. A bucket using that naming loaded as zero records with no warning. Affects the existing file-import path, not just live import
- **Fully-qualified `X-Amz-Target`** — the CloudTrail target header is now sent in the `com.amazonaws.*` form the AWS CLI uses. Real AWS accepts both, but some emulators only register that form and reject the short one
- **DB-IP Lite download URL** — `db-ip.com/db/lite` 404s; corrected to `lite.php`

### Credential handling

Typed keys are held in memory for the session only — never written to disk, never to browser storage, and never to `~/.aws`, so an existing AWS CLI setup is left untouched. "Clear cache" wipes them along with any staged download. Only the region, endpoint, and profile *name* persist between launches.

### Note on download size

Installers roughly double (Windows `.exe` 3.56 → 6.77 MB, `.deb` 5.39 → 12.09 MB) — the cost of bundling the AWS SDK and its TLS stack. The `.AppImage` grows only ~7%.

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
