import { useEffect, useState } from "react";
import {
  listAwsProfiles,
  listS3Buckets,
  checkAws,
  clearAwsCache,
  hasCachedAwsCredentials,
  type CheckAwsArgs,
} from "../../lib/tauri";
import type { AwsCredentialsInput } from "../../types/cloudtrail";
import type {
  FetchSource,
  FetchSummary,
  IngestProgressEvent,
  ProfileInfo,
} from "../../types/cloudtrail";
import { fmtLocalOrDash as fmt } from "../../lib/format";

const REGIONS = [
  "us-east-1", "us-east-2", "us-west-1", "us-west-2",
  "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
  "ap-south-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
  "ap-northeast-2", "ca-central-1", "sa-east-1",
];

// Only non-secret preferences are remembered. Access key, secret, and session
// token are never written here — they live in backend memory for the session.
const LS_REGION = "trailinspector_aws_region";
const LS_ENDPOINT = "trailinspector_aws_endpoint";
const LS_PROFILE = "trailinspector_aws_profile";
const LS_MODE = "trailinspector_aws_mode";
const LS_BUCKET = "trailinspector_aws_bucket";

type CredMode = "profile" | "manual";

function fromLocalInput(s: string): number | undefined {
  if (!s) return undefined;
  const ms = new Date(s).getTime();
  return Number.isNaN(ms) ? undefined : ms;
}

interface Props {
  /** True while a check or pull is in flight. */
  busy: boolean;
  onCheckStart: () => void;
  onCheckEnd: () => void;
  onProgress: (e: IngestProgressEvent) => void;
  onPull: () => void;
}

/**
 * Import from a live AWS environment.
 *
 * Two credential modes: a named profile from `~/.aws`, or keys typed straight in
 * (for a CTF or a handed-over key pair, where there is no profile to point at).
 *
 * This panel never writes to `~/.aws` — day-to-day CLI config is untouched. Typed
 * keys go to the backend, which holds them in memory for the session only.
 *
 * Flow is check-then-pull: Check downloads and counts everything so you see the
 * exact event count and time range before anything replaces the loaded dataset.
 */
export function AwsFetchPanel({ busy, onCheckStart, onCheckEnd, onProgress, onPull }: Props) {
  const [profiles, setProfiles] = useState<ProfileInfo[]>([]);
  const [mode, setMode] = useState<CredMode>(
    () => (localStorage.getItem(LS_MODE) as CredMode | null) ?? "manual",
  );
  const [profile, setProfile] = useState(() => localStorage.getItem(LS_PROFILE) ?? "");
  const [region, setRegion] = useState(() => localStorage.getItem(LS_REGION) ?? "us-east-1");
  const [endpoint, setEndpoint] = useState(() => localStorage.getItem(LS_ENDPOINT) ?? "");
  const [source, setSource] = useState<FetchSource>("lookupEvents");

  const [accessKeyId, setAccessKeyId] = useState("");
  const [secretAccessKey, setSecretAccessKey] = useState("");
  const [sessionToken, setSessionToken] = useState("");
  const [cached, setCached] = useState(false);

  // No default window: an unset range means "everything available".
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");

  // S3 source only. An explicit bucket skips DescribeTrails, which needs a
  // permission the S3 read path doesn't — and which emulated AWS often lacks.
  const [bucket, setBucket] = useState(() => localStorage.getItem(LS_BUCKET) ?? "");
  const [prefix, setPrefix] = useState("");
  const [buckets, setBuckets] = useState<string[]>([]);
  const [listingBuckets, setListingBuckets] = useState(false);

  const [summary, setSummary] = useState<FetchSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listAwsProfiles().then(setProfiles).catch(() => setProfiles([]));
    hasCachedAwsCredentials().then(setCached).catch(() => setCached(false));
  }, []);

  // Adopt the profile's own region when it has one.
  useEffect(() => {
    if (mode !== "profile") return;
    const r = profiles.find((p) => p.name === profile)?.region;
    if (r) setRegion(r);
  }, [profile, profiles, mode]);

  /**
   * Resolve which identity to send. Returns null and sets an error when the form
   * can't produce one. Blank key fields with credentials already cached is valid —
   * the backend reuses what it holds.
   */
  const credArgs = (): { profile?: string; credentials?: AwsCredentialsInput } | null => {
    if (mode === "profile") {
      if (!profile) {
        setError("No profile selected. Run `aws configure --profile <name>` first.");
        return null;
      }
      return { profile };
    }
    if (accessKeyId.trim() && secretAccessKey.trim()) {
      return {
        credentials: {
          accessKeyId: accessKeyId.trim(),
          secretAccessKey: secretAccessKey.trim(),
          sessionToken: sessionToken.trim() || undefined,
        },
      };
    }
    if (cached) return {};
    setError("Enter an access key and secret, or switch to a named profile.");
    return null;
  };

  const runListBuckets = async () => {
    setError(null);
    const creds = credArgs();
    if (!creds) return;

    setListingBuckets(true);
    try {
      const found = await listS3Buckets({
        ...creds,
        region,
        endpointUrl: endpoint.trim() || undefined,
      });
      setBuckets(found);
      if (found.length === 1 && !bucket) setBucket(found[0]);
      if (found.length === 0) setError("No buckets visible to these credentials.");
    } catch (e) {
      setError(String(e));
    } finally {
      setListingBuckets(false);
    }
  };

  const runCheck = async () => {
    setError(null);
    setSummary(null);

    const startMs = fromLocalInput(start);
    const endMs = fromLocalInput(end);
    if (startMs != null && endMs != null && startMs >= endMs) {
      setError("Start time must be before end time.");
      return;
    }

    const creds = credArgs();
    if (!creds) return;

    const args: CheckAwsArgs = {
      ...creds,
      region,
      source,
      startMs,
      endMs,
      endpointUrl: endpoint.trim() || undefined,
      bucket: source === "trailBucket" ? bucket.trim() || undefined : undefined,
      prefix: source === "trailBucket" ? prefix.trim() || undefined : undefined,
    };

    localStorage.setItem(LS_REGION, region);
    localStorage.setItem(LS_ENDPOINT, endpoint);
    localStorage.setItem(LS_PROFILE, profile);
    localStorage.setItem(LS_MODE, mode);
    localStorage.setItem(LS_BUCKET, bucket);

    onCheckStart();
    try {
      const s = await checkAws(args, onProgress);
      setSummary(s);
      setCached(await hasCachedAwsCredentials());
      // Clear the secret from component state once the backend has it — no reason
      // for it to sit in the DOM afterwards.
      setSecretAccessKey("");
      setSessionToken("");
    } catch (e) {
      setError(String(e));
    } finally {
      onCheckEnd();
    }
  };

  const runClear = async () => {
    setError(null);
    try {
      await clearAwsCache();
      setSummary(null);
      setCached(false);
      setAccessKeyId("");
      setSecretAccessKey("");
      setSessionToken("");
    } catch (e) {
      setError(String(e));
    }
  };

  const labelStyle: React.CSSProperties = {
    fontSize: 11, fontWeight: 600, color: "var(--text-secondary)", width: 84, flexShrink: 0,
  };
  const inputStyle: React.CSSProperties = {
    flex: 1, fontSize: 11, padding: "3px 6px", borderRadius: 3,
    background: "var(--bg-tertiary)", border: "1px solid var(--border)",
    color: "var(--text-primary)", outline: "none", minWidth: 0,
  };
  const row: React.CSSProperties = { display: "flex", alignItems: "center", gap: 8 };

  return (
    <div
      style={{
        background: "var(--bg-secondary)",
        border: "1px solid var(--border)",
        borderRadius: 6,
        padding: "12px 16px",
        width: 480,
        maxWidth: "90vw",
        display: "flex",
        flexDirection: "column",
        gap: 8,
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontSize: 12, fontWeight: 700, color: "var(--text-primary)" }}>
          Import from live environment
        </span>
        {cached && (
          <span style={{ fontSize: 10, color: "var(--accent-green)" }}>credentials cached</span>
        )}
      </div>

      <div style={row}>
        <span style={labelStyle}>Credentials</span>
        <select
          style={inputStyle}
          value={mode}
          onChange={(e) => setMode(e.target.value as CredMode)}
          disabled={busy}
        >
          <option value="manual">Enter keys directly</option>
          <option value="profile">Named profile from ~/.aws</option>
        </select>
      </div>

      {mode === "profile" ? (
        <div style={row}>
          <span style={labelStyle}>Profile</span>
          <select
            style={inputStyle}
            value={profile}
            onChange={(e) => setProfile(e.target.value)}
            disabled={busy}
          >
            <option value="">{profiles.length ? "Select…" : "No profiles found"}</option>
            {profiles.map((p) => (
              <option key={p.name} value={p.name}>{p.name}</option>
            ))}
          </select>
        </div>
      ) : (
        <>
          <div style={row}>
            <span style={labelStyle}>Access key</span>
            <input
              style={inputStyle}
              value={accessKeyId}
              onChange={(e) => setAccessKeyId(e.target.value)}
              placeholder={cached ? "using cached credentials" : "AKIA… / ASIA…"}
              disabled={busy}
              autoComplete="off"
              spellCheck={false}
            />
          </div>
          <div style={row}>
            <span style={labelStyle}>Secret key</span>
            <input
              type="password"
              style={inputStyle}
              value={secretAccessKey}
              onChange={(e) => setSecretAccessKey(e.target.value)}
              placeholder={cached ? "using cached credentials" : ""}
              disabled={busy}
              autoComplete="off"
            />
          </div>
          <div style={row}>
            <span style={labelStyle}>Session token</span>
            <input
              type="password"
              style={inputStyle}
              value={sessionToken}
              onChange={(e) => setSessionToken(e.target.value)}
              placeholder="required for ASIA… temporary keys"
              disabled={busy}
              autoComplete="off"
            />
          </div>
        </>
      )}

      <div style={row}>
        <span style={labelStyle}>AWS URL</span>
        <input
          style={inputStyle}
          value={endpoint}
          onChange={(e) => setEndpoint(e.target.value)}
          placeholder="optional — LocalStack / emulated AWS"
          disabled={busy}
          spellCheck={false}
        />
      </div>

      <div style={row}>
        <span style={labelStyle}>Region</span>
        <select
          style={inputStyle}
          value={region}
          onChange={(e) => setRegion(e.target.value)}
          disabled={busy}
        >
          {!REGIONS.includes(region) && <option value={region}>{region}</option>}
          {REGIONS.map((r) => <option key={r} value={r}>{r}</option>)}
        </select>
      </div>

      <div style={row}>
        <span style={labelStyle}>Source</span>
        <select
          style={inputStyle}
          value={source}
          onChange={(e) => setSource(e.target.value as FetchSource)}
          disabled={busy}
        >
          <option value="lookupEvents">LookupEvents API (90 days, no S3 access)</option>
          <option value="trailBucket">S3 trail bucket (full history)</option>
        </select>
      </div>

      {source === "trailBucket" && (
        <>
          <div style={row}>
            <span style={labelStyle}>Bucket</span>
            <input
              style={inputStyle}
              value={bucket}
              onChange={(e) => setBucket(e.target.value)}
              placeholder="blank = discover via DescribeTrails"
              disabled={busy}
              list="ti-bucket-list"
              spellCheck={false}
            />
            <datalist id="ti-bucket-list">
              {buckets.map((b) => <option key={b} value={b} />)}
            </datalist>
            <button
              onClick={runListBuckets}
              disabled={busy || listingBuckets}
              style={{
                fontSize: 11, padding: "3px 8px", borderRadius: 3,
                background: "var(--bg-tertiary)", border: "1px solid var(--border)",
                color: "var(--text-primary)",
                cursor: busy || listingBuckets ? "not-allowed" : "pointer",
                whiteSpace: "nowrap",
              }}
            >
              {listingBuckets ? "…" : "List"}
            </button>
          </div>
          <div style={row}>
            <span style={labelStyle}>Prefix</span>
            <input
              style={inputStyle}
              value={prefix}
              onChange={(e) => setPrefix(e.target.value)}
              placeholder="optional — e.g. AWSLogs/"
              disabled={busy}
              spellCheck={false}
            />
          </div>
        </>
      )}

      <div style={row}>
        <span style={labelStyle}>From</span>
        <input
          type="datetime-local"
          style={inputStyle}
          value={start}
          onChange={(e) => setStart(e.target.value)}
          disabled={busy}
        />
      </div>
      <div style={row}>
        <span style={labelStyle}>To</span>
        <input
          type="datetime-local"
          style={inputStyle}
          value={end}
          onChange={(e) => setEnd(e.target.value)}
          disabled={busy}
        />
      </div>

      <div
        style={{
          fontSize: 10, color: "var(--text-secondary)", background: "var(--bg-tertiary)",
          border: "1px solid var(--border)", borderRadius: 4, padding: "6px 8px", lineHeight: 1.5,
        }}
      >
        Leave both times empty to take everything available. Keys are held in memory
        for this session only — never written to disk and never to <code>~/.aws</code>,
        so your CLI setup is untouched. Check downloads and counts everything before
        anything is loaded; LookupEvents is rate limited (~2 req/s).
      </div>

      {error && (
        <div
          style={{
            background: "rgba(248,81,73,0.1)", border: "1px solid rgba(248,81,73,0.3)",
            color: "#f85149", fontSize: 11, borderRadius: 4, padding: "6px 8px",
            wordBreak: "break-word",
          }}
        >
          {error}
        </div>
      )}

      {summary && (
        <div
          style={{
            background: "var(--bg-tertiary)", border: "1px solid var(--accent-green)",
            borderRadius: 4, padding: "8px 10px", fontSize: 11, lineHeight: 1.7,
          }}
        >
          <div style={{ fontWeight: 700, color: "var(--text-primary)", marginBottom: 2 }}>
            Check result
          </div>
          <div><span style={{ color: "var(--text-secondary)" }}>Events</span>{" "}
            <span style={{ color: "var(--text-primary)" }}>{summary.events.toLocaleString()}</span>
            {" "}<span style={{ color: "var(--text-secondary)" }}>in {summary.files} file(s)</span>
          </div>
          <div><span style={{ color: "var(--text-secondary)" }}>Range</span>{" "}
            {fmt(summary.earliestMs)} → {fmt(summary.latestMs)}
          </div>
          {summary.bucket && (
            <div><span style={{ color: "var(--text-secondary)" }}>Bucket</span> s3://{summary.bucket}</div>
          )}
          {summary.trails.length > 0 && (
            <div><span style={{ color: "var(--text-secondary)" }}>Trails</span> {summary.trails.join(", ")}</div>
          )}
          {summary.events === 0 && (
            <div style={{ color: "var(--accent-yellow)" }}>
              Nothing matched — widen the window or check the region.
            </div>
          )}
        </div>
      )}

      <div style={{ display: "flex", gap: 8 }}>
        <button
          onClick={runCheck}
          disabled={busy}
          style={{
            flex: 1, fontSize: 12, fontWeight: 600, padding: "6px 0", borderRadius: 4,
            border: "1px solid transparent",
            background: busy ? "var(--bg-tertiary)" : "var(--accent-blue)",
            color: busy ? "var(--text-secondary)" : "#0d1117",
            cursor: busy ? "not-allowed" : "pointer",
          }}
        >
          {busy ? "Working…" : summary ? "Re-check" : "Check"}
        </button>

        <button
          onClick={onPull}
          disabled={busy || !summary || summary.events === 0}
          style={{
            flex: 1, fontSize: 12, fontWeight: 600, padding: "6px 0", borderRadius: 4,
            border: "1px solid transparent",
            background: !busy && summary && summary.events > 0 ? "var(--accent-green)" : "var(--bg-tertiary)",
            color: !busy && summary && summary.events > 0 ? "#ffffff" : "var(--text-secondary)",
            cursor: !busy && summary && summary.events > 0 ? "pointer" : "not-allowed",
          }}
        >
          Pull
        </button>

        <button
          onClick={runClear}
          disabled={busy}
          style={{
            fontSize: 12, fontWeight: 600, padding: "6px 10px", borderRadius: 4,
            background: "var(--bg-tertiary)", border: "1px solid var(--border)",
            color: busy ? "var(--text-secondary)" : "var(--text-primary)",
            cursor: busy ? "not-allowed" : "pointer",
            whiteSpace: "nowrap",
          }}
        >
          Clear cache
        </button>
      </div>
    </div>
  );
}
