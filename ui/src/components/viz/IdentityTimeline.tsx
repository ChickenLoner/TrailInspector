import { useState, useCallback, useEffect } from "react";
import { getIdentitySummary } from "../../lib/tauri";
import type { IdentitySummary, TimelineEvent } from "../../types/cloudtrail";

function formatTs(ms: number): string {
  return new Date(ms).toLocaleString([], {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

function durLabel(ms: number): string {
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h`;
  return `${Math.round(h / 24)}d`;
}

/** Format a ms timestamp to a datetime-local input value string (local time). */
function msToDatetimeLocal(ms: number): string {
  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, "0");
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
    `T${pad(d.getHours())}:${pad(d.getMinutes())}`
  );
}

/** Extract meaningful resource label(s) from requestParameters.
 *  For events with two key parameters (e.g. AttachUserPolicy), shows both joined by →.
 */
function extractDetail(ev: TimelineEvent): string {
  const p = ev.requestParameters;
  if (!p) return "";

  // S3: always bucket[/key]
  const bucket = p["bucketName"] as string | undefined;
  const key = (p["key"] ?? p["prefix"] ?? p["object"]) as string | undefined;
  if (bucket) return key ? `${bucket}/${key}` : bucket;

  // IAM / STS — collect subject and target separately so we can combine them
  const userName = (p["userName"] ?? p["newUserName"]) as string | undefined;
  const roleName = (p["roleName"] ?? p["roleArn"]) as string | undefined;
  const policyName = (p["policyName"] ?? p["policyArn"]) as string | undefined;
  const groupName = p["groupName"] as string | undefined;
  const roleSessionName = p["roleSessionName"] as string | undefined;

  // Two-part combos: Attach/DetachUserPolicy, PutUserPolicy, AddUserToGroup, etc.
  if (userName && policyName) return `${userName} → ${policyName}`;
  if (userName && groupName)  return `${userName} → ${groupName}`;
  if (roleName && policyName) return `${roleName} → ${policyName}`;
  if (groupName && policyName) return `${groupName} → ${policyName}`;
  // AssumeRole / AssumeRoleWithSAML / AssumeRoleWithWebIdentity
  if (roleName && roleSessionName) return `${roleName} (${roleSessionName})`;

  // Single IAM values
  if (userName) return userName;
  if (roleName) return roleName;
  if (policyName) return policyName;
  if (groupName) return groupName;

  // EC2
  const instanceId = p["instanceId"] as string | undefined;
  const amiId = p["imageId"] as string | undefined;
  const sgId = p["groupId"] as string | undefined;
  if (instanceId) return instanceId;
  if (amiId) return amiId;
  if (sgId) return sgId;

  // Lambda / ECS / ECR
  const fnName = (p["functionName"] ?? p["clusterName"] ?? p["repositoryName"]) as string | undefined;
  if (fnName) return fnName;

  // Secrets Manager / SSM / KMS
  const secretId = (p["secretId"] ?? p["keyId"] ?? p["name"] ?? p["parameterName"]) as string | undefined;
  if (secretId) return secretId;

  // CloudTrail / Config / other: resourceName or targetId
  const resourceName = (p["resourceName"] ?? p["targetId"] ?? p["resourceId"]) as string | undefined;
  if (resourceName) return resourceName;

  // Fallback: first short string value
  for (const v of Object.values(p)) {
    if (typeof v === "string" && v.length > 0 && v.length < 120) return v;
  }
  return "";
}

function EventRow({ ev }: { ev: TimelineEvent }) {
  const hasError = !!ev.errorCode;
  const detail = extractDetail(ev);
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "152px 180px minmax(100px, 1fr) 80px 110px 140px",
        gap: 0,
        borderBottom: "1px solid var(--border)",
        fontSize: 12,
        fontFamily: "monospace",
        minHeight: 28,
        alignItems: "center",
      }}
    >
      <span style={{ padding: "0 8px", color: "var(--text-secondary)", whiteSpace: "nowrap", fontSize: 11 }}>
        {formatTs(ev.timestampMs)}
      </span>
      <span
        style={{
          padding: "0 8px",
          color: hasError ? "var(--accent-red, #f85149)" : "var(--text-primary)",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
        title={ev.eventName}
      >
        {ev.eventName}
      </span>
      <span
        style={{
          padding: "0 8px",
          color: "var(--text-secondary)",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          fontSize: 11,
        }}
        title={detail}
      >
        {detail || "—"}
      </span>
      <span style={{ padding: "0 8px", color: "var(--text-secondary)", whiteSpace: "nowrap", fontSize: 11 }}>
        {ev.awsRegion}
      </span>
      <span
        style={{
          padding: "0 8px",
          color: "var(--text-secondary)",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          fontSize: 11,
        }}
        title={ev.sourceIp}
      >
        {ev.sourceIp ?? "—"}
      </span>
      <span
        style={{
          padding: "0 8px",
          color: hasError ? "var(--accent-red, #f85149)" : "var(--text-secondary)",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          fontSize: 11,
        }}
        title={ev.errorCode}
      >
        {ev.errorCode ?? ""}
      </span>
    </div>
  );
}

const TIME_PRESETS = [
  { label: "All", value: "" },
  { label: "1h", value: "1h" },
  { label: "6h", value: "6h" },
  { label: "24h", value: "24h" },
  { label: "7d", value: "7d" },
];

const PRESET_DURATIONS_MS: Record<string, number> = {
  "1h": 60 * 60 * 1000,
  "6h": 6 * 60 * 60 * 1000,
  "24h": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
};

interface Props {
  initialValue?: string;
}

export function IdentityTimeline({ initialValue }: Props) {
  const [input, setInput] = useState(initialValue ?? "");
  const [summary, setSummary] = useState<IdentitySummary | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState(0);

  // Time filter state
  const [timePreset, setTimePreset] = useState("");
  const [customFrom, setCustomFrom] = useState("");
  const [customTo, setCustomTo] = useState("");
  const [earliestMs, setEarliestMs] = useState<number | undefined>();
  const [latestMs, setLatestMs] = useState<number | undefined>();

  const lookup = useCallback(async (
    target: string,
    page: number = 0,
    eMs?: number,
    lMs?: number,
  ) => {
    const t = target.trim();
    if (!t) return;
    setLoading(true);
    setError(null);
    if (page === 0) setSummary(null);
    try {
      const result = await getIdentitySummary(t, page, undefined, eMs, lMs);
      setSummary(result);
      setCurrentPage(page);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (initialValue) {
      setInput(initialValue);
      lookup(initialValue);
    }
  }, [initialValue]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleTimePreset = useCallback((preset: string) => {
    setTimePreset(preset);
    setCustomFrom("");
    setCustomTo("");
    let eMs: number | undefined;
    let lMs: number | undefined;
    if (preset) {
      // Use identity's lastSeenMs as base if available, otherwise Date.now()
      const base = summary?.lastSeenMs ?? Date.now();
      const dur = PRESET_DURATIONS_MS[preset] ?? 0;
      eMs = base - dur;
      lMs = base;
    }
    setEarliestMs(eMs);
    setLatestMs(lMs);
    const target = summary?.arn ?? input.trim();
    if (target) lookup(target, 0, eMs, lMs);
  }, [summary, input, lookup]);

  const handleApplyCustom = useCallback(() => {
    const eMs = customFrom ? new Date(customFrom).getTime() : undefined;
    const lMs = customTo ? new Date(customTo).getTime() : undefined;
    if (!eMs && !lMs) return;
    setTimePreset("");
    setEarliestMs(eMs);
    setLatestMs(lMs);
    const target = summary?.arn ?? input.trim();
    if (target) lookup(target, 0, eMs, lMs);
  }, [customFrom, customTo, summary, input, lookup]);

  const handleClearTime = useCallback(() => {
    setTimePreset("");
    setCustomFrom("");
    setCustomTo("");
    setEarliestMs(undefined);
    setLatestMs(undefined);
    const target = summary?.arn ?? input.trim();
    if (target) lookup(target, 0, undefined, undefined);
  }, [summary, input, lookup]);

  // When summary loads after a time-filtered query, populate custom inputs
  // with the filtered range so the user can see what's active
  useEffect(() => {
    if (earliestMs && !customFrom) {
      setCustomFrom(msToDatetimeLocal(earliestMs));
    }
    if (latestMs && !customTo) {
      setCustomTo(msToDatetimeLocal(latestMs));
    }
  }, [earliestMs, latestMs]); // eslint-disable-line react-hooks/exhaustive-deps

  const spanMs = summary ? summary.lastSeenMs - summary.firstSeenMs : 0;
  const uniqueActions = summary?.byEvent.length ?? 0;
  const hasTimeFilter = earliestMs !== undefined || latestMs !== undefined;

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100%",
        background: "var(--bg-primary)",
        overflow: "hidden",
      }}
    >
      {/* Search bar */}
      <div
        style={{
          padding: "8px 12px",
          borderBottom: "1px solid var(--border)",
          background: "var(--bg-secondary)",
          display: "flex",
          gap: 6,
          alignItems: "center",
        }}
      >
        <span style={{ fontSize: 11, fontWeight: 700, color: "var(--text-secondary)", whiteSpace: "nowrap" }}>
          IDENTITY
        </span>
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && lookup(input, 0, earliestMs, latestMs)}
          placeholder="Enter ARN or principal ID…"
          style={{
            flex: 1,
            background: "var(--bg-tertiary)",
            border: "1px solid var(--border)",
            borderRadius: 4,
            color: "var(--text-primary)",
            padding: "4px 8px",
            fontSize: 12,
            fontFamily: "monospace",
            outline: "none",
          }}
        />
        <button
          onClick={() => lookup(input, 0, earliestMs, latestMs)}
          disabled={loading}
          style={{
            background: "var(--accent-blue)",
            border: "none",
            borderRadius: 4,
            color: "#0d1117",
            padding: "4px 12px",
            fontSize: 12,
            fontWeight: 600,
            cursor: loading ? "default" : "pointer",
            opacity: loading ? 0.6 : 1,
            whiteSpace: "nowrap",
          }}
        >
          {loading ? "…" : "Lookup"}
        </button>
      </div>

      {/* Time filter bar */}
      <div
        style={{
          padding: "4px 12px",
          borderBottom: "1px solid var(--border)",
          background: "var(--bg-secondary)",
          display: "flex",
          alignItems: "center",
          gap: 6,
          flexWrap: "wrap",
          flexShrink: 0,
        }}
      >
        <span style={{ fontSize: 11, color: "var(--text-secondary)", whiteSpace: "nowrap" }}>
          Time:
        </span>
        {TIME_PRESETS.map(({ label, value }) => (
          <button
            key={label}
            onClick={() => value === "" ? handleClearTime() : handleTimePreset(value)}
            style={{
              background: (value === "" ? !hasTimeFilter : timePreset === value)
                ? "var(--accent-green)"
                : "var(--bg-tertiary)",
              border: "1px solid var(--border)",
              color: (value === "" ? !hasTimeFilter : timePreset === value)
                ? "#ffffff"
                : "var(--text-secondary)",
              padding: "1px 8px",
              borderRadius: 3,
              fontSize: 11,
              cursor: "pointer",
              fontWeight: (value === "" ? !hasTimeFilter : timePreset === value) ? 600 : 400,
            }}
          >
            {label}
          </button>
        ))}
        <span style={{ marginLeft: 4, fontSize: 11, color: "var(--text-secondary)", whiteSpace: "nowrap" }}>
          From:
        </span>
        <input
          type="datetime-local"
          value={customFrom}
          onChange={(e) => setCustomFrom(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleApplyCustom()}
          style={{
            background: "var(--bg-tertiary)",
            border: "1px solid var(--border)",
            borderRadius: 3,
            color: "var(--text-primary)",
            padding: "1px 4px",
            fontSize: 11,
            colorScheme: "dark",
          }}
        />
        <span style={{ fontSize: 11, color: "var(--text-secondary)", whiteSpace: "nowrap" }}>
          To:
        </span>
        <input
          type="datetime-local"
          value={customTo}
          onChange={(e) => setCustomTo(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleApplyCustom()}
          style={{
            background: "var(--bg-tertiary)",
            border: "1px solid var(--border)",
            borderRadius: 3,
            color: "var(--text-primary)",
            padding: "1px 4px",
            fontSize: 11,
            colorScheme: "dark",
          }}
        />
        <button
          onClick={handleApplyCustom}
          disabled={!customFrom && !customTo}
          style={{
            background: "var(--bg-tertiary)",
            border: "1px solid var(--border)",
            borderRadius: 3,
            color: (!customFrom && !customTo) ? "var(--text-secondary)" : "var(--accent-blue)",
            padding: "1px 8px",
            fontSize: 11,
            cursor: (!customFrom && !customTo) ? "default" : "pointer",
            opacity: (!customFrom && !customTo) ? 0.5 : 1,
            fontWeight: 600,
          }}
        >
          Apply
        </button>
        {hasTimeFilter && (
          <button
            onClick={handleClearTime}
            style={{
              background: "none",
              border: "none",
              color: "var(--accent-red, #f85149)",
              padding: "1px 4px",
              fontSize: 11,
              cursor: "pointer",
            }}
            title="Clear time filter"
          >
            ✕ Clear
          </button>
        )}
      </div>

      {error && (
        <div
          style={{
            margin: "8px 12px",
            color: "var(--accent-red, #f85149)",
            fontSize: 12,
            padding: "4px 8px",
            background: "rgba(248,81,73,0.1)",
            borderRadius: 4,
            border: "1px solid rgba(248,81,73,0.3)",
          }}
        >
          {error}
        </div>
      )}

      {summary && (
        <>
          {/* Stats cards */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(4, 1fr)",
              gap: 1,
              borderBottom: "1px solid var(--border)",
              background: "var(--border)",
              flexShrink: 0,
            }}
          >
            {[
              { label: "Total Events", value: summary.totalEvents.toLocaleString() },
              { label: "First Seen", value: formatTs(summary.firstSeenMs) },
              { label: "Last Seen", value: formatTs(summary.lastSeenMs) },
              { label: "Active Span", value: `${durLabel(spanMs)} · ${uniqueActions} actions` },
            ].map(({ label, value }) => (
              <div
                key={label}
                style={{
                  background: "var(--bg-secondary)",
                  padding: "8px 12px",
                }}
              >
                <div style={{ fontSize: 10, textTransform: "uppercase", color: "var(--text-secondary)", marginBottom: 3, letterSpacing: "0.05em" }}>
                  {label}
                </div>
                <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)", fontFamily: "monospace" }}>
                  {value}
                </div>
              </div>
            ))}
          </div>

          {/* ARN */}
          <div
            style={{
              padding: "4px 12px",
              background: "var(--bg-secondary)",
              borderBottom: "1px solid var(--border)",
              fontSize: 11,
              fontFamily: "monospace",
              color: "var(--accent-blue)",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
              flexShrink: 0,
            }}
            title={summary.arn}
          >
            {summary.arn}
          </div>

          {/* Table header */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "152px 180px minmax(100px, 1fr) 80px 110px 140px",
              borderBottom: "1px solid var(--border)",
              background: "var(--bg-tertiary)",
              flexShrink: 0,
            }}
          >
            {["Time", "Event Name", "Resource / Detail", "Region", "Source IP", "Error"].map((h) => (
              <span
                key={h}
                style={{
                  padding: "4px 8px",
                  fontSize: 10,
                  fontWeight: 700,
                  textTransform: "uppercase",
                  color: "var(--text-secondary)",
                  letterSpacing: "0.05em",
                }}
              >
                {h}
              </span>
            ))}
          </div>

          {/* Event timeline — vertically scrollable */}
          <div style={{ flex: 1, overflowY: "auto", overflowX: "auto" }}>
            {summary.events.map((ev) => (
              <EventRow key={ev.id} ev={ev} />
            ))}
            {summary.totalEvents > summary.pageSize && (
              <div
                style={{
                  padding: "8px 12px",
                  fontSize: 11,
                  color: "var(--text-secondary)",
                  textAlign: "center",
                  borderTop: "1px solid var(--border)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: 12,
                }}
              >
                <button
                  onClick={() => lookup(summary.arn, currentPage - 1, earliestMs, latestMs)}
                  disabled={currentPage === 0 || loading}
                  style={{
                    background: "var(--bg-tertiary)",
                    border: "1px solid var(--border)",
                    borderRadius: 4,
                    color: currentPage === 0 ? "var(--text-secondary)" : "var(--accent-blue)",
                    padding: "2px 10px",
                    fontSize: 11,
                    cursor: currentPage === 0 ? "default" : "pointer",
                    opacity: currentPage === 0 ? 0.5 : 1,
                  }}
                >
                  Prev
                </button>
                <span>
                  {(currentPage * summary.pageSize + 1).toLocaleString()}–
                  {Math.min((currentPage + 1) * summary.pageSize, summary.totalEvents).toLocaleString()}
                  {" "}of {summary.totalEvents.toLocaleString()} events
                </span>
                <button
                  onClick={() => lookup(summary.arn, currentPage + 1, earliestMs, latestMs)}
                  disabled={(currentPage + 1) * summary.pageSize >= summary.totalEvents || loading}
                  style={{
                    background: "var(--bg-tertiary)",
                    border: "1px solid var(--border)",
                    borderRadius: 4,
                    color: (currentPage + 1) * summary.pageSize >= summary.totalEvents ? "var(--text-secondary)" : "var(--accent-blue)",
                    padding: "2px 10px",
                    fontSize: 11,
                    cursor: (currentPage + 1) * summary.pageSize >= summary.totalEvents ? "default" : "pointer",
                    opacity: (currentPage + 1) * summary.pageSize >= summary.totalEvents ? 0.5 : 1,
                  }}
                >
                  Next
                </button>
              </div>
            )}
          </div>
        </>
      )}

      {!summary && !loading && !error && (
        <div
          style={{
            flex: 1,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color: "var(--text-secondary)",
            fontSize: 12,
          }}
        >
          Enter an ARN or principal ID to investigate
        </div>
      )}
    </div>
  );
}
