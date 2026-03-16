import { useState, useCallback } from "react";
import { getIdentitySummary } from "../../lib/tauri";
import type { IdentitySummary } from "../../types/cloudtrail";

function formatTs(ms: number): string {
  return new Date(ms).toLocaleString([], {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
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

export function IdentityTimeline() {
  const [arn, setArn] = useState("");
  const [input, setInput] = useState("");
  const [summary, setSummary] = useState<IdentitySummary | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const lookup = useCallback(async (target: string) => {
    const t = target.trim();
    if (!t) return;
    setLoading(true);
    setError(null);
    setSummary(null);
    setArn(t);
    try {
      const result = await getIdentitySummary(t);
      setSummary(result);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") lookup(input);
  };

  const spanMs = summary ? summary.lastSeenMs - summary.firstSeenMs : 0;

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100%",
        background: "var(--bg-primary)",
        padding: 12,
        overflow: "hidden",
      }}
    >
      {/* Header */}
      <div
        style={{
          fontSize: 12,
          fontWeight: 700,
          color: "var(--text-primary)",
          marginBottom: 10,
          borderBottom: "1px solid var(--border)",
          paddingBottom: 6,
        }}
      >
        Identity Investigation
      </div>

      {/* Search bar */}
      <div style={{ display: "flex", gap: 6, marginBottom: 12 }}>
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Enter ARN or principal ID…"
          style={{
            flex: 1,
            background: "var(--bg-tertiary)",
            border: "1px solid var(--border)",
            borderRadius: 4,
            color: "var(--text-primary)",
            padding: "4px 8px",
            fontSize: 12,
            outline: "none",
          }}
        />
        <button
          onClick={() => lookup(input)}
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
          }}
        >
          {loading ? "…" : "Lookup"}
        </button>
      </div>

      {error && (
        <div
          style={{
            color: "var(--accent-red, #f85149)",
            fontSize: 12,
            marginBottom: 8,
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
        <div style={{ flex: 1, overflowY: "auto" }}>
          {/* Summary header */}
          <div
            style={{
              background: "var(--bg-secondary)",
              border: "1px solid var(--border)",
              borderRadius: 6,
              padding: 10,
              marginBottom: 12,
              fontSize: 12,
            }}
          >
            <div
              style={{
                fontFamily: "monospace",
                fontSize: 11,
                color: "var(--accent-blue)",
                wordBreak: "break-all",
                marginBottom: 6,
              }}
            >
              {arn}
            </div>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr 1fr",
                gap: 8,
                color: "var(--text-secondary)",
              }}
            >
              <div>
                <div style={{ fontSize: 10, textTransform: "uppercase", marginBottom: 2 }}>
                  Total Events
                </div>
                <div style={{ fontSize: 16, fontWeight: 700, color: "var(--text-primary)" }}>
                  {summary.totalEvents.toLocaleString()}
                </div>
              </div>
              <div>
                <div style={{ fontSize: 10, textTransform: "uppercase", marginBottom: 2 }}>
                  First Seen
                </div>
                <div style={{ fontSize: 11, color: "var(--text-primary)" }}>
                  {formatTs(summary.firstSeenMs)}
                </div>
              </div>
              <div>
                <div style={{ fontSize: 10, textTransform: "uppercase", marginBottom: 2 }}>
                  Active Span
                </div>
                <div style={{ fontSize: 16, fontWeight: 700, color: "var(--text-primary)" }}>
                  {durLabel(spanMs)}
                </div>
              </div>
            </div>
          </div>

          {/* Per-event breakdown */}
          <div
            style={{
              fontSize: 11,
              fontWeight: 600,
              textTransform: "uppercase",
              color: "var(--text-secondary)",
              marginBottom: 6,
              letterSpacing: "0.05em",
            }}
          >
            Actions ({summary.byEvent.length})
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            {summary.byEvent.map((ev) => {
              const hasErrors = ev.errorCodes.length > 0;
              return (
                <div
                  key={ev.eventName}
                  style={{
                    background: "var(--bg-secondary)",
                    border: `1px solid ${hasErrors ? "rgba(248,81,73,0.4)" : "var(--border)"}`,
                    borderRadius: 4,
                    padding: "6px 10px",
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                  }}
                >
                  <span
                    style={{
                      flex: 1,
                      fontSize: 12,
                      fontFamily: "monospace",
                      color: hasErrors ? "var(--accent-red, #f85149)" : "var(--text-primary)",
                    }}
                  >
                    {ev.eventName}
                  </span>
                  <span
                    style={{
                      background: "var(--bg-tertiary)",
                      borderRadius: 3,
                      padding: "1px 6px",
                      fontSize: 11,
                      color: "var(--accent-blue)",
                      fontWeight: 600,
                    }}
                  >
                    {ev.count.toLocaleString()}
                  </span>
                  <span style={{ fontSize: 10, color: "var(--text-secondary)", minWidth: 80 }}>
                    {formatTs(ev.firstSeenMs).slice(0, 16)}
                  </span>
                  {hasErrors && (
                    <span
                      style={{
                        fontSize: 10,
                        color: "var(--accent-red, #f85149)",
                        maxWidth: 120,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                      title={ev.errorCodes.join(", ")}
                    >
                      {ev.errorCodes.join(", ")}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </div>
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
          Enter an ARN to investigate principal activity
        </div>
      )}
    </div>
  );
}
