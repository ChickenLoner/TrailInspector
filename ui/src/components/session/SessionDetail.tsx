import { useState, useEffect } from "react";
import { getSessionDetail, getSessionAlerts } from "../../lib/tauri";
import type { SessionDetail as SessionDetailType, SessionEvent, AlertStub, Severity } from "../../types/cloudtrail";

const SEV_COLOR: Record<Severity, string> = {
  critical: "#d41f1f", high: "#c96d16", medium: "#f8be34", low: "#3c95d1", info: "#65a637",
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function fmtDuration(ms: number): string {
  if (ms < 1000) return "<1s";
  if (ms < 60_000) return `${Math.round(ms / 1000)}s`;
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`;
  return `${Math.floor(ms / 3_600_000)}h ${Math.floor((ms % 3_600_000) / 60_000)}m`;
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace("Z", "").slice(0, 19);
}

// ---------------------------------------------------------------------------
// Event row in the timeline
// ---------------------------------------------------------------------------

function EventRow({ event }: { event: SessionEvent }) {
  const hasError = !!event.errorCode;
  return (
    <div
      style={{
        display: "flex",
        gap: 10,
        padding: "6px 14px",
        borderBottom: "1px solid var(--border)",
        background: hasError ? "rgba(248,81,73,0.04)" : "transparent",
      }}
    >
      {/* Timestamp */}
      <span
        style={{
          fontSize: 10,
          fontFamily: "monospace",
          color: "var(--text-secondary)",
          flexShrink: 0,
          paddingTop: 1,
          minWidth: 150,
        }}
      >
        {event.eventTime.replace("T", " ").replace("Z", "")}
      </span>

      {/* Event name */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 2 }}>
          <span
            style={{
              fontSize: 12,
              fontWeight: 600,
              color: hasError ? "#f85149" : "var(--text-primary)",
              whiteSpace: "nowrap",
            }}
          >
            {event.eventName}
          </span>
          <span
            style={{
              fontSize: 10,
              color: "var(--text-secondary)",
              fontFamily: "monospace",
            }}
          >
            {event.eventSource}
          </span>
        </div>
        <div style={{ display: "flex", gap: 8, fontSize: 10, color: "var(--text-secondary)", flexWrap: "wrap" }}>
          <span>{event.awsRegion}</span>
          {event.errorCode && (
            <span style={{ color: "#f85149" }}>{event.errorCode}</span>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// SessionDetail
// ---------------------------------------------------------------------------

const EVENTS_PAGE_SIZE = 50;

interface Props {
  sessionId: number;
  onClose: () => void;
}

export function SessionDetail({ sessionId, onClose }: Props) {
  const [detail, setDetail] = useState<SessionDetailType | null>(null);
  const [eventsPage, setEventsPage] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [alerts, setAlerts] = useState<AlertStub[]>([]);

  async function load(epage: number) {
    setLoading(true);
    setError(null);
    try {
      const d = await getSessionDetail(sessionId, epage, EVENTS_PAGE_SIZE);
      setDetail(d);
      setEventsPage(epage);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    setDetail(null);
    setAlerts([]);
    setEventsPage(0);
    load(0);
    getSessionAlerts(sessionId).then(setAlerts).catch(() => {});
  }, [sessionId]); // eslint-disable-line react-hooks/exhaustive-deps

  const totalEventPages = detail ? Math.ceil(detail.eventsTotal / EVENTS_PAGE_SIZE) : 0;

  return (
    <div
      style={{
        flex: 1,
        display: "flex",
        flexDirection: "column",
        background: "var(--bg-secondary)",
        overflow: "hidden",
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: "8px 14px",
          borderBottom: "1px solid var(--border)",
          display: "flex",
          alignItems: "flex-start",
          gap: 10,
          flexShrink: 0,
        }}
      >
        <div style={{ flex: 1, minWidth: 0 }}>
          <div
            style={{
              fontSize: 12,
              fontWeight: 600,
              color: "var(--text-primary)",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
              marginBottom: 4,
            }}
            title={detail?.identityKey}
          >
            {detail?.identityKey ?? "Loading…"}
          </div>

          {detail && (
            <div style={{ display: "flex", gap: 12, fontSize: 10, color: "var(--text-secondary)", flexWrap: "wrap" }}>
              <span
                style={{
                  fontFamily: "monospace",
                  color: "#58a6ff",
                  background: "rgba(88,166,255,0.08)",
                  padding: "1px 6px",
                  borderRadius: 3,
                  border: "1px solid rgba(88,166,255,0.2)",
                }}
              >
                {detail.sourceIp}
              </span>
              <span>{fmtTime(detail.firstEventMs)} → {fmtTime(detail.lastEventMs)}</span>
              <span>{fmtDuration(detail.durationMs)}</span>
              <span>{detail.eventCount.toLocaleString()} events</span>
              {detail.errorCount > 0 && (
                <span style={{ color: "#f85149" }}>{detail.errorCount} errors</span>
              )}
              {detail.uniqueRegions.length > 0 && (
                <span>{detail.uniqueRegions.join(", ")}</span>
              )}
            </div>
          )}
        </div>
        <button
          onClick={onClose}
          style={{
            background: "transparent",
            border: "none",
            color: "var(--text-secondary)",
            cursor: "pointer",
            fontSize: 18,
            lineHeight: 1,
            padding: 2,
            flexShrink: 0,
          }}
          title="Close"
        >
          &times;
        </button>
      </div>

      {/* Unique event names */}
      {detail && detail.uniqueEventNames.length > 0 && (
        <div
          style={{
            padding: "6px 14px",
            borderBottom: "1px solid var(--border)",
            display: "flex",
            gap: 4,
            flexWrap: "wrap",
            flexShrink: 0,
          }}
        >
          {detail.uniqueEventNames.map((name) => (
            <span
              key={name}
              style={{
                fontSize: 10,
                fontFamily: "monospace",
                background: "var(--bg-tertiary)",
                border: "1px solid var(--border)",
                borderRadius: 3,
                padding: "1px 6px",
                color: "var(--text-secondary)",
              }}
            >
              {name}
            </span>
          ))}
        </div>
      )}

      {/* Correlated alerts */}
      {alerts.length > 0 && (
        <div
          style={{
            padding: "6px 14px",
            borderBottom: "1px solid var(--border)",
            flexShrink: 0,
          }}
        >
          <div style={{ fontSize: 10, fontWeight: 700, color: "var(--text-secondary)", marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.05em" }}>
            Alerts ({alerts.length})
          </div>
          <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
            {alerts.map((a) => (
              <span
                key={a.ruleId}
                title={`${a.title} — ${a.matchingCount} event(s)`}
                style={{
                  fontSize: 10,
                  fontFamily: "monospace",
                  background: `${SEV_COLOR[a.severity]}18`,
                  border: `1px solid ${SEV_COLOR[a.severity]}50`,
                  color: SEV_COLOR[a.severity],
                  borderRadius: 3,
                  padding: "1px 6px",
                  whiteSpace: "nowrap",
                }}
              >
                {a.ruleId} · {a.matchingCount}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Error state */}
      {error && (
        <div
          style={{
            margin: "8px 14px",
            padding: "6px 10px",
            background: "rgba(248,81,73,0.1)",
            border: "1px solid rgba(248,81,73,0.3)",
            borderRadius: 4,
            fontSize: 11,
            color: "#f85149",
          }}
        >
          {error}
        </div>
      )}

      {/* Loading */}
      {loading && (
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
          Loading events…
        </div>
      )}

      {/* Event timeline */}
      {!loading && detail && (
        <>
          {/* Column headers */}
          <div
            style={{
              display: "flex",
              gap: 10,
              padding: "4px 14px",
              borderBottom: "1px solid var(--border)",
              background: "var(--bg-primary)",
              flexShrink: 0,
            }}
          >
            <span style={{ fontSize: 10, fontWeight: 600, color: "var(--text-secondary)", minWidth: 150 }}>
              TIME
            </span>
            <span style={{ fontSize: 10, fontWeight: 600, color: "var(--text-secondary)" }}>
              EVENT / SOURCE / REGION
            </span>
          </div>

          <div style={{ flex: 1, overflowY: "auto" }}>
            {detail.events.map((ev: SessionEvent) => (
              <EventRow key={ev.id} event={ev} />
            ))}
          </div>

          {/* Events pagination */}
          {totalEventPages > 1 && (
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                gap: 8,
                padding: "6px 14px",
                borderTop: "1px solid var(--border)",
                background: "var(--bg-secondary)",
                flexShrink: 0,
              }}
            >
              <button
                onClick={() => load(eventsPage - 1)}
                disabled={eventsPage === 0}
                style={{
                  background: "var(--bg-tertiary)",
                  border: "1px solid var(--border)",
                  borderRadius: 3,
                  color: eventsPage === 0 ? "var(--text-dimmed)" : "var(--text-primary)",
                  fontSize: 11,
                  padding: "2px 8px",
                  cursor: eventsPage === 0 ? "default" : "pointer",
                }}
              >
                ‹ Prev
              </button>
              <span style={{ fontSize: 10, color: "var(--text-secondary)" }}>
                Events {eventsPage * EVENTS_PAGE_SIZE + 1}–
                {Math.min((eventsPage + 1) * EVENTS_PAGE_SIZE, detail.eventsTotal)} of {detail.eventsTotal}
              </span>
              <button
                onClick={() => load(eventsPage + 1)}
                disabled={eventsPage >= totalEventPages - 1}
                style={{
                  background: "var(--bg-tertiary)",
                  border: "1px solid var(--border)",
                  borderRadius: 3,
                  color: eventsPage >= totalEventPages - 1 ? "var(--text-dimmed)" : "var(--text-primary)",
                  fontSize: 11,
                  padding: "2px 8px",
                  cursor: eventsPage >= totalEventPages - 1 ? "default" : "pointer",
                }}
              >
                Next ›
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
