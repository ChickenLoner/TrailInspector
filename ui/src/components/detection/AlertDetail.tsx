import { useState, useEffect } from "react";
import type { Alert, Severity, SessionSummary } from "../../types/cloudtrail";
import { getAlertSessions } from "../../lib/tauri";

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace("Z", "").slice(0, 16);
}

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#f85149",
  high: "#e3a020",
  medium: "#d29922",
  low: "#58a6ff",
  info: "#8b949e",
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

interface Props {
  alert: Alert | null;
  onViewEvidence: (query: string) => void;
  onClose: () => void;
}

export function AlertDetail({ alert, onViewEvidence, onClose }: Props) {
  const [sessions, setSessions] = useState<SessionSummary[]>([]);

  useEffect(() => {
    setSessions([]);
    if (alert) {
      getAlertSessions(alert.ruleId).then(setSessions).catch(() => {});
    }
  }, [alert?.ruleId]);

  if (!alert) {
    return (
      <div
        style={{
          width: 340,
          flexShrink: 0,
          borderLeft: "1px solid var(--border)",
          background: "var(--bg-secondary)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          color: "var(--text-secondary)",
          fontSize: 11,
        }}
      >
        Select an alert to view details
      </div>
    );
  }

  const color = SEVERITY_COLOR[alert.severity];

  return (
    <div
      style={{
        width: 340,
        flexShrink: 0,
        borderLeft: "1px solid var(--border)",
        background: "var(--bg-secondary)",
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: "10px 12px",
          borderBottom: "1px solid var(--border)",
          display: "flex",
          alignItems: "flex-start",
          gap: 8,
        }}
      >
        <div style={{ flex: 1, minWidth: 0 }}>
          <div
            style={{
              fontSize: 10,
              fontWeight: 700,
              fontFamily: "monospace",
              color,
              letterSpacing: "0.06em",
              marginBottom: 4,
            }}
          >
            {SEVERITY_LABEL[alert.severity]} &mdash; {alert.ruleId}
          </div>
          <div
            style={{
              fontSize: 13,
              fontWeight: 600,
              color: "var(--text-primary)",
              lineHeight: 1.3,
            }}
          >
            {alert.title}
          </div>
        </div>
        <button
          onClick={onClose}
          style={{
            background: "transparent",
            border: "none",
            color: "var(--text-secondary)",
            cursor: "pointer",
            fontSize: 16,
            lineHeight: 1,
            padding: 2,
            flexShrink: 0,
          }}
          title="Close"
        >
          &times;
        </button>
      </div>

      {/* Scrollable content */}
      <div style={{ flex: 1, overflowY: "auto", padding: "10px 12px" }}>
        {/* Description */}
        <div
          style={{
            fontSize: 12,
            color: "var(--text-secondary)",
            lineHeight: 1.5,
            marginBottom: 14,
          }}
        >
          {alert.description}
        </div>

        {/* MITRE */}
        <Section title="MITRE ATT&CK">
          <KV label="Tactic" value={alert.mitreTactic} />
          <KV label="Technique" value={alert.mitreTechnique} mono />
          <KV label="Service" value={alert.service} />
        </Section>

        {/* Evidence count */}
        <Section title="Evidence">
          <KV
            label="Matching Events"
            value={`${alert.matchingRecordIds.length.toLocaleString()} record(s)`}
          />
          <KV label="Search Query" value={alert.query} mono />
        </Section>

        {/* Sessions */}
        {sessions.length > 0 && (
          <Section title={`Sessions (${sessions.length})`}>
            {sessions.map((s) => (
              <div
                key={s.id}
                style={{
                  padding: "5px 8px",
                  borderBottom: "1px solid var(--border)",
                  fontSize: 11,
                }}
              >
                <div
                  style={{
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    color: "var(--text-primary)",
                    marginBottom: 2,
                  }}
                  title={s.identityKey}
                >
                  {s.identityKey}
                </div>
                <div style={{ display: "flex", gap: 8, fontSize: 10, color: "var(--text-secondary)" }}>
                  <span style={{ fontFamily: "monospace", color: "#58a6ff" }}>{s.sourceIp}</span>
                  <span>{fmtTime(s.firstEventMs)}</span>
                  <span>{s.eventCount} events</span>
                </div>
              </div>
            ))}
          </Section>
        )}

        {/* Metadata */}
        {Object.keys(alert.metadata).length > 0 && (
          <Section title="Details">
            {Object.entries(alert.metadata).map(([k, v]) => (
              <KV key={k} label={k} value={v} mono />
            ))}
          </Section>
        )}
      </div>

      {/* View Evidence button */}
      <div
        style={{
          padding: "10px 12px",
          borderTop: "1px solid var(--border)",
          display: "flex",
          gap: 8,
        }}
      >
        <button
          onClick={() => onViewEvidence(alert.query)}
          title={`Opens Search with: ${alert.query}`}
          style={{
            flex: 1,
            background: "var(--accent-blue)",
            border: "none",
            borderRadius: 4,
            color: "#0d1117",
            padding: "6px 12px",
            fontSize: 12,
            fontWeight: 600,
            cursor: "pointer",
          }}
        >
          View Evidence in Search ↗
        </button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 14 }}>
      <div
        style={{
          fontSize: 10,
          fontWeight: 700,
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          color: "var(--text-secondary)",
          marginBottom: 6,
        }}
      >
        {title}
      </div>
      <div
        style={{
          background: "var(--bg-tertiary)",
          borderRadius: 4,
          border: "1px solid var(--border)",
          overflow: "hidden",
        }}
      >
        {children}
      </div>
    </div>
  );
}

function KV({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div
      style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "flex-start",
        padding: "5px 8px",
        borderBottom: "1px solid var(--border)",
        gap: 8,
      }}
    >
      <span style={{ fontSize: 11, color: "var(--text-secondary)", flexShrink: 0 }}>
        {label}
      </span>
      <span
        style={{
          fontSize: 11,
          color: "var(--text-primary)",
          fontFamily: mono ? "monospace" : undefined,
          textAlign: "right",
          wordBreak: "break-all",
        }}
      >
        {value}
      </span>
    </div>
  );
}
