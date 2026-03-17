import type { Alert, Severity } from "../../types/cloudtrail";

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#d41f1f",
  high: "#c96d16",
  medium: "#f8be34",
  low: "#3c95d1",
  info: "#65a637",
};

const SEVERITY_BG: Record<Severity, string> = {
  critical: "rgba(212,31,31,0.18)",
  high: "rgba(201,109,22,0.18)",
  medium: "rgba(248,190,52,0.15)",
  low: "rgba(60,149,209,0.15)",
  info: "rgba(101,166,55,0.15)",
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      style={{
        display: "inline-block",
        padding: "1px 7px",
        borderRadius: 3,
        fontSize: 10,
        fontWeight: 700,
        fontFamily: "monospace",
        letterSpacing: "0.06em",
        background: SEVERITY_BG[severity],
        color: SEVERITY_COLOR[severity],
        border: `1px solid ${SEVERITY_COLOR[severity]}40`,
        whiteSpace: "nowrap",
      }}
    >
      {SEVERITY_LABEL[severity]}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Summary cards
// ---------------------------------------------------------------------------

function SummaryCards({ alerts }: { alerts: Alert[] }) {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const a of alerts) {
    counts[a.severity] = (counts[a.severity] ?? 0) + 1;
  }

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(5, 1fr)",
        gap: 1,
        background: "var(--border)",
        borderBottom: "1px solid var(--border)",
        flexShrink: 0,
      }}
    >
      {SEVERITY_ORDER.map((sev) => (
        <div
          key={sev}
          style={{
            background: "var(--bg-secondary)",
            padding: "10px 14px",
            textAlign: "center",
          }}
        >
          <div
            style={{
              fontSize: 22,
              fontWeight: 700,
              fontFamily: "monospace",
              color: counts[sev] > 0 ? SEVERITY_COLOR[sev] : "var(--text-secondary)",
            }}
          >
            {counts[sev]}
          </div>
          <div
            style={{
              fontSize: 10,
              fontWeight: 700,
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              color: SEVERITY_COLOR[sev],
              marginTop: 2,
              opacity: counts[sev] > 0 ? 1 : 0.5,
            }}
          >
            {SEVERITY_LABEL[sev]}
          </div>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Alert row
// ---------------------------------------------------------------------------

interface AlertRowProps {
  alert: Alert;
  isSelected: boolean;
  onClick: () => void;
}

function AlertRow({ alert, isSelected, onClick }: AlertRowProps) {
  return (
    <div
      onClick={onClick}
      style={{
        display: "flex",
        alignItems: "flex-start",
        gap: 10,
        padding: "10px 14px",
        borderBottom: "1px solid var(--border)",
        background: isSelected ? "rgba(60,149,209,0.08)" : "var(--bg-primary)",
        cursor: "pointer",
        borderLeft: isSelected ? "2px solid var(--accent-blue)" : "2px solid transparent",
        transition: "background 0.1s",
      }}
    >
      {/* Severity badge */}
      <div style={{ flexShrink: 0, paddingTop: 1 }}>
        <SeverityBadge severity={alert.severity} />
      </div>

      {/* Main content */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 3 }}>
          <span
            style={{
              fontSize: 12,
              fontWeight: 600,
              color: "var(--text-primary)",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {alert.title}
          </span>
          <span
            style={{
              fontSize: 10,
              fontFamily: "monospace",
              color: "var(--text-secondary)",
              flexShrink: 0,
            }}
          >
            {alert.ruleId}
          </span>
        </div>
        <div
          style={{
            fontSize: 11,
            color: "var(--text-secondary)",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            marginBottom: 3,
          }}
          title={alert.description}
        >
          {alert.description}
        </div>
        <div style={{ display: "flex", gap: 10, fontSize: 10, color: "var(--text-secondary)" }}>
          <span>{alert.matchingRecordIds.length.toLocaleString()} event(s)</span>
          <span style={{ color: "var(--border)" }}>|</span>
          <span>{alert.mitreTactic}</span>
          <span style={{ color: "var(--border)" }}>|</span>
          <span style={{ fontFamily: "monospace" }}>{alert.mitreTechnique}</span>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// AlertPanel
// ---------------------------------------------------------------------------

interface Props {
  alerts: Alert[];
  selectedAlert: Alert | null;
  onAlertSelect: (alert: Alert) => void;
}

export function AlertPanel({ alerts, selectedAlert, onAlertSelect }: Props) {
  if (alerts.length === 0) {
    return (
      <div
        style={{
          flex: 1,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          gap: 8,
          color: "var(--text-secondary)",
          background: "var(--bg-primary)",
        }}
      >
        <div style={{ fontSize: 28, opacity: 0.4 }}>!</div>
        <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)" }}>
          No alerts
        </div>
        <div style={{ fontSize: 11 }}>No detections fired on this dataset.</div>
      </div>
    );
  }

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
      <SummaryCards alerts={alerts} />

      {/* Alert list */}
      <div style={{ flex: 1, overflowY: "auto" }}>
        {alerts.map((alert) => (
          <AlertRow
            key={`${alert.ruleId}-${alert.matchingRecordIds[0]}`}
            alert={alert}
            isSelected={selectedAlert?.ruleId === alert.ruleId}
            onClick={() => onAlertSelect(alert)}
          />
        ))}
      </div>
    </div>
  );
}
