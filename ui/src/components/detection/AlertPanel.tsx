import { useState, useMemo } from "react";
import type { Alert, Severity } from "../../types/cloudtrail";

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#d41f1f",
  high:     "#c96d16",
  medium:   "#f8be34",
  low:      "#3c95d1",
  info:     "#65a637",
};

const SEVERITY_BG: Record<Severity, string> = {
  critical: "rgba(212,31,31,0.18)",
  high:     "rgba(201,109,22,0.18)",
  medium:   "rgba(248,190,52,0.15)",
  low:      "rgba(60,149,209,0.15)",
  info:     "rgba(101,166,55,0.15)",
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "CRITICAL",
  high:     "HIGH",
  medium:   "MEDIUM",
  low:      "LOW",
  info:     "INFO",
};

type GroupBy = "severity" | "service" | "tactic";

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

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

function ServiceChip({ label }: { label: string }) {
  return (
    <span
      style={{
        display: "inline-block",
        padding: "1px 6px",
        borderRadius: 3,
        fontSize: 10,
        fontWeight: 600,
        fontFamily: "monospace",
        background: "rgba(88,166,255,0.1)",
        color: "#58a6ff",
        border: "1px solid rgba(88,166,255,0.2)",
        whiteSpace: "nowrap",
      }}
    >
      {label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Severity filter chips (replaces old summary cards)
// ---------------------------------------------------------------------------

interface SeverityFiltersProps {
  alerts: Alert[];
  active: Set<Severity>;
  onToggle: (s: Severity) => void;
}

function SeverityFilters({ alerts, active, onToggle }: SeverityFiltersProps) {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const a of alerts) counts[a.severity]++;

  return (
    <div
      style={{
        display: "flex",
        gap: 4,
        padding: "6px 12px",
        borderBottom: "1px solid var(--border)",
        flexWrap: "wrap",
        flexShrink: 0,
      }}
    >
      {SEVERITY_ORDER.map((sev) => {
        const isActive = active.has(sev);
        const count = counts[sev];
        return (
          <button
            key={sev}
            onClick={() => onToggle(sev)}
            disabled={count === 0}
            title={isActive ? `Hide ${sev}` : `Show ${sev}`}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 5,
              padding: "3px 8px",
              borderRadius: 3,
              border: `1px solid ${isActive ? SEVERITY_COLOR[sev] + "60" : "var(--border)"}`,
              background: isActive ? SEVERITY_BG[sev] : "var(--bg-tertiary)",
              color: isActive ? SEVERITY_COLOR[sev] : "var(--text-secondary)",
              fontSize: 10,
              fontWeight: 700,
              fontFamily: "monospace",
              letterSpacing: "0.05em",
              cursor: count === 0 ? "default" : "pointer",
              opacity: count === 0 ? 0.4 : 1,
              transition: "all 0.1s",
            }}
          >
            {SEVERITY_LABEL[sev]}
            <span
              style={{
                background: isActive ? SEVERITY_COLOR[sev] + "30" : "var(--border)",
                borderRadius: 8,
                padding: "0 4px",
                fontSize: 10,
                fontWeight: 700,
                minWidth: 16,
                textAlign: "center",
              }}
            >
              {count}
            </span>
          </button>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Search + group-by toolbar
// ---------------------------------------------------------------------------

interface ToolbarProps {
  search: string;
  onSearchChange: (v: string) => void;
  groupBy: GroupBy;
  onGroupByChange: (g: GroupBy) => void;
  filteredCount: number;
  totalCount: number;
}

function Toolbar({ search, onSearchChange, groupBy, onGroupByChange, filteredCount, totalCount }: ToolbarProps) {
  return (
    <div
      style={{
        padding: "6px 12px",
        borderBottom: "1px solid var(--border)",
        display: "flex",
        gap: 8,
        alignItems: "center",
        flexShrink: 0,
        background: "var(--bg-secondary)",
      }}
    >
      {/* Search */}
      <input
        value={search}
        onChange={(e) => onSearchChange(e.target.value)}
        placeholder="Filter by title or rule ID…"
        style={{
          flex: 1,
          background: "var(--bg-tertiary)",
          border: "1px solid var(--border)",
          borderRadius: 4,
          color: "var(--text-primary)",
          fontSize: 11,
          padding: "4px 8px",
          outline: "none",
          fontFamily: "inherit",
        }}
      />

      {/* Summary */}
      <span style={{ fontSize: 10, color: "var(--text-secondary)", whiteSpace: "nowrap", flexShrink: 0 }}>
        {filteredCount < totalCount
          ? `${filteredCount} / ${totalCount}`
          : `${totalCount} alert${totalCount !== 1 ? "s" : ""}`}
      </span>

      {/* Group-by toggle */}
      <div
        style={{
          display: "flex",
          border: "1px solid var(--border)",
          borderRadius: 4,
          overflow: "hidden",
          flexShrink: 0,
        }}
      >
        {(["severity", "service", "tactic"] as GroupBy[]).map((g) => (
          <button
            key={g}
            onClick={() => onGroupByChange(g)}
            style={{
              padding: "3px 8px",
              border: "none",
              borderRight: g !== "tactic" ? "1px solid var(--border)" : "none",
              background: groupBy === g ? "var(--accent-blue)" : "var(--bg-tertiary)",
              color: groupBy === g ? "#0d1117" : "var(--text-secondary)",
              fontSize: 10,
              fontWeight: 600,
              cursor: "pointer",
              textTransform: "capitalize",
              transition: "all 0.1s",
            }}
          >
            {g}
          </button>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Group section header
// ---------------------------------------------------------------------------

interface GroupHeaderProps {
  label: string;
  count: number;
  isCollapsed: boolean;
  onToggle: () => void;
  groupBy: GroupBy;
  severity?: Severity;
}

function GroupHeader({ label, count, isCollapsed, onToggle, groupBy, severity }: GroupHeaderProps) {
  const color =
    groupBy === "severity" && severity
      ? SEVERITY_COLOR[severity]
      : "var(--text-secondary)";

  return (
    <div
      onClick={onToggle}
      style={{
        display: "flex",
        alignItems: "center",
        gap: 8,
        padding: "5px 12px",
        background: "var(--bg-secondary)",
        borderBottom: "1px solid var(--border)",
        cursor: "pointer",
        userSelect: "none",
      }}
    >
      <span style={{ fontSize: 10, color: "var(--text-secondary)", flexShrink: 0 }}>
        {isCollapsed ? "▶" : "▼"}
      </span>
      {groupBy === "severity" && severity ? (
        <SeverityBadge severity={severity} />
      ) : groupBy === "service" ? (
        <ServiceChip label={label} />
      ) : (
        <span style={{ fontSize: 11, fontWeight: 600, color }}>
          {label}
        </span>
      )}
      <span
        style={{
          fontSize: 10,
          color: "var(--text-secondary)",
          marginLeft: "auto",
          flexShrink: 0,
        }}
      >
        {count} alert{count !== 1 ? "s" : ""}
      </span>
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
  groupBy: GroupBy;
}

function AlertRow({ alert, isSelected, onClick, groupBy }: AlertRowProps) {
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
      {/* Show severity badge unless grouped by severity (redundant there) */}
      {groupBy !== "severity" && (
        <div style={{ flexShrink: 0, paddingTop: 1 }}>
          <SeverityBadge severity={alert.severity} />
        </div>
      )}

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
        <div style={{ display: "flex", gap: 10, fontSize: 10, color: "var(--text-secondary)", flexWrap: "wrap" }}>
          <span>{alert.matchingCount.toLocaleString()} event(s)</span>
          <span style={{ color: "var(--border)" }}>|</span>
          {groupBy !== "service" && <ServiceChip label={alert.service} />}
          {groupBy === "service" && <span>{alert.mitreTactic}</span>}
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
  const [groupBy, setGroupBy] = useState<GroupBy>("severity");
  const [activeSeverities, setActiveSeverities] = useState<Set<Severity>>(
    () => new Set(SEVERITY_ORDER)
  );
  const [search, setSearch] = useState("");
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  function toggleSeverity(sev: Severity) {
    setActiveSeverities((prev) => {
      const next = new Set(prev);
      if (next.has(sev)) next.delete(sev);
      else next.add(sev);
      return next;
    });
  }

  function toggleCollapsed(key: string) {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  // Apply search + severity filters
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return alerts.filter((a) => {
      if (!activeSeverities.has(a.severity)) return false;
      if (q) {
        return (
          a.title.toLowerCase().includes(q) ||
          a.ruleId.toLowerCase().includes(q) ||
          a.service.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [alerts, activeSeverities, search]);

  // Build groups
  const groups = useMemo((): Array<{ key: string; label: string; severity?: Severity; items: Alert[] }> => {
    const map = new Map<string, Alert[]>();
    for (const a of filtered) {
      const key =
        groupBy === "severity" ? a.severity
        : groupBy === "service" ? a.service
        : a.mitreTactic;
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(a);
    }

    if (groupBy === "severity") {
      return SEVERITY_ORDER
        .filter((s) => map.has(s))
        .map((s) => ({ key: s, label: SEVERITY_LABEL[s], severity: s, items: map.get(s)! }));
    }

    // Sort by count desc for service/tactic groupings
    return Array.from(map.entries())
      .sort((a, b) => b[1].length - a[1].length)
      .map(([key, items]) => ({ key, label: key, items }));
  }, [filtered, groupBy]);

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
      <SeverityFilters alerts={alerts} active={activeSeverities} onToggle={toggleSeverity} />
      <Toolbar
        search={search}
        onSearchChange={setSearch}
        groupBy={groupBy}
        onGroupByChange={setGroupBy}
        filteredCount={filtered.length}
        totalCount={alerts.length}
      />

      {/* Grouped alert list */}
      <div style={{ flex: 1, overflowY: "auto" }}>
        {filtered.length === 0 ? (
          <div
            style={{
              padding: 24,
              textAlign: "center",
              fontSize: 12,
              color: "var(--text-secondary)",
            }}
          >
            No alerts match current filters.
          </div>
        ) : (
          groups.map((group) => {
            const isCollapsed = collapsed.has(group.key);
            return (
              <div key={group.key}>
                <GroupHeader
                  label={group.label}
                  count={group.items.length}
                  isCollapsed={isCollapsed}
                  onToggle={() => toggleCollapsed(group.key)}
                  groupBy={groupBy}
                  severity={group.severity}
                />
                {!isCollapsed &&
                  group.items.map((alert) => (
                    <AlertRow
                      key={`${alert.ruleId}-${alert.matchingRecordIds[0]}`}
                      alert={alert}
                      isSelected={selectedAlert?.ruleId === alert.ruleId}
                      onClick={() => onAlertSelect(alert)}
                      groupBy={groupBy}
                    />
                  ))}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
