import { useState } from "react";
import type { GlobalTimeRange } from "../../types/cloudtrail";

// ---------------------------------------------------------------------------
// Preset definitions
// ---------------------------------------------------------------------------

const PRESETS: { label: string; offsetMs: number | null }[] = [
  { label: "All",  offsetMs: null },
  { label: "1h",   offsetMs: 60 * 60 * 1_000 },
  { label: "6h",   offsetMs: 6 * 60 * 60 * 1_000 },
  { label: "24h",  offsetMs: 24 * 60 * 60 * 1_000 },
  { label: "7d",   offsetMs: 7 * 24 * 60 * 60 * 1_000 },
];

function msToDatetimeLocal(ms: number): string {
  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
}

function datetimeLocalToMs(value: string): number {
  // Treat datetime-local input as UTC (append "Z")
  return new Date(value + "Z").getTime();
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

interface Props {
  timeRange: GlobalTimeRange;
  onTimeRangeChange: (range: GlobalTimeRange) => void;
}

export function GlobalTimeBar({ timeRange, onTimeRangeChange }: Props) {
  const [showCustom, setShowCustom] = useState(false);
  const [customStart, setCustomStart] = useState(() =>
    timeRange.startMs ? msToDatetimeLocal(timeRange.startMs) : ""
  );
  const [customEnd, setCustomEnd] = useState(() =>
    timeRange.endMs ? msToDatetimeLocal(timeRange.endMs) : ""
  );

  const applyPreset = (offsetMs: number | null, label: string) => {
    setShowCustom(false);
    if (offsetMs === null) {
      onTimeRangeChange({ startMs: null, endMs: null, label: "All" });
    } else {
      const endMs = Date.now();
      const startMs = endMs - offsetMs;
      onTimeRangeChange({ startMs, endMs, label: `Last ${label}` });
    }
  };

  const applyCustom = () => {
    if (!customStart || !customEnd) return;
    const startMs = datetimeLocalToMs(customStart);
    const endMs = datetimeLocalToMs(customEnd);
    if (isNaN(startMs) || isNaN(endMs) || startMs >= endMs) return;
    onTimeRangeChange({
      startMs,
      endMs,
      label: "Custom",
    });
    setShowCustom(false);
  };

  const isPresetActive = (offsetMs: number | null) => {
    if (offsetMs === null) return timeRange.startMs === null && timeRange.label !== "Custom";
    return timeRange.label === `Last ${PRESETS.find(p => p.offsetMs === offsetMs)?.label}`;
  };

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 4,
        padding: "0 12px",
        height: 30,
        background: "var(--bg-secondary)",
        borderBottom: "1px solid var(--border)",
        flexShrink: 0,
        position: "relative",
      }}
    >
      <span
        style={{ fontSize: 10, color: "var(--text-secondary)", marginRight: 4, fontWeight: 600, letterSpacing: "0.05em" }}
      >
        TIME:
      </span>

      {/* Preset buttons */}
      {PRESETS.map(({ label, offsetMs }) => {
        const active = isPresetActive(offsetMs);
        return (
          <button
            key={label}
            onClick={() => applyPreset(offsetMs, label)}
            style={{
              background: active ? "var(--accent-green)" : "var(--bg-tertiary)",
              border: "1px solid var(--border)",
              color: active ? "#ffffff" : "var(--text-secondary)",
              padding: "1px 8px",
              borderRadius: 3,
              fontSize: 11,
              cursor: "pointer",
              fontWeight: active ? 600 : 400,
            }}
          >
            {label}
          </button>
        );
      })}

      {/* Custom button */}
      <button
        onClick={() => setShowCustom((v) => !v)}
        style={{
          background: timeRange.label === "Custom" ? "rgba(60,149,209,0.2)" : "var(--bg-tertiary)",
          border: `1px solid ${timeRange.label === "Custom" ? "var(--accent-blue)" : "var(--border)"}`,
          color: timeRange.label === "Custom" ? "var(--accent-blue)" : "var(--text-secondary)",
          padding: "1px 8px",
          borderRadius: 3,
          fontSize: 11,
          cursor: "pointer",
        }}
      >
        Custom…
      </button>

      {/* Active range label */}
      {timeRange.startMs !== null && timeRange.endMs !== null && (
        <span style={{ fontSize: 10, color: "var(--text-secondary)", marginLeft: 4, fontFamily: "monospace" }}>
          {new Date(timeRange.startMs).toISOString().slice(0, 16).replace("T", " ")} UTC
          {" — "}
          {new Date(timeRange.endMs).toISOString().slice(0, 16).replace("T", " ")} UTC
        </span>
      )}

      {/* Custom date picker popover */}
      {showCustom && (
        <div
          style={{
            position: "absolute",
            top: 32,
            left: 0,
            zIndex: 200,
            background: "var(--bg-secondary)",
            border: "1px solid var(--border)",
            borderRadius: 6,
            padding: "12px 16px",
            boxShadow: "0 4px 16px rgba(0,0,0,0.5)",
            display: "flex",
            flexDirection: "column",
            gap: 10,
            minWidth: 340,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: "var(--text-secondary)" }}>Custom Time Range</div>
            <div style={{ fontSize: 10, color: "var(--text-secondary)", background: "var(--bg-tertiary)", border: "1px solid var(--border)", borderRadius: 3, padding: "1px 6px" }}>UTC</div>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <label style={{ fontSize: 11, color: "var(--text-secondary)", width: 36 }}>From</label>
            <input
              type="datetime-local"
              value={customStart}
              onChange={(e) => setCustomStart(e.target.value)}
              style={{
                flex: 1,
                background: "var(--bg-tertiary)",
                border: "1px solid var(--border)",
                borderRadius: 3,
                color: "var(--text-primary)",
                fontSize: 11,
                padding: "3px 6px",
                outline: "none",
                colorScheme: "dark",
              }}
            />
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <label style={{ fontSize: 11, color: "var(--text-secondary)", width: 36 }}>To</label>
            <input
              type="datetime-local"
              value={customEnd}
              onChange={(e) => setCustomEnd(e.target.value)}
              style={{
                flex: 1,
                background: "var(--bg-tertiary)",
                border: "1px solid var(--border)",
                borderRadius: 3,
                color: "var(--text-primary)",
                fontSize: 11,
                padding: "3px 6px",
                outline: "none",
                colorScheme: "dark",
              }}
            />
          </div>
          <div style={{ display: "flex", gap: 6, justifyContent: "flex-end" }}>
            <button
              onClick={() => setShowCustom(false)}
              style={{
                background: "var(--bg-tertiary)",
                border: "1px solid var(--border)",
                borderRadius: 3,
                color: "var(--text-secondary)",
                fontSize: 11,
                padding: "4px 12px",
                cursor: "pointer",
              }}
            >
              Cancel
            </button>
            <button
              onClick={applyCustom}
              disabled={!customStart || !customEnd}
              style={{
                background: "var(--accent-blue)",
                border: "none",
                borderRadius: 3,
                color: "#0d1117",
                fontSize: 11,
                fontWeight: 700,
                padding: "4px 12px",
                cursor: !customStart || !customEnd ? "default" : "pointer",
                opacity: !customStart || !customEnd ? 0.5 : 1,
              }}
            >
              Apply
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
