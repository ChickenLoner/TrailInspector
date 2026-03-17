import { useState, useEffect, useCallback } from "react";
import { runDetections } from "../../lib/tauri";
import type { Alert } from "../../types/cloudtrail";
import { AlertPanel } from "./AlertPanel";
import { AlertDetail } from "./AlertDetail";

interface Props {
  /** Called when user clicks "View Evidence" — switches to search tab with pre-built query */
  onViewEvidence: (query: string) => void;
}

export function DetectionView({ onViewEvidence }: Props) {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hasRun, setHasRun] = useState(false);

  const runAll = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await runDetections();
      setAlerts(result);
      setHasRun(true);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  // Auto-run on first mount
  useEffect(() => {
    if (!hasRun) {
      runAll();
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const handleCloseDetail = useCallback(() => {
    setSelectedAlert(null);
  }, []);

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
      {/* Header bar */}
      <div
        style={{
          padding: "6px 14px",
          borderBottom: "1px solid var(--border)",
          background: "var(--bg-secondary)",
          display: "flex",
          alignItems: "center",
          gap: 10,
          flexShrink: 0,
        }}
      >
        <span
          style={{
            fontSize: 11,
            fontWeight: 700,
            textTransform: "uppercase",
            letterSpacing: "0.06em",
            color: "var(--text-secondary)",
          }}
        >
          DETECTIONS
        </span>

        {!loading && (
          <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>
            {alerts.length} alert{alerts.length !== 1 ? "s" : ""}
          </span>
        )}

        <div style={{ flex: 1 }} />

        <button
          onClick={runAll}
          disabled={loading}
          style={{
            background: loading ? "var(--bg-tertiary)" : "var(--accent-blue)",
            border: "none",
            borderRadius: 4,
            color: loading ? "var(--text-secondary)" : "#0d1117",
            padding: "3px 12px",
            fontSize: 11,
            fontWeight: 600,
            cursor: loading ? "default" : "pointer",
            opacity: loading ? 0.7 : 1,
          }}
        >
          {loading ? "Running…" : "Re-run Detections"}
        </button>
      </div>

      {/* Error banner */}
      {error && (
        <div
          style={{
            margin: "8px 12px",
            padding: "6px 10px",
            background: "rgba(248,81,73,0.1)",
            border: "1px solid rgba(248,81,73,0.3)",
            borderRadius: 4,
            fontSize: 12,
            color: "#f85149",
            flexShrink: 0,
          }}
        >
          {error}
        </div>
      )}

      {/* Loading spinner */}
      {loading && (
        <div
          style={{
            flex: 1,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color: "var(--text-secondary)",
            fontSize: 12,
            gap: 8,
          }}
        >
          <span style={{ fontFamily: "monospace", fontSize: 18, opacity: 0.6 }}>…</span>
          Running {17} detection rules…
        </div>
      )}

      {/* Main content: panel + detail side-by-side */}
      {!loading && (
        <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
          <AlertPanel
            alerts={alerts}
            selectedAlert={selectedAlert}
            onAlertSelect={setSelectedAlert}
          />
          <AlertDetail
            alert={selectedAlert}
            onViewEvidence={onViewEvidence}
            onClose={handleCloseDetail}
          />
        </div>
      )}
    </div>
  );
}
