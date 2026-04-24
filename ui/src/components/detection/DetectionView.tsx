import { useState, useEffect, useCallback } from "react";
import { runDetections, getCustomRuleErrors, reloadCustomRules, openRulesFile } from "../../lib/tauri";
import type { Alert } from "../../types/cloudtrail";
import { AlertPanel } from "./AlertPanel";
import { AlertDetail } from "./AlertDetail";

interface Props {
  onViewEvidence: (query: string) => void;
  startMs?: number;
  endMs?: number;
}

export function DetectionView({ onViewEvidence, startMs, endMs }: Props) {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ruleErrors, setRuleErrors] = useState<string[]>([]);
  const [reloading, setReloading] = useState(false);

  const fetchRuleErrors = useCallback(async () => {
    try {
      const errs = await getCustomRuleErrors();
      setRuleErrors(errs);
    } catch {
      // non-critical — silently ignore
    }
  }, []);

  const runAll = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await runDetections(startMs, endMs);
      setAlerts(result);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [startMs, endMs]);

  const handleReload = useCallback(async () => {
    setReloading(true);
    try {
      const errs = await reloadCustomRules();
      setRuleErrors(errs);
      await runAll();
    } catch (e) {
      setError(String(e));
    } finally {
      setReloading(false);
    }
  }, [runAll]);

  const handleOpenFile = useCallback(async () => {
    try {
      await openRulesFile();
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    fetchRuleErrors();
    runAll();
  }, [startMs, endMs]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleCloseDetail = useCallback(() => setSelectedAlert(null), []);

  const isWorking = loading || reloading;

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

        {!isWorking && (
          <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>
            {alerts.length} alert{alerts.length !== 1 ? "s" : ""}
          </span>
        )}

        <div style={{ flex: 1 }} />

        {/* Open rules file */}
        <button
          onClick={handleOpenFile}
          disabled={isWorking}
          title="Open rules.yaml in your default text editor"
          style={{
            background: "transparent",
            border: "1px solid var(--border)",
            borderRadius: 4,
            color: "var(--text-secondary)",
            padding: "3px 10px",
            fontSize: 11,
            fontWeight: 500,
            cursor: isWorking ? "default" : "pointer",
            opacity: isWorking ? 0.5 : 1,
          }}
        >
          Open Rules File
        </button>

        {/* Reload rules */}
        <button
          onClick={handleReload}
          disabled={isWorking}
          title="Reload rules.yaml and re-run detections"
          style={{
            background: "transparent",
            border: "1px solid var(--border)",
            borderRadius: 4,
            color: ruleErrors.length > 0 ? "#e3b341" : "var(--text-secondary)",
            padding: "3px 10px",
            fontSize: 11,
            fontWeight: 500,
            cursor: isWorking ? "default" : "pointer",
            opacity: isWorking ? 0.5 : 1,
            display: "flex",
            alignItems: "center",
            gap: 5,
          }}
        >
          {reloading ? "Reloading…" : "Reload Rules"}
          {ruleErrors.length > 0 && !reloading && (
            <span
              style={{
                background: "#e3b341",
                color: "#0d1117",
                borderRadius: 10,
                padding: "0 5px",
                fontSize: 10,
                fontWeight: 700,
                lineHeight: "16px",
              }}
            >
              {ruleErrors.length}
            </span>
          )}
        </button>

        {/* Re-run detections */}
        <button
          onClick={runAll}
          disabled={isWorking}
          style={{
            background: isWorking ? "var(--bg-tertiary)" : "var(--accent-blue)",
            border: "none",
            borderRadius: 4,
            color: isWorking ? "var(--text-secondary)" : "#0d1117",
            padding: "3px 12px",
            fontSize: 11,
            fontWeight: 600,
            cursor: isWorking ? "default" : "pointer",
            opacity: isWorking ? 0.7 : 1,
          }}
        >
          {loading ? "Running…" : "Re-run Detections"}
        </button>
      </div>

      {/* Custom rule error banner */}
      {ruleErrors.length > 0 && (
        <div
          style={{
            margin: "8px 12px 0",
            padding: "8px 12px",
            background: "rgba(227,179,65,0.1)",
            border: "1px solid rgba(227,179,65,0.35)",
            borderRadius: 4,
            fontSize: 12,
            color: "#e3b341",
            flexShrink: 0,
          }}
        >
          <div style={{ fontWeight: 600, marginBottom: ruleErrors.length > 1 ? 4 : 0 }}>
            {ruleErrors.length} custom rule error{ruleErrors.length !== 1 ? "s" : ""} — fix in rules.yaml and click Reload Rules
          </div>
          {ruleErrors.map((e, i) => (
            <div key={i} style={{ opacity: 0.85, fontFamily: "monospace", fontSize: 11 }}>
              {e}
            </div>
          ))}
        </div>
      )}

      {/* Detection run error banner */}
      {error && (
        <div
          style={{
            margin: "8px 12px 0",
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
      {isWorking && (
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
          {reloading ? "Reloading rules…" : "Running detection rules…"}
        </div>
      )}

      {/* Main content */}
      {!isWorking && (
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
