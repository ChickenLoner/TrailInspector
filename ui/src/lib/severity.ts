/**
 * Severity presentation — the single source of truth.
 *
 * The colours themselves live in `styles/globals.css` as `--sev-*` custom
 * properties; this module only names them. Three components previously carried
 * their own palette and two of them disagreed: AlertDetail rendered critical as
 * `#f85149` while AlertPanel and SessionDetail used `#d41f1f`, so the same alert
 * changed colour depending on which panel you looked at. Referencing the vars
 * means a palette change is a one-line CSS edit and cannot drift again.
 */
import type { Severity } from "../types/cloudtrail";

/** Most severe first — the order alerts and filter chips are listed in. */
export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};

/** Translucent fill for badges and highlighted rows. */
export const SEVERITY_BG: Record<Severity, string> = {
  critical: "var(--sev-critical-bg)",
  high: "var(--sev-high-bg)",
  medium: "var(--sev-medium-bg)",
  low: "var(--sev-low-bg)",
  info: "var(--sev-info-bg)",
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

/** Zero-initialised tally, one entry per severity. */
export function emptySeverityCounts(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}
