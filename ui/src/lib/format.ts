/**
 * Shared display formatters.
 *
 * These were previously redefined per component. Two of the copies were not
 * actually identical — SessionView sliced timestamps to seconds while
 * AlertDetail sliced to minutes, and the two `fmtDuration`s used different
 * shapes ("90m" vs "1h 30m"). Both variants are kept here under distinct names
 * so the difference is a deliberate choice at the call site rather than an
 * accident of which file you happened to be editing.
 */

// ---------------------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------------------

/** `2024-01-15 10:00:00` — UTC, second precision. */
export function fmtTimestamp(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace("Z", "").slice(0, 19);
}

/** `2024-01-15 10:00` — UTC, minute precision, for space-constrained panels. */
export function fmtTimestampMinutes(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace("Z", "").slice(0, 16);
}

/** Viewer's locale and timezone, 24-hour, second precision. */
export function fmtLocalTimestamp(ms: number): string {
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

/** Viewer's locale, or an em dash when there is no bound to show. */
export function fmtLocalOrDash(ms: number | null): string {
  return ms == null ? "—" : new Date(ms).toLocaleString();
}

// ---------------------------------------------------------------------------
// Durations
// ---------------------------------------------------------------------------

/** Coarsest single unit: `<1s`, `45s`, `12m`, `3.5h`. */
export function fmtDuration(ms: number): string {
  if (ms < 1000) return "<1s";
  if (ms < 60_000) return `${Math.round(ms / 1000)}s`;
  if (ms < 3_600_000) return `${Math.round(ms / 60_000)}m`;
  return `${(ms / 3_600_000).toFixed(1)}h`;
}

/** Two-part form: `<1s`, `45s`, `12m 30s`, `3h 20m`. */
export function fmtDurationParts(ms: number): string {
  if (ms < 1000) return "<1s";
  if (ms < 60_000) return `${Math.round(ms / 1000)}s`;
  if (ms < 3_600_000) {
    return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`;
  }
  return `${Math.floor(ms / 3_600_000)}h ${Math.floor((ms % 3_600_000) / 60_000)}m`;
}

// ---------------------------------------------------------------------------
// Bytes
// ---------------------------------------------------------------------------

export type ByteUnit = "B" | "KB" | "MB" | "GB";

export const BYTE_DIVISORS: Record<ByteUnit, number> = {
  B: 1,
  KB: 1024,
  MB: 1024 * 1024,
  GB: 1024 * 1024 * 1024,
};

export function formatBytes(b: number, unit: ByteUnit): string {
  if (unit === "B") return `${b.toLocaleString()} B`;
  return `${(b / BYTE_DIVISORS[unit]).toFixed(2)} ${unit}`;
}

/** Largest unit that keeps the value >= 1. */
export function autoUnit(b: number): ByteUnit {
  if (b >= 1024 * 1024 * 1024) return "GB";
  if (b >= 1024 * 1024) return "MB";
  if (b >= 1024) return "KB";
  return "B";
}
