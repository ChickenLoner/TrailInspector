/**
 * Shared display formatters.
 *
 * These were previously redefined per component. Two of the copies were not
 * actually identical — SessionView sliced timestamps to seconds while
 * AlertDetail sliced to minutes, and the two `fmtDuration`s used different
 * shapes ("90m" vs "1h 30m"). Both variants are kept here under distinct names
 * so the difference is a deliberate choice at the call site rather than an
 * accident of which file you happened to be editing.
 *
 * (The local-time variants that used to live here were removed: the same event read as 14:00 in
 * one pane and 07:00 in another. Everything is UTC now.)
 */

import { formatTs } from "./time";

// ---------------------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------------------

/**
 * Timestamps are always UTC (see `lib/time.ts`). These two names remain so call sites can say
 * which precision they want; they delegate so there is one implementation.
 */

/** `2024-01-15 10:00:00` — UTC, second precision. */
export function fmtTimestamp(ms: number): string {
  return formatTs(ms);
}

/** `2024-01-15 10:00` — UTC, minute precision, for space-constrained panels. */
export function fmtTimestampMinutes(ms: number): string {
  return formatTs(ms, { seconds: false });
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
