/**
 * Time formatting for the whole UI. Everything is UTC: CloudTrail timestamps are UTC, the
 * backend filters in UTC epoch milliseconds, and mixing local and UTC renderings made the same
 * event read as 14:00 in one pane and 07:00 in another.
 */

const pad = (n: number) => String(n).padStart(2, "0");

export interface FormatOptions {
  /** Include seconds (default true). */
  seconds?: boolean;
  /** Append " UTC" (default false; the status bar states the convention once). */
  suffix?: boolean;
}

/**
 * `YYYY-MM-DD HH:MM[:SS]` in UTC. Accepts epoch milliseconds or an ISO string. An unparseable
 * string is returned unchanged; a non-finite number renders as an em dash.
 */
export function formatTs(value: number | string, opts: FormatOptions = {}): string {
  const { seconds = true, suffix = false } = opts;
  const ms = typeof value === "number" ? value : Date.parse(value);
  if (!Number.isFinite(ms)) return typeof value === "string" ? value : "—";
  const d = new Date(ms);
  let out =
    `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ` +
    `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
  if (seconds) out += `:${pad(d.getUTCSeconds())}`;
  return suffix ? `${out} UTC` : out;
}

/** UTC wall time as a `datetime-local` input value (`YYYY-MM-DDTHH:MM`). */
export function toDatetimeLocalUtc(ms: number): string {
  const d = new Date(ms);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
}

/** Read a `datetime-local` input value as UTC. Returns NaN when empty or malformed. */
export function parseLocalInputAsUtc(value: string): number {
  if (!value) return NaN;
  // `datetime-local` yields `YYYY-MM-DDTHH:MM` or `...:SS`; appending Z makes it UTC.
  return Date.parse(`${value}Z`);
}
