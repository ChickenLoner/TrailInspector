import type { ActiveFilters } from "../types/cloudtrail";

/**
 * Turn the active facet filters into a query fragment, e.g.
 * `userName="alice" AND errorCode!="AccessDenied"`.
 *
 * Clauses are joined with AND in the order the filters were first set. Order does not
 * change what matches; it only keeps the displayed query stable and readable.
 */
export function buildFilterFragment(filters: ActiveFilters): string {
  const parts: string[] = [];
  for (const [field, f] of Object.entries(filters)) {
    if (!f) continue;
    const val = f.value.replace(/"/g, '\\"');
    parts.push(f.mode === "include" ? `${field}="${val}"` : `${field}!="${val}"`);
  }
  return parts.join(" AND ");
}
