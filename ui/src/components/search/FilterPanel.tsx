import { useState, useEffect, useCallback, useRef } from "react";
import { getTopFields } from "../../lib/tauri";
import type { FieldValueCount } from "../../types/cloudtrail";

interface FilterSection {
  field: string;
  label: string;
}

const FILTER_SECTIONS: FilterSection[] = [
  { field: "userName", label: "User" },
  { field: "sourceIPAddress", label: "Source IP" },
  { field: "userAgent", label: "User Agent" },
  { field: "eventName", label: "Event Name" },
  { field: "eventSource", label: "Service" },
  { field: "awsRegion", label: "Region" },
  { field: "errorCode", label: "Error Code" },
  { field: "identityType", label: "Identity Type" },
  { field: "bucketName", label: "S3 Bucket" },
];

type FilterMode = "include" | "exclude";

export interface ActiveFilter {
  value: string;
  mode: FilterMode;
}

/** One active filter per field. Owned by the parent — see `Props.filters`. */
export type FilterState = Record<string, ActiveFilter | null>;

/**
 * Render `filters` as a query fragment, optionally omitting one field's clause.
 *
 * Passing `null` yields the fragment applied to the search. Passing a field name
 * yields the scope used to count *that* field's values: every other filter still
 * applies, but the field itself is left unconstrained so all of its reachable
 * values stay listed with true counts — including one you have excluded.
 */
export function buildFilterFragment(filters: FilterState, except: string | null = null): string {
  const parts: string[] = [];
  for (const { field } of FILTER_SECTIONS) {
    if (field === except) continue;
    const f = filters[field];
    if (!f) continue;
    const val = f.value.replace(/"/g, '\\"');
    parts.push(f.mode === "include" ? `${field}="${val}"` : `${field}!="${val}"`);
  }
  return parts.join(" AND ");
}

interface Props {
  /**
   * Active filters, owned by the parent.
   *
   * This must not be local state. `AppShell` unmounts the search view on every
   * tab switch, so a local copy is destroyed while the parent keeps applying the
   * fragment derived from it. The panel would come back empty-handed: the
   * excluded value missing from its own list, no row to click to undo it, and
   * `hasAnyActive` false so the Clear button was hidden as well.
   */
  filters: FilterState;
  /** Called with the next filter state whenever the user cycles a value. */
  onFiltersChange: (next: FilterState) => void;
  /** Called when a user name is clicked — triggers Identity tab navigation. */
  onUserSelect?: (user: string) => void;
  /**
   * Query text + global time range, **without** the filter fragment.
   *
   * The panel re-adds the fragment itself, per field, minus that field's own
   * clause. Passing the combined query here instead would make every facet
   * self-scoping and collapse each list to the one value already picked.
   */
  baseQuery?: string;
}

export function FilterPanel({ filters, onFiltersChange, onUserSelect, baseQuery }: Props) {
  const [sections, setSections] = useState<Record<string, FieldValueCount[]>>({});
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const loadTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Facet loads now fire on every filter click, so guard against a slow earlier
  // batch landing after a newer one and overwriting it.
  const loadReqRef = useRef(0);

  // Reload field value counts whenever the base query or the active filters
  // change (debounced 300ms). Each field is counted against its own scope.
  useEffect(() => {
    if (loadTimer.current) clearTimeout(loadTimer.current);
    loadTimer.current = setTimeout(async () => {
      const reqId = ++loadReqRef.current;
      const results: Record<string, FieldValueCount[]> = {};
      await Promise.all(
        FILTER_SECTIONS.map(async ({ field }) => {
          const scoped = [baseQuery ?? "", buildFilterFragment(filters, field)]
            .map((s) => s.trim())
            .filter(Boolean)
            .join(" AND ");
          try {
            results[field] = await getTopFields(field, scoped || undefined, 20);
          } catch {
            results[field] = [];
          }
        })
      );
      if (reqId !== loadReqRef.current) return; // superseded by a newer load
      setSections(results);
    }, 300);
    return () => {
      if (loadTimer.current) clearTimeout(loadTimer.current);
    };
  }, [baseQuery, filters]);

  // Cycles: absent → include → exclude → absent
  const toggleValue = useCallback(
    (field: string, value: string) => {
      const newFilters = { ...filters };
      const current = filters[field];

      if (!current || current.value !== value) {
        newFilters[field] = { value, mode: "include" };
      } else if (current.mode === "include") {
        newFilters[field] = { value, mode: "exclude" };
      } else {
        // exclude → off
        newFilters[field] = null;
      }

      onFiltersChange(newFilters);
    },
    [filters, onFiltersChange]
  );

  const toggleCollapse = useCallback((field: string) => {
    setCollapsed((prev) => ({ ...prev, [field]: !prev[field] }));
  }, []);

  const clearAll = useCallback(() => onFiltersChange({}), [onFiltersChange]);

  const hasAnyActive = Object.values(filters).some((f) => f !== null);

  return (
    <div
      className="flex flex-col h-full overflow-y-auto"
      style={{
        width: 200,
        minWidth: 200,
        background: "var(--bg-secondary)",
        borderRight: "1px solid var(--border)",
      }}
    >
      {/* Header */}
      <div
        className="flex items-center justify-between px-3 py-2 flex-shrink-0"
        style={{ borderBottom: "1px solid var(--border)" }}
      >
        <span className="text-xs font-semibold" style={{ color: "var(--text-secondary)" }}>
          FILTERS
        </span>
        {hasAnyActive && (
          <button
            onClick={clearAll}
            className="text-xs"
            style={{ color: "var(--accent-blue)", background: "none", border: "none", cursor: "pointer" }}
          >
            Clear
          </button>
        )}
      </div>

      {/* Sections */}
      {FILTER_SECTIONS.map(({ field, label }) => {
        const rawValues = sections[field] ?? [];
        const isCollapsed = collapsed[field];
        const activeFilter = filters[field] ?? null;
        const hasActive = activeFilter !== null;

        // Safety net: the field's own clause is excluded from its count query, so
        // an active value normally comes back with a real count. It can still
        // fall outside the top-20 if the field is high-cardinality and the picked
        // value is rare — keep it pinned so it stays clickable to clear.
        const values =
          activeFilter && !rawValues.some((v) => v.value === activeFilter.value)
            ? [{ value: activeFilter.value, count: 0 }, ...rawValues]
            : rawValues;

        return (
          <div key={field} style={{ borderBottom: "1px solid var(--border)" }}>
            {/* Section header */}
            <button
              onClick={() => toggleCollapse(field)}
              className="w-full flex items-center justify-between px-3 py-2 text-xs font-medium"
              style={{
                background: "none",
                border: "none",
                color: hasActive
                  ? activeFilter?.mode === "exclude"
                    ? "var(--accent-red, #f87171)"
                    : "var(--accent-blue)"
                  : "var(--text-primary)",
                cursor: "pointer",
                textAlign: "left",
              }}
            >
              <span>
                {label}
                {hasActive && (
                  <span style={{ marginLeft: 4, fontSize: 10 }}>
                    {activeFilter?.mode === "exclude" ? "≠" : "="}
                  </span>
                )}
              </span>
              <span style={{ color: "var(--text-secondary)" }}>{isCollapsed ? "▶" : "▼"}</span>
            </button>

            {/* Values */}
            {!isCollapsed && (
              <div className="pb-1">
                {values.length === 0 ? (
                  <div className="px-3 py-1 text-xs" style={{ color: "var(--text-secondary)" }}>
                    No values
                  </div>
                ) : (
                  values.map(({ value, count }) => {
                    const isThisActive = activeFilter?.value === value;
                    const mode: FilterMode | null = isThisActive ? activeFilter!.mode : null;
                    const canInspect = field === "userName" && !!onUserSelect;

                    // Visual styles per state
                    let rowBg = "none";
                    let boxBorder = "var(--border)";
                    let boxBg = "transparent";
                    let boxContent: string | null = null;
                    let boxColor = "transparent";

                    if (mode === "include") {
                      rowBg = "rgba(77, 171, 247, 0.08)";
                      boxBorder = "var(--accent-blue)";
                      boxBg = "var(--accent-blue)";
                      boxContent = "✓";
                      boxColor = "#fff";
                    } else if (mode === "exclude") {
                      rowBg = "rgba(248, 113, 113, 0.08)";
                      boxBorder = "#f87171";
                      boxBg = "#f87171";
                      boxContent = "–";
                      boxColor = "#fff";
                    }

                    return (
                      <div
                        key={value}
                        className="flex items-center"
                        style={{ background: rowBg }}
                      >
                        <button
                          onClick={() => toggleValue(field, value)}
                          className="flex-1 flex items-center gap-2 px-3 py-0.5 text-left"
                          title={`Click to include, again to exclude, again to clear\n${value}`}
                          style={{ background: "none", border: "none", cursor: "pointer", minWidth: 0 }}
                        >
                          {/* State indicator box */}
                          <span
                            style={{
                              width: 10,
                              height: 10,
                              border: `1px solid ${boxBorder}`,
                              background: boxBg,
                              borderRadius: 2,
                              flexShrink: 0,
                              display: "flex",
                              alignItems: "center",
                              justifyContent: "center",
                              fontSize: 8,
                              color: boxColor,
                              lineHeight: 1,
                            }}
                          >
                            {boxContent}
                          </span>
                          <span
                            className="flex-1 text-xs overflow-hidden text-ellipsis whitespace-nowrap"
                            style={{
                              color:
                                mode === "exclude"
                                  ? "#f87171"
                                  : mode === "include"
                                  ? "var(--text-bright)"
                                  : "var(--text-primary)",
                            }}
                            title={value}
                          >
                            {value}
                          </span>
                          <span className="text-xs" style={{ color: "var(--text-secondary)", flexShrink: 0 }}>
                            {count.toLocaleString()}
                          </span>
                        </button>
                        {canInspect && (
                          <button
                            onClick={() => onUserSelect(value)}
                            title="Open in Identity view"
                            style={{
                              background: "none",
                              border: "none",
                              cursor: "pointer",
                              color: "var(--text-secondary)",
                              padding: "0 6px",
                              fontSize: 11,
                              flexShrink: 0,
                            }}
                          >
                            →
                          </button>
                        )}
                      </div>
                    );
                  })
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
