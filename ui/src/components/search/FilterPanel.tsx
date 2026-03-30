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

interface ActiveFilter {
  value: string;
  mode: FilterMode;
}

interface Props {
  /** Called whenever active filters change. Returns a partial query string fragment. */
  onFilterChange: (fragment: string) => void;
  /** Called when a user name is clicked — triggers Identity tab navigation. */
  onUserSelect?: (user: string) => void;
  /** Current active query from parent — used to scope field value counts. */
  query?: string;
}

export function FilterPanel({ onFilterChange, onUserSelect, query }: Props) {
  const [sections, setSections] = useState<Record<string, FieldValueCount[]>>({});
  const [filters, setFilters] = useState<Record<string, ActiveFilter | null>>({});
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const loadTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Reload field value counts whenever the active query changes (debounced 300ms)
  useEffect(() => {
    if (loadTimer.current) clearTimeout(loadTimer.current);
    loadTimer.current = setTimeout(async () => {
      const results: Record<string, FieldValueCount[]> = {};
      await Promise.all(
        FILTER_SECTIONS.map(async ({ field }) => {
          try {
            results[field] = await getTopFields(field, query || undefined, 20);
          } catch {
            results[field] = [];
          }
        })
      );
      setSections(results);
    }, 300);
    return () => {
      if (loadTimer.current) clearTimeout(loadTimer.current);
    };
  }, [query]);

  const buildFragment = useCallback(
    (newFilters: Record<string, ActiveFilter | null>) => {
      const parts: string[] = [];
      for (const { field } of FILTER_SECTIONS) {
        const f = newFilters[field];
        if (!f) continue;
        const val = f.value.replace(/"/g, '\\"');
        if (f.mode === "include") {
          parts.push(`${field}="${val}"`);
        } else {
          parts.push(`${field}!="${val}"`);
        }
      }
      return parts.join(" AND ");
    },
    []
  );

  // Cycles: absent → include → exclude → absent
  const toggleValue = useCallback(
    (field: string, value: string) => {
      setFilters((prev) => {
        const newFilters = { ...prev };
        const current = prev[field];

        if (!current || current.value !== value) {
          newFilters[field] = { value, mode: "include" };
        } else if (current.mode === "include") {
          newFilters[field] = { value, mode: "exclude" };
        } else {
          // exclude → off
          newFilters[field] = null;
        }

        onFilterChange(buildFragment(newFilters));
        return newFilters;
      });
    },
    [buildFragment, onFilterChange]
  );

  const toggleCollapse = useCallback((field: string) => {
    setCollapsed((prev) => ({ ...prev, [field]: !prev[field] }));
  }, []);

  const clearAll = useCallback(() => {
    setFilters({});
    onFilterChange("");
  }, [onFilterChange]);

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

        // Always keep the active filter value visible so the user can click to uncheck it,
        // even if it drops out of the query-scoped top-N (e.g. after an exclude filter).
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
