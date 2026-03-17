import { useState, useEffect, useCallback } from "react";
import { getFieldValues } from "../../lib/tauri";
import type { FieldValue } from "../../types/cloudtrail";

interface FilterSection {
  field: string;
  label: string;
}

const FILTER_SECTIONS: FilterSection[] = [
  { field: "userName", label: "User" },
  { field: "sourceIPAddress", label: "Source IP" },
  { field: "userAgent", label: "User Agent" },
  { field: "eventName", label: "Event Name" },
  { field: "awsRegion", label: "Region" },
  { field: "errorCode", label: "Error Code" },
  { field: "identityType", label: "Identity Type" },
];

interface Props {
  /** Called whenever active filters change. Returns a partial query string fragment. */
  onFilterChange: (fragment: string) => void;
  /** Called when a user name is clicked — triggers Identity tab navigation. */
  onUserSelect?: (user: string) => void;
}

export function FilterPanel({ onFilterChange, onUserSelect }: Props) {
  const [sections, setSections] = useState<Record<string, FieldValue[]>>({});
  const [checked, setChecked] = useState<Record<string, Set<string>>>({});
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});

  // Load field values for all sections
  useEffect(() => {
    let cancelled = false;
    async function load() {
      const results: Record<string, FieldValue[]> = {};
      await Promise.all(
        FILTER_SECTIONS.map(async ({ field }) => {
          try {
            results[field] = await getFieldValues(field, 15);
          } catch {
            results[field] = [];
          }
        })
      );
      if (!cancelled) setSections(results);
    }
    load();
    return () => { cancelled = true; };
  }, []);

  const buildFragment = useCallback(
    (newChecked: Record<string, Set<string>>) => {
      const parts: string[] = [];
      for (const { field } of FILTER_SECTIONS) {
        const vals = newChecked[field];
        if (!vals || vals.size === 0) continue;
        const values = [...vals];
        // Always quote the value so multi-word values (e.g. user agents) are not split
        const val = values[0].replace(/"/g, '\\"');
        parts.push(`${field}="${val}"`);
      }
      return parts.join(" AND ");
    },
    []
  );

  const toggleValue = useCallback(
    (field: string, value: string) => {
      setChecked((prev) => {
        const newChecked = { ...prev };
        const existing = new Set(prev[field] ?? []);
        if (existing.has(value)) {
          existing.delete(value);
        } else {
          // Only allow one selection per field for now (radio-like)
          existing.clear();
          existing.add(value);
        }
        newChecked[field] = existing;
        const fragment = buildFragment(newChecked);
        onFilterChange(fragment);
        return newChecked;
      });
    },
    [buildFragment, onFilterChange]
  );

  const toggleCollapse = useCallback((field: string) => {
    setCollapsed((prev) => ({ ...prev, [field]: !prev[field] }));
  }, []);

  const clearAll = useCallback(() => {
    setChecked({});
    onFilterChange("");
  }, [onFilterChange]);

  const hasAnyChecked = Object.values(checked).some((s) => s.size > 0);

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
        {hasAnyChecked && (
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
        const values = sections[field] ?? [];
        const isCollapsed = collapsed[field];
        const activeSet = checked[field] ?? new Set();

        return (
          <div key={field} style={{ borderBottom: "1px solid var(--border)" }}>
            {/* Section header */}
            <button
              onClick={() => toggleCollapse(field)}
              className="w-full flex items-center justify-between px-3 py-2 text-xs font-medium"
              style={{
                background: "none",
                border: "none",
                color: activeSet.size > 0 ? "var(--accent-blue)" : "var(--text-primary)",
                cursor: "pointer",
                textAlign: "left",
              }}
            >
              <span>{label}</span>
              <span style={{ color: "var(--text-secondary)" }}>{isCollapsed ? "▶" : "▼"}</span>
            </button>

            {/* Values */}
            {!isCollapsed && (
              <div className="pb-1">
                {values.length === 0 ? (
                  <div className="px-3 py-1 text-xs" style={{ color: "var(--text-secondary)" }}>
                    Loading…
                  </div>
                ) : (
                  values.map(({ value, count }) => {
                    const isChecked = activeSet.has(value);
                    const canInspect = field === "userName" && !!onUserSelect;
                    return (
                      <div
                        key={value}
                        className="flex items-center"
                        style={{
                          background: isChecked ? "rgba(77, 171, 247, 0.08)" : "none",
                        }}
                      >
                        <button
                          onClick={() => toggleValue(field, value)}
                          className="flex-1 flex items-center gap-2 px-3 py-0.5 text-left"
                          style={{ background: "none", border: "none", cursor: "pointer", minWidth: 0 }}
                        >
                          <span
                            style={{
                              width: 10,
                              height: 10,
                              border: `1px solid ${isChecked ? "var(--accent-blue)" : "var(--border)"}`,
                              background: isChecked ? "var(--accent-blue)" : "transparent",
                              borderRadius: 2,
                              flexShrink: 0,
                            }}
                          />
                          <span
                            className="flex-1 text-xs overflow-hidden text-ellipsis whitespace-nowrap"
                            style={{ color: isChecked ? "var(--text-bright)" : "var(--text-primary)" }}
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
