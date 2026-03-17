import { useState, useCallback, useEffect, useRef } from "react";
import { save } from "@tauri-apps/plugin-dialog";
import { DropZone } from "./components/ingest/DropZone";
import { EventTable } from "./components/results/EventTable";
import { EventDetail } from "./components/results/EventDetail";
import { StatusBar } from "./components/layout/StatusBar";
import { QueryBar } from "./components/search/QueryBar";
import { FilterPanel } from "./components/search/FilterPanel";
import { TimelineChart } from "./components/viz/TimelineChart";
import { AppShell } from "./components/layout/AppShell";
import { search, getTimeline, exportCsv, exportJson } from "./lib/tauri";
import type { RecordRow, SearchResult, TimeBucket, IngestWarning } from "./types/cloudtrail";
import type { Tab } from "./components/layout/Sidebar";
import "./styles/globals.css";

const TIME_PRESETS = [
  { label: "All", value: "" },
  { label: "1h", value: "earliest=-1h" },
  { label: "6h", value: "earliest=-6h" },
  { label: "24h", value: "earliest=-24h" },
  { label: "7d", value: "earliest=-7d" },
];

const LS_QUERY_KEY = "trailinspector_last_query";
const LS_TAB_KEY = "trailinspector_last_tab";

// ── Export dropdown component ────────────────────────────────────────────────
function ExportMenu({ query, disabled }: { query: string; disabled: boolean }) {
  const [open, setOpen] = useState(false);
  const [exporting, setExporting] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  // Close on outside click
  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    window.addEventListener("mousedown", handler);
    return () => window.removeEventListener("mousedown", handler);
  }, [open]);

  const handleExport = useCallback(
    async (format: "csv" | "json") => {
      setOpen(false);
      const filters =
        format === "csv"
          ? [{ name: "CSV", extensions: ["csv"] }]
          : [{ name: "JSON", extensions: ["json"] }];
      try {
        const path = await save({ filters });
        if (!path) return; // user cancelled
        setExporting(true);
        if (format === "csv") {
          await exportCsv(query, path);
        } else {
          await exportJson(query, path);
        }
        alert(`Exported successfully to:\n${path}`);
      } catch (e) {
        alert(`Export failed: ${String(e)}`);
      } finally {
        setExporting(false);
      }
    },
    [query]
  );

  return (
    <div ref={ref} style={{ position: "relative", flexShrink: 0 }}>
      <button
        onClick={() => setOpen((v) => !v)}
        disabled={disabled || exporting}
        title="Export results"
        style={{
          background: "var(--bg-tertiary)",
          border: "1px solid var(--border)",
          color: exporting ? "var(--text-secondary)" : "var(--text-primary)",
          cursor: disabled || exporting ? "not-allowed" : "pointer",
          padding: "3px 10px",
          borderRadius: 3,
          fontSize: 12,
          fontWeight: 500,
          opacity: disabled ? 0.5 : 1,
          display: "flex",
          alignItems: "center",
          gap: 4,
        }}
      >
        {exporting ? "Exporting…" : "Export ▾"}
      </button>

      {open && (
        <div
          style={{
            position: "absolute",
            top: "calc(100% + 4px)",
            right: 0,
            background: "var(--bg-secondary)",
            border: "1px solid var(--border)",
            borderRadius: 4,
            zIndex: 100,
            minWidth: 130,
            boxShadow: "0 4px 12px rgba(0,0,0,0.4)",
          }}
        >
          {(["csv", "json"] as const).map((fmt) => (
            <button
              key={fmt}
              onClick={() => handleExport(fmt)}
              style={{
                display: "block",
                width: "100%",
                textAlign: "left",
                background: "none",
                border: "none",
                color: "var(--text-primary)",
                padding: "7px 12px",
                fontSize: 13,
                cursor: "pointer",
              }}
              onMouseEnter={(e) =>
                (e.currentTarget.style.background = "var(--bg-tertiary)")
              }
              onMouseLeave={(e) =>
                (e.currentTarget.style.background = "none")
              }
            >
              Export {fmt.toUpperCase()}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [loaded, setLoaded] = useState(false);
  const [recordCount, setRecordCount] = useState(0);
  const [results, setResults] = useState<SearchResult | null>(null);
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<RecordRow | null>(null);
  const [loading, setLoading] = useState(false);

  // Search state — restore from localStorage on first mount
  const [queryText, setQueryText] = useState(
    () => localStorage.getItem(LS_QUERY_KEY) ?? ""
  );
  const [filterFragment, setFilterFragment] = useState("");
  const [timePreset, setTimePreset] = useState("");

  // Tab + identity navigation — restore from localStorage
  const [activeTab, setActiveTab] = useState<Tab>(
    () => (localStorage.getItem(LS_TAB_KEY) as Tab | null) ?? "search"
  );
  const [selectedIdentity, setSelectedIdentity] = useState<string | undefined>();

  // Timeline state
  const [timelineBuckets, setTimelineBuckets] = useState<TimeBucket[]>([]);
  const timelineAbortRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Timing tracking
  const [loadTimeMs, setLoadTimeMs] = useState<number | undefined>();
  const [queryTimeMs, setQueryTimeMs] = useState<number | undefined>();

  // Ingest warnings (non-fatal file errors)
  const [ingestWarnings, setIngestWarnings] = useState<IngestWarning[]>([]);
  const [warningsBannerOpen, setWarningsBannerOpen] = useState(false);
  const [warningsDismissed, setWarningsDismissed] = useState(false);

  // Ref for focusing the query input via Ctrl+K
  const queryInputRef = useRef<HTMLInputElement>(null);

  // Persist query + tab to localStorage whenever they change
  useEffect(() => {
    localStorage.setItem(LS_QUERY_KEY, queryText);
  }, [queryText]);

  useEffect(() => {
    localStorage.setItem(LS_TAB_KEY, activeTab);
  }, [activeTab]);

  const buildQuery = useCallback(
    (q: string, f: string, t: string) =>
      [q.trim(), f.trim(), t.trim()].filter(Boolean).join(" AND "),
    []
  );

  const fetchTimeline = useCallback(async (fullQuery: string) => {
    if (timelineAbortRef.current) clearTimeout(timelineAbortRef.current);
    timelineAbortRef.current = setTimeout(async () => {
      try {
        const result = await getTimeline(fullQuery || undefined, 60);
        setTimelineBuckets(result.buckets);
      } catch (e) {
        console.error("Timeline error:", e);
      }
    }, 200);
  }, []);

  const fetchPage = useCallback(
    async (p: number, fullQuery: string) => {
      setLoading(true);
      const t0 = performance.now();
      try {
        const r = await search(p, 100, fullQuery || undefined);
        setResults(r);
        setPage(p);
        setQueryTimeMs(Math.round(performance.now() - t0));
      } catch (e) {
        console.error("Search error:", e);
      } finally {
        setLoading(false);
      }
    },
    []
  );

  const runQuery = useCallback(
    (q: string, f: string, t: string, p = 0) => {
      const fullQuery = buildQuery(q, f, t);
      fetchPage(p, fullQuery);
      fetchTimeline(fullQuery);
    },
    [buildQuery, fetchPage, fetchTimeline]
  );

  const handleQuerySubmit = useCallback(
    (q: string) => {
      setQueryText(q);
      runQuery(q, filterFragment, timePreset);
    },
    [filterFragment, timePreset, runQuery]
  );

  const handleFilterChange = useCallback(
    (fragment: string) => {
      setFilterFragment(fragment);
      runQuery(queryText, fragment, timePreset);
    },
    [queryText, timePreset, runQuery]
  );

  const handleTimePreset = useCallback(
    (preset: string) => {
      setTimePreset(preset);
      runQuery(queryText, filterFragment, preset);
    },
    [queryText, filterFragment, runQuery]
  );

  const handleLoaded = useCallback(
    (count: number, warnings: IngestWarning[], elapsedMs?: number) => {
      setRecordCount(count);
      setLoaded(true);
      setIngestWarnings(warnings);
      setWarningsDismissed(false);
      setWarningsBannerOpen(false);
      if (elapsedMs !== undefined) setLoadTimeMs(elapsedMs);
      fetchPage(0, "");
      fetchTimeline("");
    },
    [fetchPage, fetchTimeline]
  );

  const handleTimeRangeSelect = useCallback(
    (startMs: number, endMs: number) => {
      const fragment = `earliest=${startMs} latest=${endMs}`;
      setTimePreset(fragment);
      runQuery(queryText, filterFragment, fragment);
    },
    [queryText, filterFragment, runQuery]
  );

  const handleUserSelect = useCallback((user: string) => {
    setSelectedIdentity(user);
    setActiveTab("identity");
  }, []);

  const handleFilterSelect = useCallback(
    (field: string, value: string) => {
      const fragment = `${field}="${value}"`;
      setQueryText((prev) => {
        const next = prev.trim() ? `${prev.trim()} AND ${fragment}` : fragment;
        runQuery(next, filterFragment, timePreset);
        return next;
      });
      setActiveTab("search");
    },
    [filterFragment, timePreset, runQuery]
  );

  const handleViewEvidence = useCallback(
    (query: string) => {
      setQueryText(query);
      setFilterFragment("");
      setTimePreset("");
      runQuery(query, "", "");
      setActiveTab("search");
    },
    [runQuery]
  );

  // ── Global keyboard shortcuts ─────────────────────────────────────────────
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      // Ctrl+K / Cmd+K — focus query bar
      if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault();
        queryInputRef.current?.focus();
        queryInputRef.current?.select();
        return;
      }

      // Escape (global) — close detail panel when not inside query bar
      if (e.key === "Escape" && document.activeElement !== queryInputRef.current) {
        setSelected(null);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  const activeQuery = buildQuery(queryText, filterFragment, timePreset);
  const queryActive = activeQuery.trim().length > 0;

  if (!loaded) {
    return (
      <div style={{ height: "100vh", background: "var(--bg-primary)" }}>
        <DropZone onLoaded={handleLoaded} />
        <StatusBar recordCount={0} loaded={false} />
      </div>
    );
  }

  // The search view rendered inside AppShell on the Search tab
  const searchView = (
    <div className="flex flex-col" style={{ height: "100%" }}>
      {/* Top bar: brand + query bar + export */}
      <div
        className="flex items-center flex-shrink-0"
        style={{
          background: "var(--bg-secondary)",
          borderBottom: "1px solid var(--border)",
        }}
      >
        <div
          className="flex items-center px-3 flex-shrink-0"
          style={{
            height: 40,
            borderRight: "1px solid var(--border)",
            minWidth: 130,
          }}
        >
          <span
            className="font-bold text-sm"
            style={{ color: "var(--accent-green)" }}
          >
            TrailInspector
          </span>
        </div>
        <div className="flex-1">
          <QueryBar
            value={queryText}
            onChange={setQueryText}
            onSubmit={handleQuerySubmit}
            disabled={loading}
            inputRef={queryInputRef}
          />
        </div>
        <div className="px-2 flex-shrink-0">
          <ExportMenu query={activeQuery} disabled={loading} />
        </div>
      </div>

      {/* Time range bar */}
      <div
        className="flex items-center gap-1 px-3 flex-shrink-0"
        style={{
          height: 30,
          background: "var(--bg-secondary)",
          borderBottom: "1px solid var(--border)",
        }}
      >
        <span className="text-xs mr-1" style={{ color: "var(--text-secondary)" }}>
          Time:
        </span>
        {TIME_PRESETS.map(({ label, value }) => (
          <button
            key={label}
            onClick={() => handleTimePreset(value)}
            style={{
              background:
                timePreset === value ? "var(--accent-green)" : "var(--bg-tertiary)",
              border: "1px solid var(--border)",
              color:
                timePreset === value ? "#ffffff" : "var(--text-secondary)",
              padding: "1px 8px",
              borderRadius: 3,
              fontSize: 11,
              cursor: "pointer",
              fontWeight: timePreset === value ? 600 : 400,
            }}
          >
            {label}
          </button>
        ))}
        <span className="text-xs ml-4" style={{ color: "var(--text-secondary)" }}>
          {loading
            ? "Searching…"
            : results
            ? `${results.total.toLocaleString()} events`
            : ""}
        </span>
        {activeQuery && (
          <span
            className="text-xs ml-2 font-mono"
            style={{
              color: "var(--accent-green)",
              maxWidth: 400,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
            title={activeQuery}
          >
            {activeQuery}
          </span>
        )}
      </div>

      {/* Timeline histogram */}
      <div
        style={{
          background: "var(--bg-secondary)",
          borderBottom: "1px solid var(--border)",
          padding: "0 8px",
        }}
      >
        <TimelineChart
          buckets={timelineBuckets}
          onTimeRangeSelect={handleTimeRangeSelect}
        />
      </div>

      {/* Main area: filter panel + table + detail */}
      <div className="flex flex-1 overflow-hidden">
        <FilterPanel onFilterChange={handleFilterChange} onUserSelect={handleUserSelect} />

        <div className="flex flex-col flex-1 overflow-hidden">
          {results && (
            <EventTable
              records={results.records}
              total={results.total}
              page={page}
              pageSize={100}
              onPageChange={(p) => fetchPage(p, activeQuery)}
              selectedId={selected?.id}
              onSelect={setSelected}
            />
          )}
        </div>

        <EventDetail record={selected} onClose={() => setSelected(null)} />
      </div>
    </div>
  );

  return (
    <div style={{ height: "100vh", display: "flex", flexDirection: "column" }}>
      <div style={{ flex: 1, overflow: "hidden" }}>
        <AppShell
          searchView={searchView}
          query={activeQuery}
          onFilterSelect={handleFilterSelect}
          activeTab={activeTab}
          onTabChange={setActiveTab}
          selectedIdentity={selectedIdentity}
          onViewEvidence={handleViewEvidence}
        />
      </div>
      {ingestWarnings.length > 0 && !warningsDismissed && (
        <div
          style={{
            background: "#3a2800",
            borderTop: "1px solid #7c5200",
            color: "#f8be34",
            fontSize: 12,
            padding: "4px 12px",
            display: "flex",
            alignItems: "center",
            gap: 8,
            flexShrink: 0,
            position: "relative",
          }}
        >
          <span
            style={{ cursor: "pointer", textDecoration: "underline" }}
            onClick={() => setWarningsBannerOpen((v) => !v)}
          >
            {ingestWarnings.length} file{ingestWarnings.length > 1 ? "s" : ""} had issues — click to expand
          </span>
          <button
            onClick={() => setWarningsDismissed(true)}
            style={{
              marginLeft: "auto",
              background: "none",
              border: "none",
              color: "#f8be34",
              cursor: "pointer",
              fontSize: 16,
              lineHeight: 1,
            }}
            title="Dismiss"
          >
            ×
          </button>
          {warningsBannerOpen && (
            <div
              style={{
                position: "absolute",
                bottom: "calc(100% + 2px)",
                left: 0,
                right: 0,
                background: "#1e1500",
                border: "1px solid #7c5200",
                padding: 12,
                zIndex: 200,
                maxHeight: 200,
                overflowY: "auto",
              }}
            >
              {ingestWarnings.map((w, i) => (
                <div key={i} style={{ marginBottom: 4, fontSize: 11, fontFamily: "monospace" }}>
                  <span style={{ color: "#f8be34" }}>{w.message}</span>
                  {w.file && (
                    <span style={{ color: "var(--text-dimmed)", marginLeft: 8 }}>{w.file}</span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
      <StatusBar
        recordCount={recordCount}
        loaded={loaded}
        filteredCount={results?.total}
        queryActive={queryActive}
        loadTimeMs={loadTimeMs}
        queryTimeMs={queryTimeMs}
      />
    </div>
  );
}
