import { useState, useCallback, useEffect } from "react";
import { DropZone } from "./components/ingest/DropZone";
import { EventTable } from "./components/results/EventTable";
import { EventDetail } from "./components/results/EventDetail";
import { StatusBar } from "./components/layout/StatusBar";
import { QueryBar } from "./components/search/QueryBar";
import { FilterPanel } from "./components/search/FilterPanel";
import { search } from "./lib/tauri";
import type { RecordRow, SearchResult } from "./types/cloudtrail";
import "./styles/globals.css";

const TIME_PRESETS = [
  { label: "All", value: "" },
  { label: "1h", value: "earliest=-1h" },
  { label: "6h", value: "earliest=-6h" },
  { label: "24h", value: "earliest=-24h" },
  { label: "7d", value: "earliest=-7d" },
];

export default function App() {
  const [loaded, setLoaded] = useState(false);
  const [recordCount, setRecordCount] = useState(0);
  const [results, setResults] = useState<SearchResult | null>(null);
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<RecordRow | null>(null);
  const [loading, setLoading] = useState(false);

  // Search state
  const [queryText, setQueryText] = useState("");
  const [filterFragment, setFilterFragment] = useState("");
  const [timePreset, setTimePreset] = useState("");

  const buildQuery = useCallback(
    (q: string, f: string, t: string) =>
      [q.trim(), f.trim(), t.trim()].filter(Boolean).join(" AND "),
    []
  );

  const fetchPage = useCallback(
    async (p: number, fullQuery: string) => {
      setLoading(true);
      try {
        const r = await search(p, 100, fullQuery || undefined);
        setResults(r);
        setPage(p);
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
      fetchPage(p, buildQuery(q, f, t));
    },
    [buildQuery, fetchPage]
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
    (count: number) => {
      setRecordCount(count);
      setLoaded(true);
      fetchPage(0, "");
    },
    [fetchPage]
  );

  // Ctrl+K: focus query bar
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault();
        (document.getElementById("query-input") as HTMLInputElement)?.focus();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  if (!loaded) {
    return (
      <div style={{ height: "100vh", background: "var(--bg-primary)" }}>
        <DropZone onLoaded={handleLoaded} />
        <StatusBar recordCount={0} loaded={false} />
      </div>
    );
  }

  const activeQuery = buildQuery(queryText, filterFragment, timePreset);

  return (
    <div className="flex flex-col" style={{ height: "100vh" }}>
      {/* Top bar: brand + query bar */}
      <div
        className="flex items-center flex-shrink-0"
        style={{ background: "var(--bg-secondary)", borderBottom: "1px solid var(--border)" }}
      >
        <div
          className="flex items-center px-3 flex-shrink-0"
          style={{ height: 40, borderRight: "1px solid var(--border)", minWidth: 130 }}
        >
          <span className="font-bold text-sm" style={{ color: "var(--accent-blue)" }}>
            TrailInspector
          </span>
        </div>
        <div id="query-input" className="flex-1">
          <QueryBar
            value={queryText}
            onChange={setQueryText}
            onSubmit={handleQuerySubmit}
            disabled={loading}
          />
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
              background: timePreset === value ? "var(--accent-blue)" : "var(--bg-tertiary)",
              border: "1px solid var(--border)",
              color: timePreset === value ? "#0d1117" : "var(--text-secondary)",
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
              color: "var(--accent-green, #3fb950)",
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

      {/* Main area: filter panel + table + detail */}
      <div className="flex flex-1 overflow-hidden">
        <FilterPanel onFilterChange={handleFilterChange} />

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

      <StatusBar recordCount={recordCount} loaded={loaded} />
    </div>
  );
}
