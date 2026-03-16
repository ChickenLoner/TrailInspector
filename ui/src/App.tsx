import { useState, useEffect, useCallback } from "react";
import { DropZone } from "./components/ingest/DropZone";
import { EventTable } from "./components/results/EventTable";
import { EventDetail } from "./components/results/EventDetail";
import { StatusBar } from "./components/layout/StatusBar";
import { search } from "./lib/tauri";
import type { RecordRow, SearchResult } from "./types/cloudtrail";
import "./styles/globals.css";

export default function App() {
  const [loaded, setLoaded] = useState(false);
  const [recordCount, setRecordCount] = useState(0);
  const [results, setResults] = useState<SearchResult | null>(null);
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<RecordRow | null>(null);
  const [loading, setLoading] = useState(false);

  const fetchPage = useCallback(async (p: number) => {
    setLoading(true);
    try {
      const r = await search(p, 100);
      setResults(r);
      setPage(p);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, []);

  const handleLoaded = useCallback((count: number) => {
    setRecordCount(count);
    setLoaded(true);
    fetchPage(0);
  }, [fetchPage]);

  useEffect(() => {
    if (loaded) {
      fetchPage(page);
    }
  }, []);

  if (!loaded) {
    return (
      <div style={{ height: "100vh", background: "var(--bg-primary)" }}>
        <DropZone onLoaded={handleLoaded} />
        <StatusBar recordCount={0} loaded={false} />
      </div>
    );
  }

  return (
    <div className="flex flex-col" style={{ height: "100vh" }}>
      {/* Top bar */}
      <div
        className="flex items-center px-3 gap-3 flex-shrink-0"
        style={{ height: 40, background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)' }}
      >
        <span className="font-bold text-sm" style={{ color: 'var(--accent-blue)' }}>TrailInspector</span>
        <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
          {loading ? "Loading..." : `${recordCount.toLocaleString()} events`}
        </span>
      </div>

      {/* Main content */}
      <div className="flex flex-1 overflow-hidden">
        {results && (
          <EventTable
            records={results.records}
            total={results.total}
            page={page}
            pageSize={100}
            onPageChange={fetchPage}
            selectedId={selected?.id}
            onSelect={setSelected}
          />
        )}
        <EventDetail record={selected} onClose={() => setSelected(null)} />
      </div>

      <StatusBar recordCount={recordCount} loaded={loaded} />
    </div>
  );
}
