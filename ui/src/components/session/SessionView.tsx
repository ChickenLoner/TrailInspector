import { useState, useEffect, useCallback } from "react";
import { listSessions } from "../../lib/tauri";
import type { SessionSummary, SessionPage } from "../../types/cloudtrail";
import { SessionDetail } from "./SessionDetail";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function fmtDuration(ms: number): string {
  if (ms < 1000) return "<1s";
  if (ms < 60_000) return `${Math.round(ms / 1000)}s`;
  if (ms < 3_600_000) return `${Math.round(ms / 60_000)}m`;
  return `${(ms / 3_600_000).toFixed(1)}h`;
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace("Z", "").slice(0, 19);
}

// ---------------------------------------------------------------------------
// Session card
// ---------------------------------------------------------------------------

interface CardProps {
  session: SessionSummary;
  isSelected: boolean;
  onClick: () => void;
}

function SessionCard({ session, isSelected, onClick }: CardProps) {
  const hasErrors = session.errorCount > 0;
  return (
    <div
      onClick={onClick}
      style={{
        padding: "10px 14px",
        borderBottom: "1px solid var(--border)",
        background: isSelected ? "rgba(60,149,209,0.08)" : "var(--bg-primary)",
        borderLeft: isSelected ? "2px solid var(--accent-blue)" : "2px solid transparent",
        cursor: "pointer",
        transition: "background 0.1s",
      }}
    >
      {/* Row 1: identity + duration */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
        <span
          style={{
            fontSize: 12,
            fontWeight: 600,
            color: "var(--text-primary)",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            flex: 1,
            minWidth: 0,
          }}
          title={session.identityKey}
        >
          {session.identityKey}
        </span>
        <span
          style={{
            fontSize: 10,
            fontFamily: "monospace",
            color: "var(--text-secondary)",
            flexShrink: 0,
          }}
        >
          {fmtDuration(session.durationMs)}
        </span>
      </div>

      {/* Row 2: IP + timestamp */}
      <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 4 }}>
        <span
          style={{
            fontSize: 11,
            fontFamily: "monospace",
            color: "#58a6ff",
            background: "rgba(88,166,255,0.08)",
            padding: "1px 6px",
            borderRadius: 3,
            border: "1px solid rgba(88,166,255,0.2)",
            flexShrink: 0,
          }}
        >
          {session.sourceIp}
        </span>
        <span style={{ fontSize: 10, color: "var(--text-secondary)" }}>
          {fmtTime(session.firstEventMs)}
        </span>
      </div>

      {/* Row 3: counts + top events */}
      <div style={{ display: "flex", gap: 10, fontSize: 10, color: "var(--text-secondary)", flexWrap: "wrap" }}>
        <span>{session.eventCount.toLocaleString()} events</span>
        {hasErrors && (
          <span style={{ color: "#f85149" }}>
            {session.errorCount} error{session.errorCount !== 1 ? "s" : ""}
          </span>
        )}
        <span style={{ color: "var(--border)" }}>|</span>
        <span
          style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}
          title={session.uniqueEventNames.join(", ")}
        >
          {session.uniqueEventNames.slice(0, 3).join(", ")}
          {session.uniqueEventNames.length > 3 && ` +${session.uniqueEventNames.length - 3}`}
        </span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// SessionView
// ---------------------------------------------------------------------------

const PAGE_SIZE = 50;
const SORT_OPTIONS = [
  { value: "first", label: "Most Recent" },
  { value: "events", label: "Most Events" },
  { value: "duration", label: "Longest" },
  { value: "errors", label: "Most Errors" },
];

interface SessionViewProps {
  startMs?: number;
  endMs?: number;
}

export function SessionView({ startMs, endMs }: SessionViewProps) {
  const [page, setPage] = useState<SessionPage | null>(null);
  const [currentPage, setCurrentPage] = useState(0);
  const [sortBy, setSortBy] = useState("first");
  const [filterIdentity, setFilterIdentity] = useState("");
  const [filterIp, setFilterIp] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);

  const load = useCallback(async (pg: number, sort: string, identity: string, ip: string) => {
    setLoading(true);
    setError(null);
    try {
      const result = await listSessions(
        pg,
        PAGE_SIZE,
        sort,
        identity || undefined,
        ip || undefined,
        startMs,
        endMs,
      );
      setPage(result);
      setCurrentPage(pg);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [startMs, endMs]); // eslint-disable-line react-hooks/exhaustive-deps

  // Initial load + re-load when time range changes
  useEffect(() => {
    load(0, sortBy, filterIdentity, filterIp);
  }, [startMs, endMs]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleSortChange = (sort: string) => {
    setSortBy(sort);
    load(0, sort, filterIdentity, filterIp);
  };

  const handleSearch = () => {
    load(0, sortBy, filterIdentity, filterIp);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") handleSearch();
  };

  const totalPages = page ? Math.ceil(page.total / PAGE_SIZE) : 0;

  return (
    <div style={{ display: "flex", height: "100%", overflow: "hidden" }}>
      {/* Left: list panel */}
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          width: 380,
          flexShrink: 0,
          borderRight: "1px solid var(--border)",
          background: "var(--bg-primary)",
          overflow: "hidden",
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: "6px 12px",
            borderBottom: "1px solid var(--border)",
            background: "var(--bg-secondary)",
            display: "flex",
            alignItems: "center",
            gap: 8,
            flexShrink: 0,
          }}
        >
          <span
            style={{
              fontSize: 11,
              fontWeight: 700,
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              color: "var(--text-secondary)",
            }}
          >
            SESSIONS
          </span>
          {page && (
            <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>
              {page.total.toLocaleString()}
            </span>
          )}
          <div style={{ flex: 1 }} />
          {/* Sort */}
          <select
            value={sortBy}
            onChange={(e) => handleSortChange(e.target.value)}
            style={{
              background: "var(--bg-tertiary)",
              border: "1px solid var(--border)",
              borderRadius: 3,
              color: "var(--text-secondary)",
              fontSize: 11,
              padding: "2px 4px",
              cursor: "pointer",
            }}
          >
            {SORT_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </div>

        {/* Filters */}
        <div
          style={{
            padding: "6px 12px",
            borderBottom: "1px solid var(--border)",
            display: "flex",
            gap: 6,
            flexShrink: 0,
          }}
        >
          <input
            value={filterIdentity}
            onChange={(e) => setFilterIdentity(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Filter identity…"
            style={{
              flex: 1,
              background: "var(--bg-tertiary)",
              border: "1px solid var(--border)",
              borderRadius: 3,
              color: "var(--text-primary)",
              fontSize: 11,
              padding: "3px 7px",
              outline: "none",
              fontFamily: "inherit",
            }}
          />
          <input
            value={filterIp}
            onChange={(e) => setFilterIp(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Filter IP…"
            style={{
              width: 100,
              background: "var(--bg-tertiary)",
              border: "1px solid var(--border)",
              borderRadius: 3,
              color: "var(--text-primary)",
              fontSize: 11,
              padding: "3px 7px",
              outline: "none",
              fontFamily: "monospace",
            }}
          />
          <button
            onClick={handleSearch}
            style={{
              background: "var(--accent-blue)",
              border: "none",
              borderRadius: 3,
              color: "#0d1117",
              fontSize: 11,
              fontWeight: 600,
              padding: "3px 8px",
              cursor: "pointer",
            }}
          >
            Go
          </button>
        </div>

        {/* Error */}
        {error && (
          <div
            style={{
              margin: "8px 12px",
              padding: "6px 10px",
              background: "rgba(248,81,73,0.1)",
              border: "1px solid rgba(248,81,73,0.3)",
              borderRadius: 4,
              fontSize: 11,
              color: "#f85149",
            }}
          >
            {error}
          </div>
        )}

        {/* Loading */}
        {loading && (
          <div
            style={{
              flex: 1,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              color: "var(--text-secondary)",
              fontSize: 12,
            }}
          >
            Loading sessions…
          </div>
        )}

        {/* Session list */}
        {!loading && page && (
          <>
            <div style={{ flex: 1, overflowY: "auto" }}>
              {page.sessions.length === 0 ? (
                <div
                  style={{
                    padding: 24,
                    textAlign: "center",
                    fontSize: 12,
                    color: "var(--text-secondary)",
                  }}
                >
                  No sessions found.
                </div>
              ) : (
                page.sessions.map((s) => (
                  <SessionCard
                    key={s.id}
                    session={s}
                    isSelected={selectedId === s.id}
                    onClick={() => setSelectedId(s.id)}
                  />
                ))
              )}
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: 8,
                  padding: "6px 12px",
                  borderTop: "1px solid var(--border)",
                  background: "var(--bg-secondary)",
                  flexShrink: 0,
                }}
              >
                <button
                  onClick={() => load(currentPage - 1, sortBy, filterIdentity, filterIp)}
                  disabled={currentPage === 0}
                  style={{
                    background: "var(--bg-tertiary)",
                    border: "1px solid var(--border)",
                    borderRadius: 3,
                    color: currentPage === 0 ? "var(--text-dimmed)" : "var(--text-primary)",
                    fontSize: 11,
                    padding: "2px 8px",
                    cursor: currentPage === 0 ? "default" : "pointer",
                  }}
                >
                  ‹ Prev
                </button>
                <span style={{ fontSize: 10, color: "var(--text-secondary)" }}>
                  {currentPage + 1} / {totalPages}
                </span>
                <button
                  onClick={() => load(currentPage + 1, sortBy, filterIdentity, filterIp)}
                  disabled={currentPage >= totalPages - 1}
                  style={{
                    background: "var(--bg-tertiary)",
                    border: "1px solid var(--border)",
                    borderRadius: 3,
                    color: currentPage >= totalPages - 1 ? "var(--text-dimmed)" : "var(--text-primary)",
                    fontSize: 11,
                    padding: "2px 8px",
                    cursor: currentPage >= totalPages - 1 ? "default" : "pointer",
                  }}
                >
                  Next ›
                </button>
              </div>
            )}
          </>
        )}
      </div>

      {/* Right: detail panel */}
      {selectedId !== null ? (
        <SessionDetail sessionId={selectedId} onClose={() => setSelectedId(null)} />
      ) : (
        <div
          style={{
            flex: 1,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color: "var(--text-secondary)",
            fontSize: 12,
            background: "var(--bg-secondary)",
          }}
        >
          Select a session to view details
        </div>
      )}
    </div>
  );
}
