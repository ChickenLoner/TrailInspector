import { useState, useEffect, useCallback } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { loadGeoipDb, listIps, checkAbuseIpdb, geoLookupOnline } from "../../lib/tauri";
import type { IpPage, IpRow, AbuseCheckResult, OnlineGeoResult } from "../../types/cloudtrail";

// ---------------------------------------------------------------------------
// Flag emoji from country code
// ---------------------------------------------------------------------------

function countryFlag(code?: string | null): string {
  if (!code || code.length !== 2) return "";
  const base = 0x1F1E6 - 65;
  return String.fromCodePoint(base + code.toUpperCase().charCodeAt(0))
    + String.fromCodePoint(base + code.toUpperCase().charCodeAt(1));
}

// ---------------------------------------------------------------------------
// Merge MMDB row data with online geo (online fills gaps, MMDB takes priority)
// ---------------------------------------------------------------------------

interface MergedGeo {
  countryCode?: string;
  countryName?: string;
  city?: string;
  asn?: number;
  asnOrg?: string;
  isp?: string;
}

function parseAsnNumber(asStr?: string): number | undefined {
  if (!asStr) return undefined;
  const m = asStr.match(/^AS(\d+)/);
  return m ? parseInt(m[1], 10) : undefined;
}

function mergeGeo(row: IpRow, online?: OnlineGeoResult): MergedGeo {
  if (online?.status !== "success") {
    return {
      countryCode: row.countryCode ?? undefined,
      countryName: row.countryName ?? undefined,
      city: row.city ?? undefined,
      asn: row.asn ?? undefined,
      asnOrg: row.asnOrg ?? undefined,
    };
  }
  return {
    countryCode: row.countryCode || online.countryCode || undefined,
    countryName: row.countryName || online.country || undefined,
    city: row.city || online.city || undefined,
    asn: row.asn || parseAsnNumber(online.as) || undefined,
    asnOrg: row.asnOrg || online.org || online.isp || undefined,
    isp: online.isp || undefined,
  };
}

// ---------------------------------------------------------------------------
// GeoIP MMDB loader (optional — users can skip this now)
// ---------------------------------------------------------------------------

interface LoaderProps {
  onLoaded: () => void;
  onCancel: () => void;
}

function GeoIpLoader({ onLoaded, onCancel }: LoaderProps) {
  const [geoPath, setGeoPath] = useState<string | null>(null);
  const [asnPath, setAsnPath] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const pickFile = async (setter: (p: string) => void) => {
    const path = await open({
      filters: [{ name: "GeoIP DB", extensions: ["mmdb"] }],
      multiple: false,
    });
    if (typeof path === "string") setter(path);
  };

  const handleLoad = async () => {
    if (!geoPath && !asnPath) {
      setError("Select at least one MMDB file.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      await loadGeoipDb(geoPath ?? undefined, asnPath ?? undefined);
      onLoaded();
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: 16 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
        <div style={{ fontSize: 12, fontWeight: 700, color: "var(--text-primary)" }}>
          Load MMDB (Optional)
        </div>
        <button
          onClick={onCancel}
          style={{ background: "transparent", border: "none", color: "var(--text-secondary)", cursor: "pointer", fontSize: 16, lineHeight: 1, padding: 2 }}
          title="Cancel"
        >×</button>
      </div>
      <div style={{ fontSize: 10, color: "var(--text-secondary)", marginBottom: 12, lineHeight: 1.5, padding: "6px 8px", background: "var(--bg-tertiary)", borderRadius: 4, border: "1px solid var(--border)" }}>
        Basic geo data is already loaded automatically via ip-api.com.
        Load DB-IP Lite MMDB files for offline use or higher accuracy.
        Free at <span style={{ fontFamily: "monospace", color: "#58a6ff" }}>db-ip.com/db/lite</span>
      </div>

      <FileRow
        label="dbip-city-lite.mmdb"
        sublabel="Country, city, coordinates"
        path={geoPath}
        onPick={() => pickFile(setGeoPath)}
        onClear={() => setGeoPath(null)}
      />
      <FileRow
        label="dbip-asn-lite.mmdb"
        sublabel="ASN & organisation"
        path={asnPath}
        onPick={() => pickFile(setAsnPath)}
        onClear={() => setAsnPath(null)}
      />

      {error && (
        <div style={{ marginTop: 8, padding: "5px 8px", background: "rgba(248,81,73,0.1)", border: "1px solid rgba(248,81,73,0.3)", borderRadius: 4, fontSize: 11, color: "#f85149" }}>
          {error}
        </div>
      )}

      <button
        onClick={handleLoad}
        disabled={loading || (!geoPath && !asnPath)}
        style={{
          marginTop: 14, width: "100%",
          background: loading || (!geoPath && !asnPath) ? "var(--bg-tertiary)" : "var(--accent-blue)",
          border: "none", borderRadius: 4,
          color: loading || (!geoPath && !asnPath) ? "var(--text-secondary)" : "#0d1117",
          padding: "7px 0", fontSize: 12, fontWeight: 700,
          cursor: loading || (!geoPath && !asnPath) ? "default" : "pointer",
        }}
      >
        {loading ? "Loading…" : "Load Databases"}
      </button>
    </div>
  );
}

function FileRow({
  label, sublabel, path, onPick, onClear,
}: {
  label: string; sublabel: string; path: string | null;
  onPick: () => void; onClear: () => void;
}) {
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ fontSize: 11, fontWeight: 600, color: "var(--text-secondary)", marginBottom: 1 }}>{label}</div>
      <div style={{ fontSize: 10, color: "var(--text-secondary)", marginBottom: 4 }}>{sublabel}</div>
      <div style={{ display: "flex", gap: 5, alignItems: "center" }}>
        <div style={{ flex: 1, fontSize: 11, fontFamily: "monospace", color: path ? "var(--text-primary)" : "var(--text-secondary)", background: "var(--bg-tertiary)", border: "1px solid var(--border)", borderRadius: 3, padding: "3px 6px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={path ?? ""}>
          {path ? path.split(/[\\/]/).pop() : "No file selected"}
        </div>
        <button onClick={onPick} style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border)", borderRadius: 3, color: "var(--text-primary)", fontSize: 11, padding: "3px 8px", cursor: "pointer", flexShrink: 0 }}>
          Browse…
        </button>
        {path && (
          <button onClick={onClear} style={{ background: "transparent", border: "none", color: "var(--text-secondary)", cursor: "pointer", fontSize: 14, lineHeight: 1, padding: 2, flexShrink: 0 }} title="Clear">×</button>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// AbuseIPDB panel
// ---------------------------------------------------------------------------

function abuseColor(score: number): string {
  if (score === 0) return "#3fb950";
  if (score < 25) return "#d29922";
  if (score < 75) return "#f0883e";
  return "#f85149";
}

interface AbusePanelProps {
  ip: string;
  apiKey: string;
  onSaveKey: (key: string) => void;
  result: AbuseCheckResult | null;
  loading: boolean;
  error: string | null;
  onCheck: () => void;
}

function AbusePanel({ ip, apiKey, onSaveKey, result, loading, error, onCheck }: AbusePanelProps) {
  const [keyInput, setKeyInput] = useState(apiKey);
  useEffect(() => { setKeyInput(apiKey); }, [apiKey]);

  return (
    <div style={{ marginTop: 16, paddingTop: 12, borderTop: "1px solid var(--border)" }}>
      <div style={{ fontSize: 10, fontWeight: 700, color: "var(--text-secondary)", letterSpacing: "0.05em", textTransform: "uppercase", marginBottom: 8 }}>
        AbuseIPDB
      </div>

      {!apiKey ? (
        <div>
          <div style={{ fontSize: 10, color: "var(--text-secondary)", marginBottom: 6 }}>
            Enter your API key to check IP reputation (free at abuseipdb.com)
          </div>
          <div style={{ display: "flex", gap: 5 }}>
            <input
              type="password"
              value={keyInput}
              onChange={(e) => setKeyInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter" && keyInput.trim()) onSaveKey(keyInput.trim()); }}
              placeholder="API key…"
              style={{ flex: 1, background: "var(--bg-tertiary)", border: "1px solid var(--border)", borderRadius: 3, color: "var(--text-primary)", fontSize: 11, padding: "3px 6px", outline: "none", fontFamily: "monospace" }}
            />
            <button
              onClick={() => keyInput.trim() && onSaveKey(keyInput.trim())}
              disabled={!keyInput.trim()}
              style={{ background: keyInput.trim() ? "var(--accent-blue)" : "var(--bg-tertiary)", border: "none", borderRadius: 3, color: keyInput.trim() ? "#0d1117" : "var(--text-secondary)", fontSize: 11, fontWeight: 600, padding: "3px 8px", cursor: keyInput.trim() ? "pointer" : "default" }}
            >
              Save
            </button>
          </div>
        </div>
      ) : (
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
            <button
              onClick={onCheck}
              disabled={loading}
              style={{ background: loading ? "var(--bg-tertiary)" : "var(--accent-blue)", border: "none", borderRadius: 3, color: loading ? "var(--text-secondary)" : "#0d1117", fontSize: 11, fontWeight: 600, padding: "4px 12px", cursor: loading ? "default" : "pointer", opacity: loading ? 0.7 : 1 }}
            >
              {loading ? "Checking…" : result ? "Re-check" : `Check ${ip}`}
            </button>
            <button
              onClick={() => onSaveKey("")}
              style={{ background: "transparent", border: "none", color: "var(--text-secondary)", fontSize: 10, cursor: "pointer", textDecoration: "underline" }}
            >
              clear key
            </button>
          </div>

          {error && (
            <div style={{ fontSize: 11, color: "#f85149", background: "rgba(248,81,73,0.08)", border: "1px solid rgba(248,81,73,0.3)", borderRadius: 3, padding: "4px 8px", marginBottom: 6 }}>
              {error}
            </div>
          )}

          {result && (
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8, padding: "6px 8px", background: "var(--bg-tertiary)", borderRadius: 4, border: `1px solid ${abuseColor(result.abuseConfidenceScore)}40` }}>
                <div style={{ fontSize: 22, fontWeight: 700, color: abuseColor(result.abuseConfidenceScore), fontFamily: "monospace", lineHeight: 1 }}>
                  {result.abuseConfidenceScore}%
                </div>
                <div>
                  <div style={{ fontSize: 10, fontWeight: 600, color: abuseColor(result.abuseConfidenceScore) }}>Abuse Confidence</div>
                  <div style={{ fontSize: 10, color: "var(--text-secondary)" }}>{result.totalReports} report{result.totalReports !== 1 ? "s" : ""}</div>
                </div>
              </div>
              {result.isp && <AbuseRow label="ISP" value={result.isp} />}
              {result.domain && <AbuseRow label="Domain" value={result.domain} />}
              {result.usageType && <AbuseRow label="Type" value={result.usageType} />}
              {result.lastReportedAt && (
                <AbuseRow label="Last reported" value={new Date(result.lastReportedAt).toLocaleDateString()} />
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function AbuseRow({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", padding: "3px 0", borderBottom: "1px solid var(--border)", gap: 8 }}>
      <span style={{ fontSize: 10, color: "var(--text-secondary)", flexShrink: 0 }}>{label}</span>
      <span style={{ fontSize: 10, color: "var(--text-primary)", textAlign: "right", wordBreak: "break-all" }}>{value}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Abuse score badge (used in table rows)
// ---------------------------------------------------------------------------

function AbuseBadge({ score }: { score: number }) {
  const color = abuseColor(score);
  return (
    <span
      title={`Abuse confidence: ${score}%`}
      style={{
        display: "inline-block", minWidth: 28, padding: "1px 4px", borderRadius: 3,
        fontSize: 10, fontWeight: 700, fontFamily: "monospace", textAlign: "center",
        color, background: `${color}1a`, border: `1px solid ${color}40`, lineHeight: "14px",
      }}
    >
      {score}%
    </span>
  );
}

// ---------------------------------------------------------------------------
// IP table row
// ---------------------------------------------------------------------------

const GRID_COLS = "160px 44px 52px 110px 160px 60px";

function IpTableRow({
  row, isSelected, onClick, geo, abuseScore,
}: {
  row: IpRow; isSelected: boolean; onClick: () => void;
  geo: MergedGeo; abuseScore?: number | null;
}) {
  const flag = countryFlag(geo.countryCode);
  return (
    <div
      onClick={onClick}
      style={{
        display: "grid", gridTemplateColumns: GRID_COLS, gap: 0,
        padding: "7px 14px", borderBottom: "1px solid var(--border)",
        background: isSelected ? "rgba(60,149,209,0.08)" : "var(--bg-primary)",
        borderLeft: isSelected ? "2px solid var(--accent-blue)" : "2px solid transparent",
        cursor: "pointer", alignItems: "center", transition: "background 0.1s",
      }}
    >
      <span style={{ fontSize: 12, fontFamily: "monospace", color: "#58a6ff" }}>{row.ip}</span>
      <span style={{ display: "flex", justifyContent: "center" }}>
        {abuseScore != null ? <AbuseBadge score={abuseScore} /> : null}
      </span>
      <span style={{ fontSize: 11, color: "var(--text-secondary)", textAlign: "right" }}>{row.eventCount.toLocaleString()}</span>
      <span style={{ fontSize: 11, color: "var(--text-primary)", paddingLeft: 14 }}>
        {flag && <span style={{ marginRight: 5 }}>{flag}</span>}
        {geo.countryCode ?? "—"}
      </span>
      <span style={{ fontSize: 11, color: "var(--text-secondary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", paddingLeft: 8 }} title={geo.asnOrg}>
        {geo.asnOrg ?? geo.city ?? "—"}
      </span>
      <span style={{ fontSize: 10, fontFamily: "monospace", color: "var(--text-secondary)", textAlign: "right" }}>
        {geo.asn ? `AS${geo.asn}` : ""}
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// IpView
// ---------------------------------------------------------------------------

const PAGE_SIZE = 100;
const BATCH_SIZE = 5;
const SORT_OPTIONS = [
  { value: "events", label: "Most Events" },
  { value: "country", label: "Country A–Z" },
  { value: "asn", label: "ASN" },
];

interface IpViewProps {
  startMs?: number;
  endMs?: number;
}

export function IpView({ startMs, endMs }: IpViewProps) {
  const [mmdbLoaded, setMmdbLoaded] = useState(false);
  const [showGeoLoader, setShowGeoLoader] = useState(false);
  const [page, setPage] = useState<IpPage | null>(null);
  const [currentPage, setCurrentPage] = useState(0);
  const [sortBy, setSortBy] = useState("events");
  const [filterCountry, setFilterCountry] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedIp, setSelectedIp] = useState<string | null>(null);

  // Online geo cache — auto-populated for each page
  const [onlineGeoCache, setOnlineGeoCache] = useState<Record<string, OnlineGeoResult>>({});
  const [geoFetching, setGeoFetching] = useState(false);
  const [geoError, setGeoError] = useState<string | null>(null);

  // AbuseIPDB cache
  const [abuseApiKey, setAbuseApiKey] = useState(() => localStorage.getItem("trailinspector_abuseipdb_key") ?? "");
  const [abuseCache, setAbuseCache] = useState<Record<string, AbuseCheckResult>>({});
  const [abuseCacheErrors, setAbuseCacheErrors] = useState<Record<string, string>>({});
  const [abuseSingleLoading, setAbuseSingleLoading] = useState(false);
  const [checkAllProgress, setCheckAllProgress] = useState<{ done: number; total: number } | null>(null);

  const fetchOnlineGeo = useCallback(async (ips: string[]) => {
    if (ips.length === 0) return;
    // Only fetch IPs not already cached
    const missing = ips.filter((ip) => !onlineGeoCache[ip]);
    if (missing.length === 0) return;
    setGeoFetching(true);
    setGeoError(null);
    try {
      const results = await geoLookupOnline(missing);
      const newEntries: Record<string, OnlineGeoResult> = {};
      for (const r of results) {
        newEntries[r.query] = r;
      }
      setOnlineGeoCache((prev) => ({ ...prev, ...newEntries }));
    } catch (e) {
      setGeoError(String(e));
    } finally {
      setGeoFetching(false);
    }
  }, [onlineGeoCache]);

  const load = useCallback(async (pg: number, sort: string, country: string) => {
    setLoading(true);
    setError(null);
    try {
      const result = await listIps(pg, PAGE_SIZE, sort, country || undefined, startMs, endMs);
      setPage(result);
      setCurrentPage(pg);
      // Auto-fetch online geo for the new page
      fetchOnlineGeo(result.rows.map((r) => r.ip));
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [startMs, endMs, fetchOnlineGeo]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleMmdbLoaded = useCallback(() => {
    setMmdbLoaded(true);
    setShowGeoLoader(false);
    load(0, sortBy, filterCountry);
  }, [load, sortBy, filterCountry]);

  useEffect(() => {
    load(0, sortBy, filterCountry);
  }, [startMs, endMs]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleSort = (sort: string) => {
    setSortBy(sort);
    load(0, sort, filterCountry);
  };

  const handleFilter = () => load(0, sortBy, filterCountry);

  const saveAbuseKey = (key: string) => {
    setAbuseApiKey(key);
    localStorage.setItem("trailinspector_abuseipdb_key", key);
  };

  const checkSingle = async (ip: string) => {
    if (!ip || !abuseApiKey.trim()) return;
    setAbuseSingleLoading(true);
    setAbuseCacheErrors((prev) => { const n = { ...prev }; delete n[ip]; return n; });
    try {
      const result = await checkAbuseIpdb(abuseApiKey.trim(), ip);
      setAbuseCache((prev) => ({ ...prev, [ip]: result }));
    } catch (e) {
      setAbuseCacheErrors((prev) => ({ ...prev, [ip]: String(e) }));
    } finally {
      setAbuseSingleLoading(false);
    }
  };

  const checkAll = async () => {
    if (!abuseApiKey.trim() || !page?.rows.length || checkAllProgress) return;
    const unchecked = page.rows.map((r) => r.ip).filter((ip) => !abuseCache[ip]);
    if (!unchecked.length) return;

    setCheckAllProgress({ done: 0, total: unchecked.length });

    for (let i = 0; i < unchecked.length; i += BATCH_SIZE) {
      const batch = unchecked.slice(i, i + BATCH_SIZE);
      const results = await Promise.allSettled(
        batch.map((ip) => checkAbuseIpdb(abuseApiKey.trim(), ip))
      );
      const newHits: Record<string, AbuseCheckResult> = {};
      const newErrs: Record<string, string> = {};
      results.forEach((r, idx) => {
        const ip = batch[idx];
        if (r.status === "fulfilled") newHits[ip] = r.value;
        else newErrs[ip] = String(r.reason);
      });
      setAbuseCache((prev) => ({ ...prev, ...newHits }));
      setAbuseCacheErrors((prev) => ({ ...prev, ...newErrs }));
      setCheckAllProgress((prev) =>
        prev ? { done: Math.min(prev.done + batch.length, prev.total), total: prev.total } : null
      );
    }
    setCheckAllProgress(null);
  };

  const totalPages = page ? Math.ceil(page.total / PAGE_SIZE) : 0;
  const selectedRow = page?.rows.find((r) => r.ip === selectedIp) ?? null;
  const uncheckedCount = page?.rows.filter((r) => !abuseCache[r.ip]).length ?? 0;

  return (
    <div style={{ display: "flex", height: "100%", overflow: "hidden", flexDirection: "column" }}>
      {/* Header */}
      <div style={{ padding: "6px 14px", borderBottom: "1px solid var(--border)", background: "var(--bg-secondary)", display: "flex", alignItems: "center", gap: 10, flexShrink: 0 }}>
        <span style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--text-secondary)" }}>
          IP ADDRESSES
        </span>
        {page && (
          <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>
            {page.total.toLocaleString()} unique IPs
          </span>
        )}

        {/* Online geo status indicator */}
        {geoFetching ? (
          <span style={{ fontSize: 10, color: "var(--text-secondary)", background: "var(--bg-tertiary)", border: "1px solid var(--border)", borderRadius: 3, padding: "1px 8px" }}>
            Fetching geo…
          </span>
        ) : geoError ? (
          <span title={geoError} style={{ fontSize: 10, color: "#f85149", background: "rgba(248,81,73,0.08)", border: "1px solid rgba(248,81,73,0.3)", borderRadius: 3, padding: "1px 8px", cursor: "help" }}>
            Geo offline
          </span>
        ) : null}

        <div style={{ flex: 1 }} />

        {/* Check All button */}
        {abuseApiKey && page && page.rows.length > 0 && (
          <button
            onClick={checkAll}
            disabled={!!checkAllProgress || uncheckedCount === 0}
            title={uncheckedCount === 0 ? "All IPs on this page are already checked" : `Check ${uncheckedCount} unchecked IPs against AbuseIPDB`}
            style={{
              background: checkAllProgress || uncheckedCount === 0 ? "var(--bg-tertiary)" : "rgba(248,190,52,0.12)",
              border: `1px solid ${checkAllProgress || uncheckedCount === 0 ? "var(--border)" : "rgba(248,190,52,0.5)"}`,
              borderRadius: 3, color: checkAllProgress || uncheckedCount === 0 ? "var(--text-secondary)" : "#f8be34",
              fontSize: 11, fontWeight: 600, padding: "3px 10px",
              cursor: checkAllProgress || uncheckedCount === 0 ? "default" : "pointer",
              opacity: checkAllProgress || uncheckedCount === 0 ? 0.6 : 1,
            }}
          >
            {checkAllProgress
              ? `Checking… ${checkAllProgress.done}/${checkAllProgress.total}`
              : uncheckedCount === 0 ? "All Checked" : `Check All (${uncheckedCount})`}
          </button>
        )}

        {/* Country filter */}
        <input
          value={filterCountry}
          onChange={(e) => setFilterCountry(e.target.value.toUpperCase().slice(0, 2))}
          onKeyDown={(e) => e.key === "Enter" && handleFilter()}
          placeholder="CC"
          maxLength={2}
          title="Filter by 2-letter country code (requires MMDB)"
          style={{ width: 48, background: "var(--bg-tertiary)", border: "1px solid var(--border)", borderRadius: 3, color: "var(--text-primary)", fontSize: 11, padding: "3px 6px", outline: "none", fontFamily: "monospace", textTransform: "uppercase" }}
        />

        {/* Sort */}
        <select
          value={sortBy}
          onChange={(e) => handleSort(e.target.value)}
          style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border)", borderRadius: 3, color: "var(--text-secondary)", fontSize: 11, padding: "2px 4px", cursor: "pointer" }}
        >
          {SORT_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>

        {/* MMDB optional button */}
        <button
          onClick={() => setShowGeoLoader((v) => !v)}
          style={{
            background: mmdbLoaded ? "rgba(101,166,55,0.15)" : showGeoLoader ? "rgba(60,149,209,0.15)" : "var(--bg-tertiary)",
            border: `1px solid ${mmdbLoaded ? "rgba(101,166,55,0.4)" : showGeoLoader ? "var(--accent-blue)" : "var(--border)"}`,
            borderRadius: 3,
            color: mmdbLoaded ? "#65a637" : showGeoLoader ? "var(--accent-blue)" : "var(--text-secondary)",
            fontSize: 11, padding: "3px 10px", cursor: "pointer",
          }}
          title="Load local MMDB files for offline/higher-accuracy geo data"
        >
          {mmdbLoaded ? "MMDB Loaded" : "Load MMDB…"}
        </button>
      </div>

      {/* Content area */}
      <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
        {/* Table */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
          {/* Column headers */}
          <div style={{ display: "grid", gridTemplateColumns: GRID_COLS, gap: 0, padding: "4px 14px", borderBottom: "1px solid var(--border)", background: "var(--bg-secondary)", flexShrink: 0 }}>
            {["IP ADDRESS", "SCORE", "EVENTS", "COUNTRY", "ORG / ISP", "ASN"].map((h) => (
              <span key={h} style={{ fontSize: 10, fontWeight: 700, color: "var(--text-secondary)", letterSpacing: "0.05em" }}>{h}</span>
            ))}
          </div>

          {error && (
            <div style={{ margin: "8px 14px", padding: "6px 10px", background: "rgba(248,81,73,0.1)", border: "1px solid rgba(248,81,73,0.3)", borderRadius: 4, fontSize: 11, color: "#f85149" }}>
              {error}
            </div>
          )}

          {loading ? (
            <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-secondary)", fontSize: 12 }}>Loading…</div>
          ) : (
            <div style={{ flex: 1, overflowY: "auto" }}>
              {page?.rows.map((row) => (
                <IpTableRow
                  key={row.ip}
                  row={row}
                  isSelected={selectedIp === row.ip}
                  onClick={() => setSelectedIp((prev) => prev === row.ip ? null : row.ip)}
                  geo={mergeGeo(row, onlineGeoCache[row.ip])}
                  abuseScore={abuseCache[row.ip]?.abuseConfidenceScore ?? null}
                />
              ))}
              {(!page || page.total === 0) && !loading && (
                <div style={{ padding: 40, textAlign: "center", fontSize: 12, color: "var(--text-secondary)" }}>
                  {page ? "No IPs found" : "Load a dataset to see IP addresses"}
                </div>
              )}
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8, padding: "6px 14px", borderTop: "1px solid var(--border)", background: "var(--bg-secondary)", flexShrink: 0 }}>
              <button onClick={() => load(currentPage - 1, sortBy, filterCountry)} disabled={currentPage === 0} style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border)", borderRadius: 3, color: currentPage === 0 ? "var(--text-dimmed)" : "var(--text-primary)", fontSize: 11, padding: "2px 8px", cursor: currentPage === 0 ? "default" : "pointer" }}>
                ‹ Prev
              </button>
              <span style={{ fontSize: 10, color: "var(--text-secondary)" }}>{currentPage + 1} / {totalPages}</span>
              <button onClick={() => load(currentPage + 1, sortBy, filterCountry)} disabled={currentPage >= totalPages - 1} style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border)", borderRadius: 3, color: currentPage >= totalPages - 1 ? "var(--text-dimmed)" : "var(--text-primary)", fontSize: 11, padding: "2px 8px", cursor: currentPage >= totalPages - 1 ? "default" : "pointer" }}>
                Next ›
              </button>
            </div>
          )}
        </div>

        {/* Right panel */}
        <div style={{ width: 280, flexShrink: 0, borderLeft: "1px solid var(--border)", background: "var(--bg-secondary)", overflowY: "auto" }}>
          {showGeoLoader ? (
            <GeoIpLoader onLoaded={handleMmdbLoaded} onCancel={() => setShowGeoLoader(false)} />
          ) : selectedRow ? (
            <IpDetail
              row={selectedRow}
              geo={mergeGeo(selectedRow, onlineGeoCache[selectedRow.ip])}
              abuseApiKey={abuseApiKey}
              onSaveAbuseKey={saveAbuseKey}
              onCheckAbuse={() => checkSingle(selectedRow.ip)}
              abuseResult={abuseCache[selectedRow.ip] ?? null}
              abuseLoading={abuseSingleLoading}
              abuseError={abuseCacheErrors[selectedRow.ip] ?? null}
            />
          ) : (
            <div style={{ padding: 20, textAlign: "center", fontSize: 11, color: "var(--text-secondary)", paddingTop: 48 }}>
              <div>Select an IP to view details</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// IP detail panel
// ---------------------------------------------------------------------------

interface IpDetailProps {
  row: IpRow;
  geo: MergedGeo;
  abuseApiKey: string;
  onSaveAbuseKey: (key: string) => void;
  onCheckAbuse: () => void;
  abuseResult: AbuseCheckResult | null;
  abuseLoading: boolean;
  abuseError: string | null;
}

function IpDetail({ row, geo, abuseApiKey, onSaveAbuseKey, onCheckAbuse, abuseResult, abuseLoading, abuseError }: IpDetailProps) {
  const flag = countryFlag(geo.countryCode);
  return (
    <div style={{ padding: 16 }}>
      <div style={{ fontSize: 14, fontWeight: 700, fontFamily: "monospace", color: "#58a6ff", marginBottom: 12 }}>
        {row.ip}
      </div>
      <DetailRow label="Events" value={row.eventCount.toLocaleString()} />
      {geo.countryCode && (
        <DetailRow label="Country" value={`${flag} ${geo.countryCode}${geo.countryName ? ` — ${geo.countryName}` : ""}`} />
      )}
      {geo.city && <DetailRow label="City" value={geo.city} />}
      {geo.isp && geo.isp !== geo.asnOrg && <DetailRow label="ISP" value={geo.isp} />}
      {geo.asn && <DetailRow label="ASN" value={`AS${geo.asn}`} mono />}
      {geo.asnOrg && <DetailRow label="Org" value={geo.asnOrg} />}

      <AbusePanel
        ip={row.ip}
        apiKey={abuseApiKey}
        onSaveKey={onSaveAbuseKey}
        result={abuseResult}
        loading={abuseLoading}
        error={abuseError}
        onCheck={onCheckAbuse}
      />
    </div>
  );
}

function DetailRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", padding: "5px 0", borderBottom: "1px solid var(--border)", gap: 8 }}>
      <span style={{ fontSize: 11, color: "var(--text-secondary)", flexShrink: 0 }}>{label}</span>
      <span style={{ fontSize: 11, color: "var(--text-primary)", fontFamily: mono ? "monospace" : undefined, textAlign: "right", wordBreak: "break-all" }}>
        {value}
      </span>
    </div>
  );
}
