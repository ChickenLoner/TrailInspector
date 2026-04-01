import { useState, useEffect, useCallback } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { loadGeoipDb, listIps, checkAbuseIpdb } from "../../lib/tauri";
import type { IpPage, IpRow, AbuseCheckResult } from "../../types/cloudtrail";

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
// GeoIP loader panel (used inside the right panel when triggered)
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
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
        <div style={{ fontSize: 12, fontWeight: 700, color: "var(--text-primary)" }}>
          Load GeoIP Databases
        </div>
        <button
          onClick={onCancel}
          style={{
            background: "transparent",
            border: "none",
            color: "var(--text-secondary)",
            cursor: "pointer",
            fontSize: 16,
            lineHeight: 1,
            padding: 2,
          }}
          title="Cancel"
        >
          ×
        </button>
      </div>
      <div style={{ fontSize: 11, color: "var(--text-secondary)", marginBottom: 16, lineHeight: 1.5 }}>
        DB-IP Lite MMDB files — free, no registration.{" "}
        <span style={{ fontFamily: "monospace", color: "#58a6ff" }}>db-ip.com/db/lite</span>
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
          marginTop: 14,
          width: "100%",
          background: loading || (!geoPath && !asnPath) ? "var(--bg-tertiary)" : "var(--accent-blue)",
          border: "none",
          borderRadius: 4,
          color: loading || (!geoPath && !asnPath) ? "var(--text-secondary)" : "#0d1117",
          padding: "7px 0",
          fontSize: 12,
          fontWeight: 700,
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
// AbuseIPDB panel (inside IP detail)
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

  return (
    <div style={{ marginTop: 16, paddingTop: 12, borderTop: "1px solid var(--border)" }}>
      <div style={{ fontSize: 10, fontWeight: 700, color: "var(--text-secondary)", letterSpacing: "0.05em", textTransform: "uppercase", marginBottom: 8 }}>
        AbuseIPDB
      </div>

      {!apiKey ? (
        // No key — show input to set one
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
              style={{
                flex: 1, background: "var(--bg-tertiary)", border: "1px solid var(--border)", borderRadius: 3,
                color: "var(--text-primary)", fontSize: 11, padding: "3px 6px", outline: "none", fontFamily: "monospace",
              }}
            />
            <button
              onClick={() => keyInput.trim() && onSaveKey(keyInput.trim())}
              disabled={!keyInput.trim()}
              style={{
                background: keyInput.trim() ? "var(--accent-blue)" : "var(--bg-tertiary)",
                border: "none", borderRadius: 3, color: keyInput.trim() ? "#0d1117" : "var(--text-secondary)",
                fontSize: 11, fontWeight: 600, padding: "3px 8px", cursor: keyInput.trim() ? "pointer" : "default",
              }}
            >
              Save
            </button>
          </div>
        </div>
      ) : (
        // Key set — show check button and results
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
            <button
              onClick={onCheck}
              disabled={loading}
              style={{
                background: loading ? "var(--bg-tertiary)" : "var(--accent-blue)",
                border: "none", borderRadius: 3, color: loading ? "var(--text-secondary)" : "#0d1117",
                fontSize: 11, fontWeight: 600, padding: "4px 12px", cursor: loading ? "default" : "pointer",
                opacity: loading ? 0.7 : 1,
              }}
            >
              {loading ? "Checking…" : `Check ${ip}`}
            </button>
            <button
              onClick={() => { onSaveKey(""); setKeyInput(""); }}
              style={{ background: "transparent", border: "none", color: "var(--text-secondary)", fontSize: 10, cursor: "pointer", textDecoration: "underline" }}
              title="Remove API key"
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
                  <div style={{ fontSize: 10, fontWeight: 600, color: abuseColor(result.abuseConfidenceScore) }}>
                    Abuse Confidence
                  </div>
                  <div style={{ fontSize: 10, color: "var(--text-secondary)" }}>
                    {result.totalReports} report{result.totalReports !== 1 ? "s" : ""}
                  </div>
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
// IP table row
// ---------------------------------------------------------------------------

function IpTableRow({ row, isSelected, onClick }: { row: IpRow; isSelected: boolean; onClick: () => void }) {
  const flag = countryFlag(row.countryCode);
  return (
    <div
      onClick={onClick}
      style={{
        display: "grid",
        gridTemplateColumns: "180px 52px 120px 180px 70px",
        gap: 0,
        padding: "7px 14px",
        borderBottom: "1px solid var(--border)",
        background: isSelected ? "rgba(60,149,209,0.08)" : "var(--bg-primary)",
        borderLeft: isSelected ? "2px solid var(--accent-blue)" : "2px solid transparent",
        cursor: "pointer",
        alignItems: "center",
        transition: "background 0.1s",
      }}
    >
      <span style={{ fontSize: 12, fontFamily: "monospace", color: "#58a6ff" }}>{row.ip}</span>
      <span style={{ fontSize: 11, color: "var(--text-secondary)", textAlign: "right" }}>{row.eventCount.toLocaleString()}</span>
      <span style={{ fontSize: 11, color: "var(--text-primary)", paddingLeft: 14 }}>
        {flag && <span style={{ marginRight: 5 }}>{flag}</span>}
        {row.countryCode ?? "—"}
      </span>
      <span style={{ fontSize: 11, color: "var(--text-secondary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", paddingLeft: 8 }} title={row.asnOrg}>
        {row.asnOrg ?? row.city ?? "—"}
      </span>
      <span style={{ fontSize: 10, fontFamily: "monospace", color: "var(--text-secondary)", textAlign: "right" }}>
        {row.asn ? `AS${row.asn}` : ""}
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// IpView
// ---------------------------------------------------------------------------

const PAGE_SIZE = 100;
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
  const [geoLoaded, setGeoLoaded] = useState(false);
  const [showGeoLoader, setShowGeoLoader] = useState(false);
  const [page, setPage] = useState<IpPage | null>(null);
  const [currentPage, setCurrentPage] = useState(0);
  const [sortBy, setSortBy] = useState("events");
  const [filterCountry, setFilterCountry] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedIp, setSelectedIp] = useState<string | null>(null);

  // AbuseIPDB state
  const [abuseApiKey, setAbuseApiKey] = useState(() => localStorage.getItem("trailinspector_abuseipdb_key") ?? "");
  const [abuseResult, setAbuseResult] = useState<AbuseCheckResult | null>(null);
  const [abuseLoading, setAbuseLoading] = useState(false);
  const [abuseError, setAbuseError] = useState<string | null>(null);

  const load = useCallback(async (pg: number, sort: string, country: string) => {
    setLoading(true);
    setError(null);
    try {
      const result = await listIps(pg, PAGE_SIZE, sort, country || undefined, startMs, endMs);
      setPage(result);
      setCurrentPage(pg);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [startMs, endMs]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleGeoLoaded = useCallback(() => {
    setGeoLoaded(true);
    setShowGeoLoader(false);
    load(0, sortBy, filterCountry);
  }, [load, sortBy, filterCountry]);

  // Load IP list on mount and when time range changes (no GeoIP required)
  useEffect(() => {
    load(0, sortBy, filterCountry);
  }, [startMs, endMs]); // eslint-disable-line react-hooks/exhaustive-deps

  // Reset abuse state when selected IP changes
  useEffect(() => {
    setAbuseResult(null);
    setAbuseError(null);
  }, [selectedIp]);

  const handleSort = (sort: string) => {
    setSortBy(sort);
    load(0, sort, filterCountry);
  };

  const handleFilter = () => load(0, sortBy, filterCountry);

  const saveAbuseKey = (key: string) => {
    setAbuseApiKey(key);
    localStorage.setItem("trailinspector_abuseipdb_key", key);
    setAbuseResult(null);
    setAbuseError(null);
  };

  const checkAbuse = async () => {
    if (!selectedIp || !abuseApiKey.trim()) return;
    setAbuseLoading(true);
    setAbuseError(null);
    setAbuseResult(null);
    try {
      const result = await checkAbuseIpdb(abuseApiKey.trim(), selectedIp);
      setAbuseResult(result);
    } catch (e) {
      setAbuseError(String(e));
    } finally {
      setAbuseLoading(false);
    }
  };

  const totalPages = page ? Math.ceil(page.total / PAGE_SIZE) : 0;
  const selectedRow = page?.rows.find((r) => r.ip === selectedIp) ?? null;

  return (
    <div style={{ display: "flex", height: "100%", overflow: "hidden", flexDirection: "column" }}>
      {/* Header */}
      <div
        style={{
          padding: "6px 14px",
          borderBottom: "1px solid var(--border)",
          background: "var(--bg-secondary)",
          display: "flex",
          alignItems: "center",
          gap: 10,
          flexShrink: 0,
        }}
      >
        <span style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--text-secondary)" }}>
          IP ADDRESSES
        </span>
        {page && (
          <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>
            {page.total.toLocaleString()} unique IPs
          </span>
        )}
        {!geoLoaded && (
          <span style={{ fontSize: 10, color: "#f8be34", background: "rgba(248,190,52,0.1)", border: "1px solid rgba(248,190,52,0.3)", borderRadius: 3, padding: "1px 8px" }}>
            GeoIP not loaded
          </span>
        )}
        <div style={{ flex: 1 }} />

        {/* Country filter */}
        <input
          value={filterCountry}
          onChange={(e) => setFilterCountry(e.target.value.toUpperCase().slice(0, 2))}
          onKeyDown={(e) => e.key === "Enter" && handleFilter()}
          placeholder="CC"
          maxLength={2}
          title="Filter by 2-letter country code (e.g. US, TH)"
          style={{
            width: 48, background: "var(--bg-tertiary)", border: "1px solid var(--border)", borderRadius: 3,
            color: "var(--text-primary)", fontSize: 11, padding: "3px 6px", outline: "none",
            fontFamily: "monospace", textTransform: "uppercase",
          }}
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

        {/* GeoIP button */}
        <button
          onClick={() => setShowGeoLoader((v) => !v)}
          style={{
            background: geoLoaded ? "rgba(101,166,55,0.15)" : showGeoLoader ? "rgba(60,149,209,0.15)" : "var(--bg-tertiary)",
            border: `1px solid ${geoLoaded ? "rgba(101,166,55,0.4)" : showGeoLoader ? "var(--accent-blue)" : "var(--border)"}`,
            borderRadius: 3,
            color: geoLoaded ? "#65a637" : showGeoLoader ? "var(--accent-blue)" : "var(--text-secondary)",
            fontSize: 11, padding: "3px 10px", cursor: "pointer",
          }}
        >
          {geoLoaded ? "GeoIP Loaded" : "Load GeoIP…"}
        </button>
      </div>

      {/* Content area */}
      <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
        {/* Table */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
          {/* Column headers */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "180px 52px 120px 180px 70px",
              gap: 0, padding: "4px 14px",
              borderBottom: "1px solid var(--border)",
              background: "var(--bg-secondary)", flexShrink: 0,
            }}
          >
            {["IP ADDRESS", "EVENTS", "COUNTRY", "ORG / CITY", "ASN"].map((h) => (
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

        {/* Right panel: geo loader OR IP detail */}
        <div
          style={{
            width: 280, flexShrink: 0, borderLeft: "1px solid var(--border)",
            background: "var(--bg-secondary)", overflowY: "auto",
          }}
        >
          {showGeoLoader ? (
            <GeoIpLoader onLoaded={handleGeoLoaded} onCancel={() => setShowGeoLoader(false)} />
          ) : selectedRow ? (
            <IpDetail
              row={selectedRow}
              abuseApiKey={abuseApiKey}
              onSaveAbuseKey={saveAbuseKey}
              onCheckAbuse={checkAbuse}
              abuseResult={abuseResult}
              abuseLoading={abuseLoading}
              abuseError={abuseError}
            />
          ) : (
            <div style={{ padding: 20, textAlign: "center", fontSize: 11, color: "var(--text-secondary)", paddingTop: 48 }}>
              {!geoLoaded && (
                <div style={{ marginBottom: 20, padding: 12, background: "var(--bg-tertiary)", borderRadius: 6, border: "1px solid var(--border)" }}>
                  <div style={{ marginBottom: 6, fontSize: 11, color: "var(--text-secondary)" }}>
                    Add geo enrichment (country, city, ASN)
                  </div>
                  <button
                    onClick={() => setShowGeoLoader(true)}
                    style={{ background: "var(--bg-secondary)", border: "1px solid var(--border)", borderRadius: 4, color: "var(--text-primary)", fontSize: 11, padding: "5px 14px", cursor: "pointer" }}
                  >
                    Load GeoIP Files…
                  </button>
                </div>
              )}
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
  abuseApiKey: string;
  onSaveAbuseKey: (key: string) => void;
  onCheckAbuse: () => void;
  abuseResult: AbuseCheckResult | null;
  abuseLoading: boolean;
  abuseError: string | null;
}

function IpDetail({ row, abuseApiKey, onSaveAbuseKey, onCheckAbuse, abuseResult, abuseLoading, abuseError }: IpDetailProps) {
  const flag = countryFlag(row.countryCode);
  return (
    <div style={{ padding: 16 }}>
      <div style={{ fontSize: 14, fontWeight: 700, fontFamily: "monospace", color: "#58a6ff", marginBottom: 12 }}>
        {row.ip}
      </div>
      <DetailRow label="Events" value={row.eventCount.toLocaleString()} />
      {row.countryCode && (
        <DetailRow label="Country" value={`${flag} ${row.countryCode}${row.countryName ? ` — ${row.countryName}` : ""}`} />
      )}
      {row.city && <DetailRow label="City" value={row.city} />}
      {row.asn && <DetailRow label="ASN" value={`AS${row.asn}`} mono />}
      {row.asnOrg && <DetailRow label="Org" value={row.asnOrg} />}

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
