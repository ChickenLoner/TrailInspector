import { useState, useEffect } from "react";
import { getS3Summary } from "../../lib/tauri";
import type { S3Summary, BucketStat, ObjectStat, IdentityStat } from "../../types/cloudtrail";

// ---------------------------------------------------------------------------
// Byte formatting
// ---------------------------------------------------------------------------

type ByteUnit = "B" | "KB" | "MB" | "GB";
const BYTE_DIVISORS: Record<ByteUnit, number> = { B: 1, KB: 1024, MB: 1024 * 1024, GB: 1024 * 1024 * 1024 };

function formatBytes(b: number, unit: ByteUnit): string {
  if (unit === "B") return `${b.toLocaleString()} B`;
  return `${(b / BYTE_DIVISORS[unit]).toFixed(2)} ${unit}`;
}

function autoUnit(b: number): ByteUnit {
  if (b >= 1024 * 1024 * 1024) return "GB";
  if (b >= 1024 * 1024) return "MB";
  if (b >= 1024) return "KB";
  return "B";
}

// ---------------------------------------------------------------------------
// Shared primitives
// ---------------------------------------------------------------------------

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <div style={{
      background: "var(--bg-secondary)", border: "1px solid var(--border)",
      borderRadius: 8, padding: "12px 16px", minWidth: 140, flex: 1,
    }}>
      <div style={{ fontSize: 11, color: "var(--text-secondary)", marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 18, fontWeight: 700, color: "var(--text-primary)", fontVariantNumeric: "tabular-nums" }}>
        {value}
      </div>
    </div>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return (
    <th style={{
      textAlign: "left", padding: "6px 10px", fontSize: 11, fontWeight: 600,
      color: "var(--text-secondary)", borderBottom: "1px solid var(--border)", whiteSpace: "nowrap",
    }}>
      {children}
    </th>
  );
}

function Td({ children, title }: { children: React.ReactNode; title?: string }) {
  return (
    <td title={title} style={{
      padding: "5px 10px", fontSize: 12, color: "var(--text-primary)",
      borderBottom: "1px solid var(--border)", maxWidth: 320,
      overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
    }}>
      {children}
    </td>
  );
}

function FilterSelect({ id, label, value, onChange, options, placeholder }: {
  id: string; label: string; value: string;
  onChange: (v: string) => void; options: string[]; placeholder: string;
}) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
      <label htmlFor={id} style={{ fontSize: 12, color: "var(--text-secondary)", whiteSpace: "nowrap" }}>
        {label}
      </label>
      <select
        id={id}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        style={{
          background: "var(--bg-secondary)", border: "1px solid var(--border)",
          borderRadius: 4, color: "var(--text-primary)", fontSize: 12,
          padding: "3px 6px", cursor: "pointer", minWidth: 180, maxWidth: 280,
        }}
      >
        <option value="">{placeholder}</option>
        {options.map((o) => <option key={o} value={o}>{o}</option>)}
      </select>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{
      background: "var(--bg-secondary)", border: "1px solid var(--border)",
      borderRadius: 8, padding: "12px 16px", marginBottom: 12,
    }}>
      <div style={{
        fontSize: 12, fontWeight: 700, color: "var(--text-secondary)",
        marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.05em",
      }}>
        {title}
      </div>
      {children}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

function BucketsTable({ rows, unit }: { rows: BucketStat[]; unit: ByteUnit }) {
  if (rows.length === 0) return <div style={{ color: "var(--text-secondary)", fontSize: 12, padding: "8px 0" }}>No bucket data.</div>;
  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead><tr><Th>Bucket</Th><Th>Bytes Out</Th><Th>Objects</Th><Th>Top Identity</Th></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.bucket}>
              <Td title={r.bucket}>{r.bucket}</Td>
              <Td>{formatBytes(r.bytesOut, unit)}</Td>
              <Td>{r.objectCount.toLocaleString()}</Td>
              <Td title={r.topIdentity}>{r.topIdentity || "—"}</Td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function IdentitiesTable({ rows, unit }: { rows: IdentityStat[]; unit: ByteUnit }) {
  if (rows.length === 0) return <div style={{ color: "var(--text-secondary)", fontSize: 12, padding: "8px 0" }}>No identity data.</div>;
  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead><tr><Th>Identity</Th><Th>Bytes Out</Th><Th>Objects</Th><Th>Unique Buckets</Th></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.identity}>
              <Td title={r.identity}>{r.identity}</Td>
              <Td>{formatBytes(r.bytesOut, unit)}</Td>
              <Td>{r.objectCount.toLocaleString()}</Td>
              <Td>{r.uniqueBuckets}</Td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function TopObjectsTable({ rows, total, unit }: { rows: ObjectStat[]; total: number; unit: ByteUnit }) {
  if (rows.length === 0) return <div style={{ color: "var(--text-secondary)", fontSize: 12, padding: "8px 0" }}>No object data.</div>;
  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead><tr><Th>Object Key</Th><Th>Bucket</Th><Th>Bytes Out</Th><Th>Access Count</Th></tr></thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i}>
              <Td title={`${r.bucket}/${r.key}`}>{r.key || "—"}</Td>
              <Td title={r.bucket}>{r.bucket}</Td>
              <Td>{formatBytes(r.bytesOut, unit)}</Td>
              <Td>{r.accessCount.toLocaleString()}</Td>
            </tr>
          ))}
        </tbody>
      </table>
      {total > rows.length && (
        <div style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 6, paddingLeft: 4 }}>
          Showing top {rows.length.toLocaleString()} of {total.toLocaleString()} unique objects
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

interface Props {
  startMs?: number;
  endMs?: number;
}

export function S3View({ startMs, endMs }: Props) {
  const [summary, setSummary] = useState<S3Summary | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedBucket, setSelectedBucket] = useState("");
  const [selectedIp, setSelectedIp] = useState("");
  const [selectedIdentity, setSelectedIdentity] = useState("");
  const [unit, setUnit] = useState<ByteUnit | "auto">("auto");

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    getS3Summary(startMs, endMs, selectedBucket || undefined, selectedIp || undefined, selectedIdentity || undefined)
      .then((data) => { if (!cancelled) { setSummary(data); setLoading(false); } })
      .catch((err) => { if (!cancelled) { setError(String(err)); setLoading(false); } });

    return () => { cancelled = true; };
  }, [startMs, endMs, selectedBucket, selectedIp, selectedIdentity]);

  const effectiveUnit: ByteUnit = unit === "auto"
    ? autoUnit(summary?.totalBytesOut ?? 0)
    : unit;

  return (
    <div style={{
      height: "100%", overflowY: "auto", padding: 16,
      background: "var(--bg-primary)", color: "var(--text-primary)", fontFamily: "inherit",
    }}>
      <div style={{ maxWidth: 1100, margin: "0 auto" }}>

        {/* Header */}
        <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 14, color: "var(--accent-green)" }}>
          S3 Activity
        </div>

        {loading && <div style={{ color: "var(--text-secondary)", fontSize: 13 }}>Loading S3 data...</div>}
        {error && <div style={{ color: "#f87171", fontSize: 13, marginBottom: 10 }}>Error: {error}</div>}

        {!loading && !error && summary && summary.totalGetObjects === 0 && (
          <div style={{ color: "var(--text-secondary)", fontSize: 13 }}>
            No S3 GetObject events found in the loaded dataset.
          </div>
        )}

        {!loading && !error && summary && summary.totalGetObjects > 0 && (
          <>
            {/* Stat cards */}
            <div style={{ display: "flex", gap: 10, marginBottom: 14, flexWrap: "wrap" }}>
              <StatCard label="Total Bytes Out" value={formatBytes(summary.totalBytesOut, effectiveUnit)} />
              <StatCard label="Objects Accessed" value={summary.totalGetObjects.toLocaleString()} />
              <StatCard label="Unique Buckets" value={summary.buckets.length.toLocaleString()} />
              <StatCard label="Identities" value={summary.identities.length.toLocaleString()} />
            </div>

            {/* Filters + unit toggle row */}
            <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 14, flexWrap: "wrap" }}>
              <FilterSelect
                id="s3-bucket-filter" label="Bucket:"
                value={selectedBucket} onChange={setSelectedBucket}
                options={summary.availableBuckets} placeholder="All Buckets"
              />
              <FilterSelect
                id="s3-ip-filter" label="Source IP:"
                value={selectedIp} onChange={setSelectedIp}
                options={summary.availableIps} placeholder="All IPs"
              />
              <FilterSelect
                id="s3-identity-filter" label="Identity:"
                value={selectedIdentity} onChange={setSelectedIdentity}
                options={summary.availableIdentities} placeholder="All Identities"
              />

              {/* Byte unit toggle */}
              <div style={{ display: "flex", alignItems: "center", gap: 4, marginLeft: "auto" }}>
                <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>Unit:</span>
                {(["auto", "B", "KB", "MB", "GB"] as const).map((u) => (
                  <button
                    key={u}
                    onClick={() => setUnit(u)}
                    style={{
                      padding: "2px 7px", fontSize: 11, fontWeight: 600,
                      borderRadius: 3, cursor: "pointer",
                      border: "1px solid var(--border)",
                      background: unit === u ? "var(--accent-green)" : "var(--bg-secondary)",
                      color: unit === u ? "#fff" : "var(--text-secondary)",
                    }}
                  >
                    {u}
                  </button>
                ))}
              </div>
            </div>

            {/* Buckets */}
            <Section title="Buckets">
              <BucketsTable rows={summary.buckets} unit={effectiveUnit} />
            </Section>

            {/* Identities — above Top Objects per user request */}
            <Section title="Identities">
              <IdentitiesTable rows={summary.identities} unit={effectiveUnit} />
            </Section>

            {/* Top Objects */}
            <Section title={`Top Objects${summary.uniqueObjects > 100 ? ` (top 100 of ${summary.uniqueObjects.toLocaleString()})` : ""}`}>
              <TopObjectsTable rows={summary.topObjects} total={summary.uniqueObjects} unit={effectiveUnit} />
            </Section>
          </>
        )}
      </div>
    </div>
  );
}
