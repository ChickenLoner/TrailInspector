import { useState, useEffect } from "react";
import { getS3Summary } from "../../lib/tauri";
import type { S3Summary, BucketStat, ObjectStat, IdentityStat } from "../../types/cloudtrail";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatBytes(b: number): string {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1024 * 1024 * 1024) return `${(b / (1024 * 1024)).toFixed(1)} MB`;
  return `${(b / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

// ---------------------------------------------------------------------------
// Stat card
// ---------------------------------------------------------------------------

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <div
      style={{
        background: "var(--bg-secondary)",
        border: "1px solid var(--border)",
        borderRadius: 8,
        padding: "12px 16px",
        minWidth: 140,
        flex: 1,
      }}
    >
      <div style={{ fontSize: 11, color: "var(--text-secondary)", marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 18, fontWeight: 700, color: "var(--text-primary)", fontVariantNumeric: "tabular-nums" }}>
        {value}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Table helpers
// ---------------------------------------------------------------------------

function Th({ children }: { children: React.ReactNode }) {
  return (
    <th
      style={{
        textAlign: "left",
        padding: "6px 10px",
        fontSize: 11,
        fontWeight: 600,
        color: "var(--text-secondary)",
        borderBottom: "1px solid var(--border)",
        whiteSpace: "nowrap",
      }}
    >
      {children}
    </th>
  );
}

function Td({ children, title }: { children: React.ReactNode; title?: string }) {
  return (
    <td
      title={title}
      style={{
        padding: "5px 10px",
        fontSize: 12,
        color: "var(--text-primary)",
        borderBottom: "1px solid var(--border)",
        maxWidth: 280,
        overflow: "hidden",
        textOverflow: "ellipsis",
        whiteSpace: "nowrap",
      }}
    >
      {children}
    </td>
  );
}

// ---------------------------------------------------------------------------
// Sub-tables
// ---------------------------------------------------------------------------

function BucketsTable({ rows }: { rows: BucketStat[] }) {
  if (rows.length === 0) return <div style={{ color: "var(--text-secondary)", fontSize: 12, padding: "8px 0" }}>No bucket data.</div>;
  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr>
            <Th>Bucket</Th>
            <Th>Bytes Out</Th>
            <Th>Objects</Th>
            <Th>Top Identity</Th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.bucket} style={{ cursor: "default" }}>
              <Td title={r.bucket}>{r.bucket}</Td>
              <Td>{formatBytes(r.bytesOut)}</Td>
              <Td>{r.objectCount.toLocaleString()}</Td>
              <Td title={r.topIdentity}>{r.topIdentity || "—"}</Td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function TopObjectsTable({ rows }: { rows: ObjectStat[] }) {
  if (rows.length === 0) return <div style={{ color: "var(--text-secondary)", fontSize: 12, padding: "8px 0" }}>No object data.</div>;
  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr>
            <Th>Object Key</Th>
            <Th>Bucket</Th>
            <Th>Bytes Out</Th>
            <Th>Access Count</Th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} style={{ cursor: "default" }}>
              <Td title={r.key}>{r.key || "—"}</Td>
              <Td title={r.bucket}>{r.bucket}</Td>
              <Td>{formatBytes(r.bytesOut)}</Td>
              <Td>{r.accessCount.toLocaleString()}</Td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function IdentitiesTable({ rows }: { rows: IdentityStat[] }) {
  if (rows.length === 0) return <div style={{ color: "var(--text-secondary)", fontSize: 12, padding: "8px 0" }}>No identity data.</div>;
  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr>
            <Th>Identity</Th>
            <Th>Bytes Out</Th>
            <Th>Objects</Th>
            <Th>Unique Buckets</Th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.identity} style={{ cursor: "default" }}>
              <Td title={r.identity}>{r.identity}</Td>
              <Td>{formatBytes(r.bytesOut)}</Td>
              <Td>{r.objectCount.toLocaleString()}</Td>
              <Td>{r.uniqueBuckets}</Td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Section wrapper
// ---------------------------------------------------------------------------

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div
      style={{
        background: "var(--bg-secondary)",
        border: "1px solid var(--border)",
        borderRadius: 8,
        padding: "12px 16px",
        marginBottom: 12,
      }}
    >
      <div
        style={{
          fontSize: 12,
          fontWeight: 700,
          color: "var(--text-secondary)",
          marginBottom: 8,
          textTransform: "uppercase",
          letterSpacing: "0.05em",
        }}
      >
        {title}
      </div>
      {children}
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
  const [selectedBucket, setSelectedBucket] = useState<string>("");

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    getS3Summary(startMs, endMs, selectedBucket || undefined)
      .then((data) => {
        if (!cancelled) {
          setSummary(data);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setError(String(err));
          setLoading(false);
        }
      });

    return () => { cancelled = true; };
  }, [startMs, endMs, selectedBucket]);

  return (
    <div
      style={{
        height: "100%",
        overflowY: "auto",
        padding: 16,
        background: "var(--bg-primary)",
        color: "var(--text-primary)",
        fontFamily: "inherit",
      }}
    >
      <div style={{ maxWidth: 1100, margin: "0 auto" }}>
        {/* Header */}
        <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 14, color: "var(--accent-green)" }}>
          S3 Activity
        </div>

        {loading && (
          <div style={{ color: "var(--text-secondary)", fontSize: 13 }}>Loading S3 data...</div>
        )}

        {error && (
          <div style={{ color: "#f87171", fontSize: 13, marginBottom: 10 }}>Error: {error}</div>
        )}

        {!loading && !error && summary && summary.totalGetObjects === 0 && (
          <div style={{ color: "var(--text-secondary)", fontSize: 13 }}>
            No S3 GetObject events found in the loaded dataset.
          </div>
        )}

        {!loading && !error && summary && summary.totalGetObjects > 0 && (
          <>
            {/* Stat cards */}
            <div style={{ display: "flex", gap: 10, marginBottom: 14, flexWrap: "wrap" }}>
              <StatCard label="Total Bytes Out" value={formatBytes(summary.totalBytesOut)} />
              <StatCard label="Objects Accessed" value={summary.totalGetObjects.toLocaleString()} />
              <StatCard label="Unique Buckets" value={summary.buckets.length.toLocaleString()} />
              <StatCard label="Identities" value={summary.identities.length.toLocaleString()} />
            </div>

            {/* Bucket filter */}
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}>
              <label
                htmlFor="s3-bucket-filter"
                style={{ fontSize: 12, color: "var(--text-secondary)", whiteSpace: "nowrap" }}
              >
                Bucket filter:
              </label>
              <select
                id="s3-bucket-filter"
                value={selectedBucket}
                onChange={(e) => setSelectedBucket(e.target.value)}
                style={{
                  background: "var(--bg-secondary)",
                  border: "1px solid var(--border)",
                  borderRadius: 4,
                  color: "var(--text-primary)",
                  fontSize: 12,
                  padding: "3px 6px",
                  cursor: "pointer",
                  minWidth: 200,
                }}
              >
                <option value="">All Buckets</option>
                {summary.availableBuckets.map((b) => (
                  <option key={b} value={b}>{b}</option>
                ))}
              </select>
            </div>

            {/* Buckets table */}
            <Section title="Buckets">
              <BucketsTable rows={summary.buckets} />
            </Section>

            {/* Top objects table */}
            <Section title={`Top Objects${summary.uniqueObjects > 100 ? ` (top 100 of ${summary.uniqueObjects.toLocaleString()})` : ""}`}>
              <TopObjectsTable rows={summary.topObjects} />
            </Section>

            {/* Identities table */}
            <Section title="Identities">
              <IdentitiesTable rows={summary.identities} />
            </Section>
          </>
        )}
      </div>
    </div>
  );
}
