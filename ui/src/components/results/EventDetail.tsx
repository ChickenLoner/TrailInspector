import { useState, useEffect } from "react";
import type { RecordRow, IpInfo } from "../../types/cloudtrail";
import { lookupIp } from "../../lib/tauri";

function countryFlag(code?: string): string {
  if (!code || code.length !== 2) return "";
  const base = 0x1F1E6 - 65;
  return String.fromCodePoint(base + code.toUpperCase().charCodeAt(0))
    + String.fromCodePoint(base + code.toUpperCase().charCodeAt(1));
}

interface Props {
  record: RecordRow | null;
  onClose: () => void;
}

export function EventDetail({ record, onClose }: Props) {
  const [geoInfo, setGeoInfo] = useState<IpInfo | null>(null);

  useEffect(() => {
    setGeoInfo(null);
    if (record?.sourceIPAddress) {
      lookupIp(record.sourceIPAddress).then(setGeoInfo).catch(() => {});
    }
  }, [record?.sourceIPAddress]);

  if (!record) return null;

  const flag = countryFlag(geoInfo?.countryCode);
  const geoLabel = geoInfo
    ? [
        flag ? `${flag} ` : "",
        geoInfo.countryName ?? geoInfo.countryCode ?? "",
        geoInfo.city ? `, ${geoInfo.city}` : "",
        geoInfo.asnOrg ? ` · ${geoInfo.asnOrg}` : "",
      ].join("")
    : null;

  return (
    <div
      className="flex flex-col"
      style={{
        width: 420,
        minWidth: 420,
        background: 'var(--bg-secondary)',
        borderLeft: '1px solid var(--border)',
      }}
    >
      {/* Header */}
      <div
        className="flex items-center justify-between px-3 flex-shrink-0"
        style={{ height: 36, borderBottom: '1px solid var(--border)' }}
      >
        <span className="text-xs font-semibold" style={{ color: 'var(--text-bright)' }}>
          {record.eventName}
        </span>
        <button
          onClick={onClose}
          className="text-xs px-2 py-0.5 rounded"
          style={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border)', color: 'var(--text-secondary)', cursor: 'pointer' }}
        >
          ✕
        </button>
      </div>

      {/* Summary fields */}
      <div className="px-3 py-2 flex-shrink-0" style={{ borderBottom: '1px solid var(--border)' }}>
        <Field label="Time" value={record.eventTime} />
        <Field label="Source" value={record.eventSource} />
        <Field label="Region" value={record.awsRegion} />
        <Field label="User" value={record.userName ?? record.userArn ?? "—"} />
        <Field label="IP" value={record.sourceIPAddress ?? "—"} />
        {geoLabel && <Field label="Geo" value={geoLabel} />}
        {record.errorCode && <Field label="Error" value={record.errorCode} error />}
      </div>

      {/* Raw JSON */}
      <div className="flex-1 overflow-auto p-3">
        <p className="text-xs mb-2" style={{ color: 'var(--text-secondary)' }}>Raw Event</p>
        <pre
          className="text-xs rounded p-2 overflow-auto"
          style={{
            background: 'var(--bg-primary)',
            border: '1px solid var(--border)',
            color: 'var(--text-primary)',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-all',
          }}
        >
          {JSON.stringify(record.raw, null, 2)}
        </pre>
      </div>
    </div>
  );
}

function Field({ label, value, error }: { label: string; value: string; error?: boolean }) {
  return (
    <div className="flex gap-2 mb-1 text-xs">
      <span className="flex-shrink-0" style={{ width: 60, color: 'var(--text-secondary)' }}>{label}</span>
      <span style={{ color: error ? 'var(--accent-red)' : 'var(--text-primary)', wordBreak: 'break-all' }}>{value}</span>
    </div>
  );
}
