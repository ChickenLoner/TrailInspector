import { useEffect, useState } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import type { BarRectangleItem } from "recharts/types/cartesian/Bar";
import { getTopFields } from "../../lib/tauri";
import type { FieldValueCount } from "../../types/cloudtrail";

const FIELDS = [
  { key: "eventName", label: "Event Name" },
  { key: "awsRegion", label: "AWS Region" },
  { key: "errorCode", label: "Error Code" },
  { key: "sourceIPAddress", label: "Source IP" },
  { key: "userArn", label: "User ARN" },
];

interface FieldBarProps {
  field: string;
  label: string;
  query?: string;
  onFilterSelect?: (field: string, value: string) => void;
}

function FieldBar({ field, label, query, onFilterSelect }: FieldBarProps) {
  const [values, setValues] = useState<FieldValueCount[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    getTopFields(field, query, 15)
      .then(setValues)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [field, query]);

  if (loading) {
    return (
      <div style={{ marginBottom: 16 }}>
        <div style={{ fontSize: 11, fontWeight: 600, color: "var(--text-secondary)", marginBottom: 4 }}>
          {label}
        </div>
        <div style={{ fontSize: 11, color: "var(--text-muted, #555)" }}>Loading…</div>
      </div>
    );
  }

  if (values.length === 0) {
    return (
      <div style={{ marginBottom: 16 }}>
        <div style={{ fontSize: 11, fontWeight: 600, color: "var(--text-secondary)", marginBottom: 4 }}>
          {label}
        </div>
        <div style={{ fontSize: 11, color: "var(--text-muted, #555)" }}>No data</div>
      </div>
    );
  }

  const maxCount = Math.max(...values.map((v) => v.count), 1);

  const CustomTooltip = ({
    active,
    payload,
  }: {
    active?: boolean;
    payload?: Array<{ payload: FieldValueCount }>;
  }) => {
    if (!active || !payload || payload.length === 0) return null;
    const { value, count } = payload[0].payload;
    return (
      <div
        style={{
          background: "var(--bg-secondary)",
          border: "1px solid var(--border)",
          padding: "4px 8px",
          borderRadius: 4,
          fontSize: 11,
          color: "var(--text-primary)",
          maxWidth: 300,
          wordBreak: "break-all",
        }}
      >
        <div style={{ fontWeight: 600 }}>{value}</div>
        <div style={{ color: "var(--accent-blue)" }}>{count.toLocaleString()}</div>
      </div>
    );
  };

  return (
    <div style={{ marginBottom: 20 }}>
      <div
        style={{
          fontSize: 11,
          fontWeight: 600,
          color: "var(--text-secondary)",
          marginBottom: 4,
          textTransform: "uppercase",
          letterSpacing: "0.05em",
        }}
      >
        {label}
      </div>
      <div style={{ height: values.length * 18 + 10 }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={values}
            layout="vertical"
            margin={{ top: 0, right: 8, left: 0, bottom: 0 }}
          >
            <XAxis type="number" hide domain={[0, maxCount]} />
            <YAxis
              type="category"
              dataKey="value"
              tick={{ fontSize: 10, fill: "var(--text-primary)" }}
              width={130}
              tickFormatter={(v: string) => (v.length > 18 ? v.slice(0, 16) + "…" : v)}
            />
            <Tooltip content={<CustomTooltip />} />
            <Bar
              dataKey="count"
              radius={[0, 2, 2, 0]}
              cursor="pointer"
              onClick={(item: BarRectangleItem) => {
                const row = item.payload as FieldValueCount;
                if (onFilterSelect && row) onFilterSelect(field, row.value);
              }}
            >
              {values.map((_, idx) => (
                <Cell key={idx} fill="var(--accent-blue)" fillOpacity={0.75} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

interface Props {
  query?: string;
  onFilterSelect?: (field: string, value: string) => void;
}

export function FieldStats({ query, onFilterSelect }: Props) {
  return (
    <div
      style={{
        padding: 12,
        overflowY: "auto",
        height: "100%",
        background: "var(--bg-primary)",
      }}
    >
      <div
        style={{
          fontSize: 12,
          fontWeight: 700,
          color: "var(--text-primary)",
          marginBottom: 12,
          borderBottom: "1px solid var(--border)",
          paddingBottom: 6,
        }}
      >
        Field Statistics
      </div>
      {FIELDS.map(({ key, label }) => (
        <FieldBar
          key={key}
          field={key}
          label={label}
          query={query}
          onFilterSelect={onFilterSelect}
        />
      ))}
    </div>
  );
}
