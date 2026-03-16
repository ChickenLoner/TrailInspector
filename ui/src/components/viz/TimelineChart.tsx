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
import type { TimeBucket } from "../../types/cloudtrail";

interface Props {
  buckets: TimeBucket[];
  onTimeRangeSelect?: (startMs: number, endMs: number) => void;
}

function formatLabel(ms: number, span: number): string {
  const d = new Date(ms);
  if (span <= 3_600_000) {
    // <= 1 hour → show HH:mm:ss
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } else if (span <= 86_400_000) {
    // <= 1 day → show HH:mm
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  } else if (span <= 7 * 86_400_000) {
    // <= 7 days → show month/day HH:mm
    return (
      d.toLocaleDateString([], { month: "short", day: "numeric" }) +
      " " +
      d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    );
  } else {
    // longer → show date only
    return d.toLocaleDateString([], { month: "short", day: "numeric", year: "2-digit" });
  }
}

export function TimelineChart({ buckets, onTimeRangeSelect }: Props) {
  if (!buckets || buckets.length === 0) {
    return (
      <div
        style={{
          height: 80,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          color: "var(--text-secondary)",
          fontSize: 12,
        }}
      >
        No timeline data
      </div>
    );
  }

  const span =
    buckets.length > 1
      ? buckets[buckets.length - 1].endMs - buckets[0].startMs
      : 0;

  const data = buckets.map((b) => ({
    label: formatLabel(b.startMs, span),
    count: b.count,
    startMs: b.startMs,
    endMs: b.endMs,
  }));

  const maxCount = Math.max(...buckets.map((b) => b.count), 1);

  const handleClick = (d: { startMs?: number; endMs?: number }) => {
    if (onTimeRangeSelect && d.startMs !== undefined && d.endMs !== undefined) {
      onTimeRangeSelect(d.startMs, d.endMs);
    }
  };

  // Custom tooltip
  const CustomTooltip = ({
    active,
    payload,
  }: {
    active?: boolean;
    payload?: Array<{ payload: { label: string; count: number } }>;
  }) => {
    if (!active || !payload || payload.length === 0) return null;
    const { label, count } = payload[0].payload;
    return (
      <div
        style={{
          background: "var(--bg-secondary)",
          border: "1px solid var(--border)",
          padding: "4px 8px",
          borderRadius: 4,
          fontSize: 11,
          color: "var(--text-primary)",
        }}
      >
        <div style={{ fontWeight: 600 }}>{label}</div>
        <div style={{ color: "var(--accent-blue)" }}>{count.toLocaleString()} events</div>
      </div>
    );
  };

  // Show only a subset of x-axis ticks to avoid clutter
  const tickInterval = Math.max(1, Math.floor(data.length / 10));

  return (
    <div style={{ height: 90, padding: "4px 0" }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          margin={{ top: 2, right: 8, left: 0, bottom: 0 }}
        >
          <XAxis
            dataKey="label"
            tick={{ fontSize: 9, fill: "var(--text-secondary)" }}
            interval={tickInterval}
            axisLine={false}
            tickLine={false}
          />
          <YAxis hide domain={[0, maxCount]} />
          <Tooltip content={<CustomTooltip />} />
          <Bar
            dataKey="count"
            radius={[1, 1, 0, 0]}
            cursor="pointer"
            onClick={(item: BarRectangleItem) => handleClick(item.payload as { startMs?: number; endMs?: number })}
          >
            {data.map((entry, idx) => (
              <Cell
                key={idx}
                fill={entry.count === 0 ? "var(--bg-tertiary)" : "var(--accent-blue)"}
                fillOpacity={0.8}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
