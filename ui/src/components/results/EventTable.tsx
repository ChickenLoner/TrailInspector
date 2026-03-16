import { useCallback, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { RecordRow } from "../../types/cloudtrail";

const COLUMNS = [
  { key: "eventTime", label: "Time", width: 160 },
  { key: "eventName", label: "Event", width: 200 },
  { key: "eventSource", label: "Source", width: 180 },
  { key: "awsRegion", label: "Region", width: 110 },
  { key: "userName", label: "User", width: 150 },
  { key: "sourceIPAddress", label: "Source IP", width: 130 },
  { key: "errorCode", label: "Error", width: 120 },
] as const;

interface Props {
  records: RecordRow[];
  total: number;
  page: number;
  pageSize: number;
  onPageChange: (page: number) => void;
  selectedId?: number;
  onSelect: (record: RecordRow) => void;
}

export function EventTable({ records, total, page, pageSize, onPageChange, selectedId, onSelect }: Props) {
  const parentRef = useRef<HTMLDivElement>(null);

  const rowVirtualizer = useVirtualizer({
    count: records.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 28,
    overscan: 10,
  });

  const totalPages = Math.ceil(total / pageSize);

  const formatTime = useCallback((iso: string) => {
    try {
      return new Date(iso).toISOString().replace("T", " ").substring(0, 19);
    } catch {
      return iso;
    }
  }, []);

  return (
    <div className="flex flex-col h-full" style={{ background: 'var(--bg-primary)' }}>
      {/* Header */}
      <div
        className="flex items-center text-xs font-semibold flex-shrink-0"
        style={{
          background: 'var(--bg-tertiary)',
          borderBottom: '1px solid var(--border)',
          height: 28,
        }}
      >
        {COLUMNS.map(col => (
          <div
            key={col.key}
            className="px-2 overflow-hidden text-ellipsis whitespace-nowrap"
            style={{ width: col.width, minWidth: col.width, color: 'var(--text-secondary)' }}
          >
            {col.label}
          </div>
        ))}
      </div>

      {/* Virtualized rows */}
      <div ref={parentRef} className="flex-1 overflow-auto">
        <div style={{ height: rowVirtualizer.getTotalSize(), position: "relative" }}>
          {rowVirtualizer.getVirtualItems().map(virtualRow => {
            const record = records[virtualRow.index];
            const isSelected = record.id === selectedId;
            const hasError = !!record.errorCode;

            return (
              <div
                key={virtualRow.key}
                onClick={() => onSelect(record)}
                style={{
                  position: "absolute",
                  top: 0,
                  left: 0,
                  width: "100%",
                  height: virtualRow.size,
                  transform: `translateY(${virtualRow.start}px)`,
                  display: "flex",
                  alignItems: "center",
                  cursor: "pointer",
                  background: isSelected
                    ? "rgba(77, 171, 247, 0.12)"
                    : virtualRow.index % 2 === 0
                    ? "var(--bg-primary)"
                    : "var(--bg-secondary)",
                  borderLeft: isSelected ? "2px solid var(--accent-blue)" : "2px solid transparent",
                }}
              >
                <div className="px-2 text-xs" style={{ width: 160, minWidth: 160, color: 'var(--text-secondary)' }}>
                  {formatTime(record.eventTime)}
                </div>
                <div className="px-2 text-xs font-medium" style={{ width: 200, minWidth: 200, color: 'var(--text-bright)' }}>
                  {record.eventName}
                </div>
                <div className="px-2 text-xs" style={{ width: 180, minWidth: 180, color: 'var(--text-secondary)' }}>
                  {record.eventSource}
                </div>
                <div className="px-2 text-xs" style={{ width: 110, minWidth: 110, color: 'var(--accent-blue)' }}>
                  {record.awsRegion}
                </div>
                <div className="px-2 text-xs overflow-hidden text-ellipsis whitespace-nowrap" style={{ width: 150, minWidth: 150 }}>
                  {record.userName ?? record.userArn ?? "—"}
                </div>
                <div className="px-2 text-xs" style={{ width: 130, minWidth: 130, color: 'var(--text-secondary)' }}>
                  {record.sourceIPAddress ?? "—"}
                </div>
                <div className="px-2 text-xs" style={{ width: 120, minWidth: 120, color: hasError ? 'var(--accent-red)' : 'var(--text-secondary)' }}>
                  {record.errorCode ?? "—"}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Pagination */}
      <div
        className="flex items-center justify-between px-3 text-xs flex-shrink-0"
        style={{ height: 32, borderTop: '1px solid var(--border)', background: 'var(--bg-secondary)' }}
      >
        <span style={{ color: 'var(--text-secondary)' }}>
          {total.toLocaleString()} events · page {page + 1} of {totalPages}
        </span>
        <div className="flex gap-2">
          <button
            onClick={() => onPageChange(page - 1)}
            disabled={page === 0}
            className="px-2 py-0.5 rounded text-xs"
            style={{
              background: 'var(--bg-tertiary)',
              border: '1px solid var(--border)',
              color: page === 0 ? 'var(--text-secondary)' : 'var(--text-bright)',
              cursor: page === 0 ? 'not-allowed' : 'pointer',
            }}
          >
            ◀ Prev
          </button>
          <button
            onClick={() => onPageChange(page + 1)}
            disabled={page >= totalPages - 1}
            className="px-2 py-0.5 rounded text-xs"
            style={{
              background: 'var(--bg-tertiary)',
              border: '1px solid var(--border)',
              color: page >= totalPages - 1 ? 'var(--text-secondary)' : 'var(--text-bright)',
              cursor: page >= totalPages - 1 ? 'not-allowed' : 'pointer',
            }}
          >
            Next ▶
          </button>
        </div>
      </div>
    </div>
  );
}
