import { useState, useCallback } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { loadDirectory } from "../../lib/tauri";
import type { IngestProgressEvent } from "../../types/cloudtrail";

interface Props {
  onLoaded: (recordCount: number) => void;
}

export function DropZone({ onLoaded }: Props) {
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState<{ filesDone: number; filesTotal: number; records: number } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleOpen = useCallback(async () => {
    const selected = await open({ directory: true, multiple: false });
    if (!selected || Array.isArray(selected)) return;

    setLoading(true);
    setError(null);
    setProgress(null);

    try {
      const total = await loadDirectory(selected, (evt: IngestProgressEvent) => {
        if (evt.type === "progress") {
          setProgress({ filesDone: evt.filesDone, filesTotal: evt.filesTotal, records: evt.recordsTotal });
        }
      });
      onLoaded(total);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [onLoaded]);

  return (
    <div className="flex flex-col items-center justify-center h-full gap-6">
      <div className="text-center">
        <h1 className="text-2xl font-bold text-bright mb-2">TrailInspector</h1>
        <p className="text-muted text-sm">AWS CloudTrail Log Analyzer</p>
      </div>

      <button
        onClick={handleOpen}
        disabled={loading}
        className="px-8 py-4 rounded-lg text-sm font-semibold transition-colors"
        style={{
          background: loading ? 'var(--bg-tertiary)' : 'var(--accent-blue)',
          color: loading ? 'var(--text-secondary)' : '#0d1117',
          cursor: loading ? 'not-allowed' : 'pointer',
          border: 'none',
        }}
      >
        {loading ? "Loading..." : "Open CloudTrail Directory"}
      </button>

      {progress && (
        <div className="text-center text-sm">
          <div className="text-bright">{progress.records.toLocaleString()} records</div>
          <div className="text-muted">{progress.filesDone} / {progress.filesTotal} files</div>
          <div className="mt-2 w-64 h-1 rounded-full overflow-hidden" style={{ background: 'var(--bg-tertiary)' }}>
            <div
              className="h-full rounded-full transition-all"
              style={{
                width: `${progress.filesTotal > 0 ? (progress.filesDone / progress.filesTotal) * 100 : 0}%`,
                background: 'var(--accent-blue)',
              }}
            />
          </div>
        </div>
      )}

      {error && <p className="text-error text-sm">{error}</p>}
    </div>
  );
}
