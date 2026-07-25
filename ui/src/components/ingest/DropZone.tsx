import { useState, useCallback } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { loadDirectory, pullStaged } from "../../lib/tauri";
import { AwsFetchPanel } from "./AwsFetchPanel";
import type { IngestProgressEvent, IngestWarning } from "../../types/cloudtrail";

interface Props {
  onLoaded: (recordCount: number, warnings: IngestWarning[]) => void;
}

interface IngestProgressState {
  filesDone: number;
  filesTotal: number;
  records: number;
}

export function DropZone({ onLoaded }: Props) {
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState<IngestProgressState | null>(null);
  const [fetchStatus, setFetchStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showAws, setShowAws] = useState(false);

  /**
   * Progress sink shared by every source. Keeping one handler means the file,
   * folder, and AWS paths cannot drift in how they report progress.
   */
  const handleProgress = useCallback((evt: IngestProgressEvent) => {
    if (evt.type === "fetch") {
      setFetchStatus(evt.message);
    } else if (evt.type === "progress") {
      setFetchStatus(null);
      setProgress({
        filesDone: evt.filesDone,
        filesTotal: evt.filesTotal,
        records: evt.recordsTotal,
      });
    }
  }, []);

  /** Shared tail for anything that ends in a loaded dataset. */
  const runIngest = useCallback(
    async (run: (onProgress: (e: IngestProgressEvent) => void) => Promise<number>) => {
      setLoading(true);
      setError(null);
      setProgress(null);
      setFetchStatus(null);

      try {
        let capturedWarnings: IngestWarning[] = [];
        const total = await run((evt) => {
          if (evt.type === "complete") capturedWarnings = evt.warnings ?? [];
          handleProgress(evt);
        });
        onLoaded(total, capturedWarnings);
      } catch (e) {
        setError(String(e));
      } finally {
        setLoading(false);
      }
    },
    [onLoaded, handleProgress],
  );

  // Native dialogs can't offer "file or folder" in a single picker, so the
  // caller decides which mode to open. Everything after the pick is identical —
  // the backend walks a directory or ingests the one file it was handed.
  const handleOpen = useCallback(
    async (mode: "directory" | "file") => {
      const selected = await open(
        mode === "directory"
          ? { directory: true, multiple: false }
          : {
              multiple: false,
              filters: [{ name: "CloudTrail logs", extensions: ["json", "gz", "zip"] }],
            },
      );
      if (!selected || Array.isArray(selected)) return;
      await runIngest((onProgress) => loadDirectory(selected, onProgress));
    },
    [runIngest],
  );

  const buttonBase =
    "shrink-0 whitespace-nowrap min-w-[12rem] px-6 py-3.5 rounded-lg text-sm font-semibold transition-colors";

  return (
    <div className="flex flex-col items-center justify-center h-full gap-6 overflow-y-auto py-8">
      <div className="text-center">
        <h1 className="text-2xl font-bold text-bright mb-2">TrailInspector</h1>
        <p className="text-muted text-sm">AWS CloudTrail Log Analyzer</p>
      </div>

      <div className="flex flex-col items-center gap-3">
        {/* shrink-0 + whitespace-nowrap: without them the flex row squeezes the
            buttons and the labels wrap into the padding. min-w keeps them
            balanced and stops the primary resizing on the "Loading…" swap. */}
        <div className="flex flex-wrap justify-center gap-3">
          <button
            onClick={() => handleOpen("directory")}
            disabled={loading}
            className={buttonBase}
            style={{
              background: loading ? 'var(--bg-tertiary)' : 'var(--accent-green)',
              color: loading ? 'var(--text-secondary)' : '#ffffff',
              cursor: loading ? 'not-allowed' : 'pointer',
              // Transparent 1px border, not `none`, so all buttons share a box height.
              border: '1px solid transparent',
            }}
          >
            {loading ? "Loading…" : "Open Folder"}
          </button>

          <button
            onClick={() => handleOpen("file")}
            disabled={loading}
            className={buttonBase}
            style={{
              background: 'var(--bg-tertiary)',
              color: loading ? 'var(--text-secondary)' : 'var(--text-primary)',
              cursor: loading ? 'not-allowed' : 'pointer',
              border: '1px solid var(--border)',
            }}
          >
            Open Single File
          </button>

          <button
            onClick={() => setShowAws((v) => !v)}
            disabled={loading}
            className={buttonBase}
            style={{
              background: 'var(--bg-tertiary)',
              color: loading ? 'var(--text-secondary)' : 'var(--text-primary)',
              cursor: loading ? 'not-allowed' : 'pointer',
              border: `1px solid ${showAws ? 'var(--accent-blue)' : 'var(--border)'}`,
            }}
          >
            Import from Live AWS
          </button>
        </div>

        <p className="text-muted text-xs text-center leading-relaxed max-w-md">
          <span className="font-semibold">Folder</span> — S3-delivered{" "}
          <code className="font-mono">AWSLogs/</code> tree.{" "}
          <span className="font-semibold">File</span> — one{" "}
          <code className="font-mono">.json</code>,{" "}
          <code className="font-mono">.json.gz</code>, or{" "}
          <code className="font-mono">.zip</code>, including an{" "}
          <code className="font-mono">aws cloudtrail lookup-events</code> export.
        </p>
      </div>

      {showAws && (
        <AwsFetchPanel
          busy={loading}
          onCheckStart={() => {
            setLoading(true);
            setError(null);
            setProgress(null);
            setFetchStatus(null);
          }}
          onCheckEnd={() => setLoading(false)}
          onProgress={handleProgress}
          onPull={() => runIngest((onProgress) => pullStaged(onProgress))}
        />
      )}

      {fetchStatus && (
        <div className="text-center text-sm">
          <div className="text-bright">{fetchStatus}</div>
          <div className="text-muted text-xs mt-1">Downloading from AWS…</div>
        </div>
      )}

      {progress && (
        <div className="text-center text-sm">
          <div className="text-bright">{progress.records.toLocaleString()} records</div>
          <div className="text-muted">{progress.filesDone} / {progress.filesTotal} files</div>
          <div className="mt-2 w-64 h-1 rounded-full overflow-hidden" style={{ background: 'var(--bg-tertiary)' }}>
            <div
              className="h-full rounded-full transition-all"
              style={{
                width: `${progress.filesTotal > 0 ? (progress.filesDone / progress.filesTotal) * 100 : 0}%`,
                background: 'var(--accent-green)',
              }}
            />
          </div>
        </div>
      )}

      {error && <p className="text-error text-sm max-w-lg text-center break-words">{error}</p>}
    </div>
  );
}
