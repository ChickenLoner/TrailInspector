interface Props {
  recordCount: number;
  loaded: boolean;
  filteredCount?: number;
  queryActive?: boolean;
  loadTimeMs?: number;
  queryTimeMs?: number;
}

export function StatusBar({ recordCount, loaded, filteredCount, queryActive, loadTimeMs, queryTimeMs }: Props) {
  return (
    <div
      className="flex items-center px-3 gap-4 text-xs flex-shrink-0"
      style={{
        height: 24,
        background: 'var(--bg-tertiary)',
        borderTop: '1px solid var(--border)',
        color: 'var(--text-secondary)',
      }}
    >
      {loaded ? (
        <>
          {queryActive && filteredCount !== undefined ? (
            <span>
              <span style={{ color: 'var(--text-bright)' }}>{filteredCount.toLocaleString()}</span>
              <span> of </span>
              <span style={{ color: 'var(--text-bright)' }}>{recordCount.toLocaleString()}</span>
              <span> events</span>
            </span>
          ) : (
            <span>
              <span style={{ color: 'var(--text-bright)' }}>{recordCount.toLocaleString()}</span>
              <span> events loaded</span>
            </span>
          )}

          {loadTimeMs !== undefined && (
            <span style={{ borderLeft: '1px solid var(--border)', paddingLeft: '1rem' }}>
              Load: {loadTimeMs < 1000 ? `${loadTimeMs}ms` : `${(loadTimeMs / 1000).toFixed(1)}s`}
            </span>
          )}

          {queryTimeMs !== undefined && queryActive && (
            <span>
              Query: {queryTimeMs < 1000 ? `${queryTimeMs}ms` : `${(queryTimeMs / 1000).toFixed(1)}s`}
            </span>
          )}
        </>
      ) : (
        <span>No dataset loaded</span>
      )}

      <span style={{ marginLeft: 'auto' }}>TrailInspector</span>
    </div>
  );
}
