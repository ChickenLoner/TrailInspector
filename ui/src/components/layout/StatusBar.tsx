interface Props {
  recordCount: number;
  loaded: boolean;
}

export function StatusBar({ recordCount, loaded }: Props) {
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
          <span>{recordCount.toLocaleString()} events loaded</span>
        </>
      ) : (
        <span>No dataset loaded</span>
      )}
    </div>
  );
}
