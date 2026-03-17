import { useState, useCallback, useEffect, useRef, type KeyboardEvent } from "react";

interface Props {
  value: string;
  onChange: (value: string) => void;
  onSubmit: (value: string) => void;
  disabled?: boolean;
  /** Optional ref forwarded to the underlying <input> for external focus control */
  inputRef?: React.RefObject<HTMLInputElement | null>;
}

const PLACEHOLDER = 'eventName=ConsoleLogin AND awsRegion=us-east-1 earliest=-24h';

const FIELD_HINTS = [
  "eventName", "eventSource", "awsRegion", "sourceIPAddress",
  "userName", "userArn", "accountId", "errorCode", "identityType", "userAgent",
];

export function QueryBar({ value, onChange, onSubmit, disabled, inputRef }: Props) {
  const [localValue, setLocalValue] = useState(value);
  const internalRef = useRef<HTMLInputElement>(null);
  const resolvedRef = inputRef ?? internalRef;

  // Sync when external value changes (e.g., from filter panel)
  useEffect(() => {
    setLocalValue(value);
  }, [value]);

  const handleKeyDown = useCallback(
    (e: KeyboardEvent<HTMLInputElement>) => {
      if (e.key === "Enter") {
        e.preventDefault();
        onSubmit(localValue);
      } else if (e.key === "Escape") {
        setLocalValue("");
        onChange("");
        onSubmit("");
        resolvedRef.current?.blur();
      }
    },
    [localValue, onChange, onSubmit, resolvedRef]
  );

  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      setLocalValue(e.target.value);
      onChange(e.target.value);
    },
    [onChange]
  );

  const handleClear = useCallback(() => {
    setLocalValue("");
    onChange("");
    onSubmit("");
  }, [onChange, onSubmit]);

  return (
    <div className="flex items-center gap-2 px-3" style={{ height: 40 }}>
      {/* Search icon */}
      <svg
        width="14"
        height="14"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        style={{ color: "var(--text-secondary)", flexShrink: 0 }}
      >
        <circle cx="11" cy="11" r="8" />
        <line x1="21" y1="21" x2="16.65" y2="16.65" />
      </svg>

      <input
        ref={resolvedRef}
        id="query-input"
        type="text"
        value={localValue}
        onChange={handleChange}
        onKeyDown={handleKeyDown}
        placeholder={PLACEHOLDER}
        disabled={disabled}
        spellCheck={false}
        autoComplete="off"
        style={{
          flex: 1,
          background: "transparent",
          border: "none",
          outline: "none",
          color: "var(--text-bright)",
          fontSize: 13,
          fontFamily: "monospace",
          caretColor: "var(--accent-green)",
        }}
      />

      {/* Field hint chips */}
      <div
        className="hidden md:flex items-center gap-1 text-xs"
        style={{ color: "var(--text-secondary)", flexShrink: 0 }}
      >
        {FIELD_HINTS.slice(0, 4).map((f) => (
          <button
            key={f}
            onClick={() => {
              const newVal = localValue ? `${localValue} ${f}=` : `${f}=`;
              setLocalValue(newVal);
              onChange(newVal);
            }}
            style={{
              background: "var(--bg-tertiary)",
              border: "1px solid var(--border)",
              color: "var(--text-secondary)",
              padding: "1px 6px",
              borderRadius: 3,
              cursor: "pointer",
              fontFamily: "monospace",
              fontSize: 11,
            }}
          >
            {f}
          </button>
        ))}
      </div>

      {/* Clear button */}
      {localValue && (
        <button
          onClick={handleClear}
          style={{
            background: "none",
            border: "none",
            color: "var(--text-secondary)",
            cursor: "pointer",
            fontSize: 16,
            lineHeight: 1,
            padding: "0 2px",
            flexShrink: 0,
          }}
          title="Clear (Esc)"
        >
          ×
        </button>
      )}

      {/* Search button */}
      <button
        onClick={() => onSubmit(localValue)}
        disabled={disabled}
        style={{
          background: "var(--accent-green)",
          border: "none",
          color: "#ffffff",
          cursor: disabled ? "not-allowed" : "pointer",
          padding: "3px 12px",
          borderRadius: 3,
          fontSize: 12,
          fontWeight: 600,
          flexShrink: 0,
          opacity: disabled ? 0.5 : 1,
        }}
      >
        Search
      </button>
    </div>
  );
}
