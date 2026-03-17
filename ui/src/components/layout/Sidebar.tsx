export type Tab = "search" | "stats" | "identity" | "detections";

interface Props {
  activeTab: Tab;
  onTabChange: (tab: Tab) => void;
}

const TABS: { id: Tab; label: string; icon: string }[] = [
  { id: "search", label: "Search", icon: "S" },
  { id: "stats", label: "Stats", icon: "=" },
  { id: "identity", label: "Identity", icon: "I" },
  { id: "detections", label: "Detections", icon: "!" },
];

export function Sidebar({ activeTab, onTabChange }: Props) {
  return (
    <div
      style={{
        width: 48,
        flexShrink: 0,
        background: "var(--bg-secondary)",
        borderRight: "1px solid var(--border)",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        paddingTop: 8,
        gap: 2,
      }}
    >
      {TABS.map((tab) => {
        const isActive = activeTab === tab.id;
        return (
          <button
            key={tab.id}
            onClick={() => onTabChange(tab.id)}
            title={tab.label}
            style={{
              width: 36,
              height: 36,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              border: "none",
              borderRadius: 6,
              background: isActive ? "var(--accent-green)" : "transparent",
              color: isActive ? "#ffffff" : "var(--text-secondary)",
              cursor: "pointer",
              fontSize: 14,
              fontWeight: 700,
              transition: "background 0.1s",
            }}
          >
            {tab.icon}
          </button>
        );
      })}
    </div>
  );
}
