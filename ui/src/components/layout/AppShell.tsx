import { useState } from "react";
import { Sidebar, type Tab } from "./Sidebar";
import { FieldStats } from "../viz/FieldStats";
import { IdentityTimeline } from "../viz/IdentityTimeline";

interface Props {
  /** Content for the Search tab (query bar + event table etc.) */
  searchView: React.ReactNode;
  /** Called when user clicks a field value bar in FieldStats */
  onFilterSelect?: (field: string, value: string) => void;
  /** Current query string (passed to FieldStats for scoped stats) */
  query?: string;
}

export function AppShell({ searchView, onFilterSelect, query }: Props) {
  const [activeTab, setActiveTab] = useState<Tab>("search");

  return (
    <div style={{ display: "flex", height: "100%", overflow: "hidden" }}>
      <Sidebar activeTab={activeTab} onTabChange={setActiveTab} />

      {/* Main content */}
      <div style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "column" }}>
        {activeTab === "search" && searchView}

        {activeTab === "stats" && (
          <div style={{ flex: 1, overflow: "hidden" }}>
            <FieldStats query={query} onFilterSelect={onFilterSelect} />
          </div>
        )}

        {activeTab === "identity" && (
          <div style={{ flex: 1, overflow: "hidden" }}>
            <IdentityTimeline />
          </div>
        )}

        {activeTab === "detections" && (
          <div
            style={{
              flex: 1,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              flexDirection: "column",
              gap: 8,
              color: "var(--text-secondary)",
            }}
          >
            <div style={{ fontSize: 24 }}>!</div>
            <div style={{ fontSize: 14, fontWeight: 600, color: "var(--text-primary)" }}>
              Detections
            </div>
            <div style={{ fontSize: 12 }}>Coming in Phase 4</div>
          </div>
        )}
      </div>
    </div>
  );
}
