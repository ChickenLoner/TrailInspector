import { Sidebar, type Tab } from "./Sidebar";
import { FieldStats } from "../viz/FieldStats";
import { IdentityTimeline } from "../viz/IdentityTimeline";
import { DetectionView } from "../detection/DetectionView";

interface Props {
  /** Content for the Search tab (query bar + event table etc.) */
  searchView: React.ReactNode;
  /** Called when user clicks a field value bar in FieldStats */
  onFilterSelect?: (field: string, value: string) => void;
  /** Current query string (passed to FieldStats for scoped stats) */
  query?: string;
  /** Controlled active tab */
  activeTab: Tab;
  onTabChange: (tab: Tab) => void;
  /** Pre-fill Identity tab with this value and auto-lookup */
  selectedIdentity?: string;
  /** Called when "View Evidence" is clicked in AlertDetail — receives pre-built query string */
  onViewEvidence?: (query: string) => void;
}

export function AppShell({ searchView, onFilterSelect, query, activeTab, onTabChange, selectedIdentity, onViewEvidence }: Props) {
  return (
    <div style={{ display: "flex", height: "100%", overflow: "hidden" }}>
      <Sidebar activeTab={activeTab} onTabChange={onTabChange} />

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
            <IdentityTimeline initialValue={selectedIdentity} />
          </div>
        )}

        {activeTab === "detections" && (
          <div style={{ flex: 1, overflow: "hidden" }}>
            <DetectionView onViewEvidence={onViewEvidence ?? (() => {})} />
          </div>
        )}
      </div>
    </div>
  );
}
