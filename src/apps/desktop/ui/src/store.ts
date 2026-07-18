// App-wide state (Zustand, house style): the active view and the shared
// bridge status the sidebar and Overview both render. Per-view data stays in
// the views (useAsync); only genuinely shared state lives here.

import { create } from "zustand";
import { api, type BridgeStatus, errorText } from "@/lib/tauri";

export type View = "overview" | "browsers" | "clients" | "security" | "audit" | "setup";

interface AppState {
  view: View;
  setView: (view: View) => void;
  status: BridgeStatus | undefined;
  statusError: string | undefined;
  /** False whenever the LATEST refresh failed: `status` is then a stale
   * snapshot, and no view may derive a healthy (green) claim from it. The
   * views fall back to their unknown/idle rendering until a refresh
   * succeeds again (fail-closed display). Stays true while a refresh is
   * merely in flight - the last settled answer keeps rendering rather than
   * flashing unknown on every focus; only a settled failure drops it. */
  statusFresh: boolean;
  refreshStatus: () => Promise<void>;
  /** Auth method from the last successful kill release. Shared so that any
   * path that re-engages the switch (Overview or sidebar) can clear it - a
   * stale "released" note under an engaged switch would be a false claim. */
  releasedBy: string | undefined;
  setReleasedBy: (releasedBy: string | undefined) => void;
  /** Count of this app's own in-flight release flows (Touch ID sheet up
   * through the follow-up refresh): their focus churn must not be mistaken
   * for "user came back after possible CLI activity". A count, not a flag,
   * so an overlapping flow or a view unmount cannot end suppression early;
   * the host presence-gates every release regardless of what the UI shows. */
  releaseInFlight: number;
  beginRelease: () => void;
  endRelease: () => void;
}

// Overlapping refreshes (startup, focus, post-action) must not let a slower,
// older response overwrite a newer one; only the latest request may commit.
let statusSeq = 0;

export const useAppStore = create<AppState>((set) => ({
  view: "overview",
  setView: (view) => set({ view }),
  status: undefined,
  statusError: undefined,
  statusFresh: false,
  releasedBy: undefined,
  setReleasedBy: (releasedBy) => set({ releasedBy }),
  releaseInFlight: 0,
  beginRelease: () => set((state) => ({ releaseInFlight: state.releaseInFlight + 1 })),
  endRelease: () => set((state) => ({ releaseInFlight: Math.max(0, state.releaseInFlight - 1) })),
  refreshStatus: async () => {
    const mySeq = ++statusSeq;
    try {
      const status = await api.bridgeStatus();
      if (statusSeq === mySeq) {
        set((state) => ({
          status,
          statusError: undefined,
          statusFresh: true,
          // an observed non-off switch invalidates any prior release note:
          // it must not resurface after a later (e.g. CLI) release
          releasedBy: status.kill.state === "off" ? state.releasedBy : undefined,
        }));
      }
    } catch (err) {
      if (statusSeq === mySeq) set({ statusError: errorText(err), statusFresh: false });
    }
  },
}));
