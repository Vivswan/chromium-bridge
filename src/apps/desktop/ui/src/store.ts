// App-wide state (Zustand, house style): the active view and the shared
// bridge status the sidebar and Overview both render. Per-view data stays in
// the views (useAsync); only genuinely shared state lives here.

import { create } from "zustand";
import { api, type BridgeStatus, errorText } from "@/lib/tauri";

export type View = "overview" | "browsers" | "pairing" | "clients" | "audit" | "setup";

interface AppState {
  view: View;
  setView: (view: View) => void;
  status: BridgeStatus | undefined;
  statusError: string | undefined;
  refreshStatus: () => Promise<void>;
}

// Overlapping refreshes (startup, focus, post-action) must not let a slower,
// older response overwrite a newer one; only the latest request may commit.
let statusSeq = 0;

export const useAppStore = create<AppState>((set) => ({
  view: "overview",
  setView: (view) => set({ view }),
  status: undefined,
  statusError: undefined,
  refreshStatus: async () => {
    const mySeq = ++statusSeq;
    try {
      const status = await api.bridgeStatus();
      if (statusSeq === mySeq) set({ status, statusError: undefined });
    } catch (err) {
      if (statusSeq === mySeq) set({ statusError: errorText(err) });
    }
  },
}));
