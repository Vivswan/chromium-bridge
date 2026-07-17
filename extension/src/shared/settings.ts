// Single source of truth for the configurable settings and their defaults.
//
// Previously DEFAULTS was copy-pasted into background.ts, content.ts, and
// options.ts with "KEEP IN SYNC" comments. Now all three import from here.
// esbuild inlines this into each bundle, so there is no runtime cost.

import type { Settings } from "./types";

export const DEFAULTS: Settings = {
  pageEvalEnabled: true,
  evalMask: true,
  confirmHighRiskClick: true,
  confirmPageEval: true, // confirm every page_eval (ADR-0008). Off = run unprompted.
  confirmTabClose: true, // confirm every tab_close. Off = close unprompted.
  warnPreciseSnapshot: true,
  confirmGraceMs: 60000, // same-origin re-prompt window for click/submit only; page_eval is excluded and always reconfirms (ADR-0008).
  clickToastTimeoutMs: 30000,
  evalToastTimeoutMs: 45000,
  disabledTools: [], // string[] of tool/op names that are blocked
  allowAllSites: false,
  cdpMode: false, // route ALL page ops through chrome.debugger (CDP). See ADR-0017.
  groupTabs: true, // collect tab_open tabs into a "Chromium Bridge" group. See ADR-0018.
  fileUploadEnabled: false, // page_upload is OFF by default: attaching a local file to a page is a local-file egress vector.
  handleDialogEnabled: false, // page_handle_dialog is OFF by default: a blocked dialog cannot show an in-page confirm, so the opt-in is the gate.
  requireEnrollment: true, // refuse bridge ops until a host key is paired + pinned (ADR-0021).
  hostReverifyMs: 0, // 0 = verify host identity only at pairing + on demand. >0 = on connect,
  // re-verify against the pin when the last successful verification is older
  // than this many ms (lazy check, no scheduler; each re-verify prompts Touch ID).
};

// Read one setting from chrome.storage.local, falling back to its default.
// Not cached: settings are read once per action and storage reads are cheap.
export function getSetting<K extends keyof Settings>(key: K): Promise<Settings[K]> {
  return new Promise((resolve) => {
    chrome.storage.local.get(key as string, (r) => {
      const v = r[key as string];
      resolve(v === undefined ? DEFAULTS[key] : (v as Settings[K]));
    });
  });
}
