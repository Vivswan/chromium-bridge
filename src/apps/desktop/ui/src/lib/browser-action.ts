// Which action a browser row offers, from BrowserRow's machine fields (the
// desktop crate's RegCode enum, carried into commands.gen.ts as a closed
// union). Kept out of the view so the truth table is unit-testable.

import type { RegCode } from "./commands.gen";

export type BrowserAction = "connect" | "repair" | "none";

export function browserAction(row: { detected: boolean; code: RegCode }): BrowserAction {
  // A browser that is not installed for this user cannot be registered.
  if (!row.detected) return "none";
  switch (row.code) {
    // No registration yet: offer Connect.
    case "missing":
      return "connect";
    // A registration is present but wrong: offer Repair. The engine, not
    // this button, decides what a repair may touch (foreign manifests are
    // refused there).
    case "stale":
    case "foreign":
    case "unreadable":
      return "repair";
    // Connected, nothing to repair: offer nothing.
    case "ok":
      return "none";
    default:
      // Exhaustiveness backstop: a new RegCode fails to compile here
      // instead of silently offering nothing.
      return row.code satisfies never;
  }
}
