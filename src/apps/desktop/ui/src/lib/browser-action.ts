// Which action a browser row offers, from BrowserRow's machine fields
// (RegState::code() on the Rust side). Kept out of the view so the
// truth table is unit-testable.

export type BrowserAction = "connect" | "repair" | "none";

export function browserAction(row: { detected: boolean; code: string }): BrowserAction {
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
    // "ok" (connected, nothing to repair) and any state code this UI does
    // not know yet: offer nothing.
    default:
      return "none";
  }
}
