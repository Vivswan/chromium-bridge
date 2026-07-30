import { describe, expect, it } from "vitest";
import { browserAction } from "../src/lib/browser-action";
import type { RegCode } from "../src/lib/commands.gen";

// The row-state truth table behind the Browsers page's action button, keyed
// on the RegCode union (the desktop crate's serde mirror of core's
// RegState). The user-visible rule: a healthy registration offers no action
// (there is nothing to repair), an absent one offers Connect, a wrong one
// offers Repair, and an undetected browser offers nothing. Unknown codes are
// unrepresentable: RegCode is a closed union and the switch is exhaustive,
// so a new state fails to compile rather than silently offering nothing.
describe("browserAction", () => {
  const row = (detected: boolean, code: RegCode) => ({ detected, code });

  it("offers no action for a healthy registration", () => {
    expect(browserAction(row(true, "ok"))).toBe("none");
  });

  it("offers Connect when the browser is detected but not registered", () => {
    expect(browserAction(row(true, "missing"))).toBe("connect");
  });

  it("offers Repair when a registration is present but wrong", () => {
    for (const code of ["stale", "foreign", "unreadable"] as const) {
      expect(browserAction(row(true, code)), code).toBe("repair");
    }
  });

  it("offers no action for an undetected browser, whatever its state", () => {
    // Removal of a leftover registration stays available in the view;
    // registering an absent browser does not.
    for (const code of ["missing", "ok", "stale"] as const) {
      expect(browserAction(row(false, code)), code).toBe("none");
    }
  });
});
