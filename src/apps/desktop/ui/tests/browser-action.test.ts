import { describe, expect, it } from "vitest";
import { browserAction } from "../src/lib/browser-action";

// The row-state truth table behind the Browsers page's action button, keyed
// on RegState::code() from the Rust side. The user-visible rule: a healthy
// registration offers no action (there is nothing to repair), an absent one
// offers Connect, a wrong one offers Repair, and an undetected browser
// offers nothing.
describe("browserAction", () => {
  const row = (detected: boolean, code: string) => ({ detected, code });

  it("offers no action for a healthy registration", () => {
    expect(browserAction(row(true, "ok"))).toBe("none");
  });

  it("offers Connect when the browser is detected but not registered", () => {
    expect(browserAction(row(true, "missing"))).toBe("connect");
  });

  it("offers Repair when a registration is present but wrong", () => {
    for (const code of ["stale", "foreign", "unreadable"]) {
      expect(browserAction(row(true, code)), code).toBe("repair");
    }
  });

  it("offers no action for an undetected browser, whatever its state", () => {
    // Removal of a leftover registration stays available in the view;
    // registering an absent browser does not.
    for (const code of ["missing", "ok", "stale"]) {
      expect(browserAction(row(false, code)), code).toBe("none");
    }
  });

  it("offers no action for a state code this UI does not know", () => {
    expect(browserAction(row(true, "quarantined"))).toBe("none");
  });
});
