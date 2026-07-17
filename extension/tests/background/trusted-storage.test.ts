// #32: the storage access restriction, and that the enrollment gate fails
// closed until it is verifiably applied. What CANNOT be tested here: that
// Chrome actually blocks a real content script from reading storage.local -
// that is the isolated-browser proof (tests/README + the ext suite). Here we
// pin the SW-side contract: setAccessLevel is called for both areas, the
// result is memoized, and a failure blocks the gate.

import { beforeEach, describe, expect, test, vi } from "vitest";
import { fakeBrowser } from "wxt/testing";
import {
  hardenStorageAccess,
  resetStorageHardeningForTests,
} from "@/lib/background/trusted-storage";

beforeEach(() => {
  fakeBrowser.reset();
  resetStorageHardeningForTests();
});

describe("hardenStorageAccess", () => {
  test("restricts BOTH local and session to TRUSTED_CONTEXTS, local FIRST", async () => {
    const order: string[] = [];
    const local = vi.fn(() => {
      order.push("local");
      return Promise.resolve();
    });
    const session = vi.fn(() => {
      order.push("session");
      return Promise.resolve();
    });
    (fakeBrowser.storage.local as unknown as Record<string, unknown>).setAccessLevel = local;
    (fakeBrowser.storage.session as unknown as Record<string, unknown>).setAccessLevel = session;

    const result = await hardenStorageAccess();
    expect(result.ok).toBe(true);
    expect(local).toHaveBeenCalledWith({ accessLevel: "TRUSTED_CONTEXTS" });
    expect(session).toHaveBeenCalledWith({ accessLevel: "TRUSTED_CONTEXTS" });
    // local carries the trust state and is the only area content-readable by
    // default, so it must be restricted before session (already trusted).
    expect(order).toEqual(["local", "session"]);
  });

  test("is memoized: applied once per SW life", async () => {
    const local = vi.fn().mockResolvedValue(undefined);
    (fakeBrowser.storage.local as unknown as Record<string, unknown>).setAccessLevel = local;
    (fakeBrowser.storage.session as unknown as Record<string, unknown>).setAccessLevel = vi
      .fn()
      .mockResolvedValue(undefined);
    await hardenStorageAccess();
    await hardenStorageAccess();
    expect(local).toHaveBeenCalledTimes(1);
  });

  test("reports failure (does not throw) when setAccessLevel is unavailable", async () => {
    (fakeBrowser.storage.local as unknown as Record<string, unknown>).setAccessLevel = () => {
      throw new Error("not supported in this Chrome");
    };
    const result = await hardenStorageAccess();
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("not supported");
  });
});
