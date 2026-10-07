// The CDP session registry's teardown listener is policy-driven: an
// accepted policy push whose effective cdpMode is false must tear live
// sessions down on the PUSH path (the accepted push writes the policy
// storage keys, which the listener watches).

import { POLICY_DEFAULTS, type PolicyValues } from "@chromium-bridge/shared/generated/policy";
import { beforeEach, describe, expect, test, vi } from "vitest";
import { fakeBrowser } from "wxt/testing/fake-browser";

function record(overrides: Partial<PolicyValues>) {
  return {
    scope: null,
    effective: { ...POLICY_DEFAULTS, disabledTools: [], ...overrides },
    revision: 1,
    baselineB64: "ZG9j",
    at: 1,
  };
}

// A fresh module per test: installCdpLifecycleListeners latches (module
// state), and fakeBrowser.reset() drops the listeners it registered.
async function freshRegistry() {
  vi.resetModules();
  const mod = await import("@/lib/background/cdp/registry");
  const teardown = vi.spyOn(mod.cdpRegistry, "teardownAll").mockResolvedValue();
  mod.installCdpLifecycleListeners();
  return teardown;
}

// The debugger seam: fakeBrowser ships no debugger API, and the recheck tests
// must pin the REAL leak - that the refused session's debugger attach was
// actually detached - not just the registry bookkeeping.
const dbg = {
  attach: vi.fn(() => Promise.resolve()),
  detach: vi.fn(() => Promise.resolve()),
};

beforeEach(() => {
  fakeBrowser.reset();
  dbg.attach = vi.fn(() => Promise.resolve());
  dbg.detach = vi.fn(() => Promise.resolve());
  // The lifecycle install wires onDetach, and the creation recheck
  // attaches before it can refuse.
  (fakeBrowser as unknown as { debugger: unknown }).debugger = {
    attach: dbg.attach,
    detach: dbg.detach,
    onDetach: { addListener: () => {} },
  };
});

describe("cdp registry teardown is policy-driven: a cdpMode refusal detaches", () => {
  test("a policy push restricting cdpMode tears down on the push path", async () => {
    const teardown = await freshRegistry();
    // The accepted push's writes: cutover armed, record with cdpMode false.
    await fakeBrowser.storage.local.set({
      bridgePolicyCutover: true,
      bridgePolicyState: record({ cdpMode: false }),
    });
    await vi.waitFor(() => expect(teardown).toHaveBeenCalled());
  });

  test("a decision that raced a restriction cannot register a persistent session", async () => {
    // The leak this closes: a decision snapshotted cdpMode:true, a
    // restricting push landed (teardownAll fired) while a confirmation held
    // the decision open, and the decision then reached session creation -
    // nothing would ever tear the NEW session down. The creation-point
    // recheck refuses instead.
    await fakeBrowser.storage.local.set({
      bridgePolicyCutover: true,
      bridgePolicyState: record({ cdpMode: false }),
    });
    vi.resetModules();
    const mod = await import("@/lib/background/cdp/registry");
    await expect(mod.cdpRegistry.get(1)).rejects.toThrow("not granted by the effective policy");
    // The real leak, pinned: the just-made debugger attach was detached, not
    // merely dropped from the registry's bookkeeping.
    expect(dbg.detach).toHaveBeenCalledWith({ tabId: 1 });
    expect(mod.cdpRegistry.size).toBe(0);
  });

  test("a blocked posture counts as no grant at session creation", async () => {
    await fakeBrowser.storage.local.set({ bridgePolicyCutover: true }); // blocked: no record
    vi.resetModules();
    const mod = await import("@/lib/background/cdp/registry");
    await expect(mod.cdpRegistry.get(1)).rejects.toThrow("not granted by the effective policy");
    expect(dbg.detach).toHaveBeenCalledWith({ tabId: 1 });
    expect(mod.cdpRegistry.size).toBe(0);
  });

  test("an ERRORED policy read at session creation fails closed like a refusal", async () => {
    // The recheck read itself rejecting (a storage failure, not a policy
    // refusal) must not leave the just-made session attached, registered,
    // and bannered: detach, forget, and rethrow.
    vi.resetModules();
    vi.doMock("@/lib/background/effective-policy", () => ({
      getEffectivePolicy: () => Promise.reject(new Error("storage read failed")),
    }));
    try {
      const mod = await import("@/lib/background/cdp/registry");
      await expect(mod.cdpRegistry.get(1)).rejects.toThrow("storage read failed");
      expect(dbg.detach).toHaveBeenCalledWith({ tabId: 1 });
      expect(mod.cdpRegistry.size).toBe(0);
    } finally {
      vi.doUnmock("@/lib/background/effective-policy");
    }
  });
});
