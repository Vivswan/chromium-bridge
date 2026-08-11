// ADR-0032 Phase 3 (S2): the CDP session registry's teardown listener is
// policy-driven, not a raw legacy-settings watch. Pre-cutover the legacy
// cdpMode toggle tears sessions down exactly as before; post-cutover an
// accepted policy push whose effective cdpMode is false must tear live
// sessions down on the PUSH path (the accepted push writes the policy
// storage keys, which the listener watches), and a legacy toggle alone must
// no longer rip down sessions the policy still grants.

import { POLICY_DEFAULTS, type PolicyValues } from "@chromium-bridge/shared";
import { beforeEach, describe, expect, test, vi } from "vitest";
import { fakeBrowser } from "wxt/testing";

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

// The debugger seam: fakeBrowser ships no debugger API, and the SFX-3 tests
// must pin the REAL leak - that the refused session's debugger attach was
// actually detached (SP-3) - not just the registry bookkeeping.
const dbg = {
  attach: vi.fn(() => Promise.resolve()),
  detach: vi.fn(() => Promise.resolve()),
};

beforeEach(() => {
  fakeBrowser.reset();
  dbg.attach = vi.fn(() => Promise.resolve());
  dbg.detach = vi.fn(() => Promise.resolve());
  // The lifecycle install wires onDetach, and the SFX-3 creation recheck
  // attaches before it can refuse.
  (fakeBrowser as unknown as { debugger: unknown }).debugger = {
    attach: dbg.attach,
    detach: dbg.detach,
    onDetach: { addListener: () => {} },
  };
});

describe("cdp registry teardown is policy-driven (ADR-0032 S2)", () => {
  test("pre-cutover: the legacy cdpMode toggle still tears everything down", async () => {
    await fakeBrowser.storage.local.set({ cdpMode: true });
    const teardown = await freshRegistry();
    await fakeBrowser.storage.local.set({ cdpMode: false });
    await vi.waitFor(() => expect(teardown).toHaveBeenCalled());
  });

  test("post-cutover deny: a policy push restricting cdpMode tears down on the push path although legacy says on", async () => {
    await fakeBrowser.storage.local.set({ cdpMode: true }); // legacy: on
    const teardown = await freshRegistry();
    // The accepted push's writes: cutover armed, record with cdpMode false.
    await fakeBrowser.storage.local.set({
      bridgePolicyCutover: true,
      bridgePolicyState: record({ cdpMode: false }),
    });
    await vi.waitFor(() => expect(teardown).toHaveBeenCalled());
  });

  test("post-cutover grant: a legacy toggle cannot rip down sessions the policy still grants", async () => {
    await fakeBrowser.storage.local.set({
      cdpMode: true,
      bridgePolicyCutover: true,
      bridgePolicyState: record({ cdpMode: true }),
    });
    const teardown = await freshRegistry();
    await fakeBrowser.storage.local.set({ cdpMode: false }); // legacy flips off
    // Give the async handler a beat; the policy-resolved mode is still true.
    await new Promise((r) => setTimeout(r, 10));
    expect(teardown).not.toHaveBeenCalled();
  });

  test("a decision that raced a restriction cannot register a persistent session (SFX-3)", async () => {
    // The leak this closes: a decision snapshotted cdpMode:true, a
    // restricting push landed (teardownAll fired) while a confirmation held
    // the decision open, and the decision then reached session creation -
    // nothing would ever tear the NEW session down. The creation-point
    // recheck refuses instead.
    await fakeBrowser.storage.local.set({
      cdpMode: true, // the stale legacy grant the decision started under
      bridgePolicyCutover: true,
      bridgePolicyState: record({ cdpMode: false }),
    });
    vi.resetModules();
    const mod = await import("@/lib/background/cdp/registry");
    await expect(mod.cdpRegistry.get(1)).rejects.toThrow("not granted by the effective policy");
    // The real leak, pinned: the just-made debugger attach was detached, not
    // merely dropped from the registry's bookkeeping (SP-3).
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

  test("an ERRORED policy read at session creation fails closed like a refusal (CS-2)", async () => {
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
