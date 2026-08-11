// ADR-0032 Phase 3, Lane S: the ONE effective-policy resolution
// (effective-policy.ts). Pre-cutover it must be byte-for-byte today's legacy
// settings (same names, same per-field salvage, settings.ts untouched until
// Phase 5); post-cutover it is the stored ratcheted effective from
// policy-sync while ACTIVE - and a BLOCKED posture (awaitingBaseline /
// compromised) is state-typed, carrying no values at all (SFX-1): the old
// deny-baseline fold could be consumed outside the dispatch barrier, and
// POLICY_DEFAULTS is not the restrictive pole on every field. The deliberate
// behavior flip is pinned below: pageEvalEnabled defaults to true under the
// legacy schema and the whole posture blocks post-cutover until a baseline
// verifies.

import { POLICY_DEFAULTS, type PolicyValues } from "@chromium-bridge/shared";
import { beforeEach, describe, expect, test } from "vitest";
import { fakeBrowser } from "wxt/testing/fake-browser";
import { getEffectivePolicy, withFreshPolicy } from "@/lib/background/effective-policy";
import { policyDispatchGate, resetPolicySyncForTests } from "@/lib/background/policy-sync";

function policyValues(overrides: Partial<PolicyValues> = {}): PolicyValues {
  return { ...POLICY_DEFAULTS, disabledTools: [], ...overrides };
}

async function armCutover(effective?: Partial<PolicyValues>): Promise<void> {
  await fakeBrowser.storage.local.set({ bridgePolicyCutover: true });
  if (effective) {
    await fakeBrowser.storage.local.set({
      bridgePolicyState: {
        // The unpinned lane's scope: these suites run with no pin, so the
        // stored record must be in-scope to be ACTIVE (ADR-0032 decision 3).
        scope: null,
        effective: policyValues(effective),
        revision: 1,
        baselineB64: "ZG9j",
        at: 1,
      },
    });
  }
}

/** Resolve and unwrap, asserting the expected non-blocked arm. */
async function effectiveValues(expectedState: "legacy" | "active"): Promise<PolicyValues> {
  const policy = await getEffectivePolicy();
  expect(policy.state).toBe(expectedState);
  if (policy.state === "blocked") throw new Error(policy.reason);
  return policy.values;
}

beforeEach(() => {
  fakeBrowser.reset();
  resetPolicySyncForTests();
});

describe("pre-cutover: the legacy settings, exactly", () => {
  test("an empty store resolves to the legacy defaults (pageEvalEnabled TRUE)", async () => {
    const policy = await effectiveValues("legacy");
    expect(policy.pageEvalEnabled).toBe(true);
    expect(policy.confirmGraceMs).toBe(60000);
    expect(policy.clickToastTimeoutMs).toBe(30000);
    expect(policy.evalToastTimeoutMs).toBe(45000);
    expect(policy.cdpMode).toBe(false);
    expect(policy.fileUploadEnabled).toBe(false);
    expect(policy.handleDialogEnabled).toBe(false);
    expect(policy.confirmHighRiskClick).toBe(true);
    expect(policy.confirmPageEval).toBe(true);
    expect(policy.touchIdConfirm).toBe(true);
    expect(policy.confirmTabClose).toBe(true);
    expect(policy.warnPreciseSnapshot).toBe(true);
    expect(policy.evalMask).toBe(true);
    expect(policy.hostReverifyMs).toBe(0);
    expect(policy.disabledTools).toEqual([]);
  });

  test("legacy storage values govern all 15 fields", async () => {
    await fakeBrowser.storage.local.set({
      pageEvalEnabled: false,
      confirmGraceMs: 5,
      disabledTools: ["tab_list"],
      cdpMode: true,
      touchIdConfirm: false,
    });
    const policy = await effectiveValues("legacy");
    expect(policy.pageEvalEnabled).toBe(false);
    expect(policy.confirmGraceMs).toBe(5);
    expect(policy.disabledTools).toEqual(["tab_list"]);
    expect(policy.cdpMode).toBe(true);
    expect(policy.touchIdConfirm).toBe(false);
  });

  test("per-field salvage: a corrupt value falls to ITS legacy default, neighbors intact", async () => {
    await fakeBrowser.storage.local.set({
      confirmGraceMs: "not a number",
      disabledTools: "not an array",
      evalMask: false,
    });
    const policy = await effectiveValues("legacy");
    expect(policy.confirmGraceMs).toBe(60000);
    expect(policy.disabledTools).toEqual([]);
    expect(policy.evalMask).toBe(false);
  });
});

describe("post-cutover: the stored effective, never the legacy bag", () => {
  test("cutover with no stored effective is BLOCKED: no values to consume, and the barrier refuses the same state", async () => {
    // Legacy storage says everything is wide open; post-cutover with no
    // stored effective there is NOTHING to enforce against (SFX-1) - the
    // old fold to the deny-baseline defaults was consumable outside the
    // barrier, and POLICY_DEFAULTS is not the restrictive pole on every
    // field (hostReverifyMs 0 is most permissive, disabledTools is empty).
    await fakeBrowser.storage.local.set({
      pageEvalEnabled: true,
      fileUploadEnabled: true,
      confirmHighRiskClick: false,
    });
    await armCutover();
    // Exact shape (CS-5): the blocked arm carries a reason and NO .values
    // key - the leak is closed structurally.
    await expect(getEffectivePolicy()).resolves.toEqual({
      state: "blocked",
      reason: expect.any(String),
    });
    expect((await policyDispatchGate()).allowed).toBe(false);
    // The standalone decision entry refuses too - a test or one-off caller
    // cannot start a decision in a blocked posture.
    await expect(withFreshPolicy(async () => "ran")).rejects.toThrow(/policy/);
  });

  test("a stored effective wins over conflicting legacy values, field by field", async () => {
    await fakeBrowser.storage.local.set({
      disabledTools: ["page_eval"],
      confirmGraceMs: 1,
      evalMask: true,
    });
    await armCutover({ disabledTools: ["tab_list"], confirmGraceMs: 90_000, evalMask: false });
    const policy = await effectiveValues("active");
    expect(policy.disabledTools).toEqual(["tab_list"]);
    expect(policy.confirmGraceMs).toBe(90_000);
    expect(policy.evalMask).toBe(false);
  });

  test("a corrupt stored effective LATCHES: blocked behind a refusing barrier, never legacy and never per-field salvage", async () => {
    await fakeBrowser.storage.local.set({ pageEvalEnabled: true });
    await fakeBrowser.storage.local.set({ bridgePolicyCutover: true });
    await fakeBrowser.storage.local.set({
      bridgePolicyState: {
        scope: null,
        effective: { pageEvalEnabled: true }, // fails the strict schema
        revision: 1,
        baselineB64: "ZG9j",
        at: 1,
      },
    });
    // Corrupt is the compromised arm (kill-mirror STRICT precedent): no
    // values to consume, and the barrier refuses the same state.
    await expect(getEffectivePolicy()).resolves.toEqual({
      state: "blocked",
      reason: expect.any(String),
    });
    expect((await policyDispatchGate()).allowed).toBe(false);
  });
});
