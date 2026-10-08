// The ONE effective-policy resolution (effective-policy.ts). Pre-cutover it
// is the deny baseline; post-cutover it is the stored ratcheted effective
// from policy-sync while ACTIVE - and a BLOCKED posture (awaitingBaseline /
// compromised) is state-typed, carrying no values at all: a deny-baseline
// fold consumable outside the dispatch barrier would relax a lost record,
// and POLICY_DEFAULTS is not the restrictive pole on every field.

import { POLICY_DEFAULTS, type PolicyValues } from "@genkan/shared/generated/policy";
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
        // stored record must be in-scope to be ACTIVE.
        scope: null,
        effective: policyValues(effective),
        revision: 1,
        baselineB64: "ZG9j",
        at: 1,
      },
    });
  }
}

/** Resolve and unwrap, asserting the active arm. */
async function activeValues(): Promise<PolicyValues> {
  const policy = await getEffectivePolicy();
  expect(policy.state).toBe("active");
  if (policy.state === "blocked") throw new Error(policy.reason);
  return policy.values;
}

beforeEach(() => {
  fakeBrowser.reset();
  resetPolicySyncForTests();
});

describe("pre-cutover: a fresh install enforces the deny baseline", () => {
  test("no host push ever: the effective policy IS POLICY_DEFAULTS, so no permissive default can sneak back in", async () => {
    const policy = await getEffectivePolicy();
    expect(policy).toEqual({ state: "preCutover", values: POLICY_DEFAULTS });
    expect(POLICY_DEFAULTS.pageEvalEnabled).toBe(false);
    expect((await policyDispatchGate()).allowed).toBe(true);
  });
});

describe("post-cutover: the stored effective, never the baseline", () => {
  test("cutover with no stored effective is BLOCKED: no values to consume, and the barrier refuses the same state", async () => {
    // Post-cutover with no stored effective there is NOTHING to enforce
    // against - a fold to the deny-baseline defaults would be consumable
    // outside the barrier, and POLICY_DEFAULTS is not the restrictive pole
    // on every field (hostReverifyMs 0 is most permissive, disabledTools is
    // empty).
    await armCutover();
    // Exact shape: the blocked arm carries a reason and NO .values key - the
    // leak is closed structurally.
    await expect(getEffectivePolicy()).resolves.toEqual({
      state: "blocked",
      reason: expect.any(String),
    });
    expect((await policyDispatchGate()).allowed).toBe(false);
    // The standalone decision entry refuses too - a test or one-off caller
    // cannot start a decision in a blocked posture.
    await expect(withFreshPolicy(async () => "ran")).rejects.toThrow(/policy/);
  });

  test("a stored effective governs, field by field", async () => {
    await armCutover({ disabledTools: ["tab_list"], confirmGraceMs: 90_000, evalMask: false });
    const policy = await activeValues();
    expect(policy.disabledTools).toEqual(["tab_list"]);
    expect(policy.confirmGraceMs).toBe(90_000);
    expect(policy.evalMask).toBe(false);
  });

  test("a corrupt stored effective LATCHES: blocked behind a refusing barrier, never per-field salvage", async () => {
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
