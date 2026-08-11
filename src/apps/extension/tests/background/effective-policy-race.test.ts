// The belt-and-braces single-snapshot guard in effective-policy.ts: the
// legacy arm reads the cutover flag in the SAME storage.get as the 15 legacy
// fields, so a cutover arming BETWEEN the posture read and the legacy-keys
// read (the first accepted push landing mid-decision) resolves BLOCKED
// instead of enforcing legacy values under a cutover that has already begun.
// Startup-sweep-only deletion (legacy-cleanup.ts) already closes the
// read-vs-DELETE race by construction; this covers the read-vs-ARM
// interleave. The posture is mocked to hold "legacy" so the test can plant
// the flag the real posture read would otherwise see first.

import { beforeEach, describe, expect, test, vi } from "vitest";
import { fakeBrowser } from "wxt/testing";
import { getEffectivePolicy } from "@/lib/background/effective-policy";

vi.mock("@/lib/background/policy-sync", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/background/policy-sync")>();
  return {
    ...actual,
    getPolicyPosture: vi.fn(async () => ({ kind: "legacy" as const })),
  };
});

beforeEach(() => {
  fakeBrowser.reset();
});

describe("mid-decision cutover arming", () => {
  test("a cutover flag visible in the legacy-keys snapshot resolves BLOCKED, never legacy values", async () => {
    // Legacy storage says wide open; the flag landed after the (mocked
    // stale) posture read. Enforcing the legacy values now would run a
    // decision under pre-cutover rules the cutover has already ended.
    await fakeBrowser.storage.local.set({ pageEvalEnabled: true, bridgePolicyCutover: true });
    const policy = await getEffectivePolicy();
    expect(policy).toEqual({ state: "blocked", reason: expect.stringContaining("cutover") });
  });

  test("with no flag in the snapshot the legacy arm resolves normally", async () => {
    await fakeBrowser.storage.local.set({ pageEvalEnabled: false });
    const policy = await getEffectivePolicy();
    expect(policy.state).toBe("legacy");
    if (policy.state === "legacy") expect(policy.values.pageEvalEnabled).toBe(false);
  });
});
