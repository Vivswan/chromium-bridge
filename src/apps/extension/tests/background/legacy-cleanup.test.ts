// The Phase 5 cutover-conditional storage cleanup (legacy-cleanup.ts):
// deletes the 15 retired policy keys + requireEnrollment ONLY when the
// one-way cutover reads exactly armed AND the legacy bag has shipped
// (legacySettingsSent reads exactly true) - the ADR's "after the import path
// has shipped" condition. Pre-cutover installs (non-macOS forever, old hosts
// indefinitely) keep their stored values, an armed cutover with an UNSENT
// bag keeps them too (the only copy of a migration that can no longer
// ship), and a corrupt flag deletes NOTHING (fail-safe: keep data on
// ambiguity). Startup-sweep-only by design: no storage watch, so no deletion
// can ever interleave with a mid-life legacy enforcement read.

import { POLICY_FIELDS } from "@chromium-bridge/shared";
import { beforeEach, describe, expect, test } from "vitest";
import { fakeBrowser } from "wxt/testing";
import {
  cleanupLegacySettings,
  installLegacyCleanup,
  LEGACY_SETTINGS_KEYS,
} from "@/lib/background/legacy-cleanup";
import { resetStorageHardeningForTests } from "@/lib/background/trusted-storage";

/** A fully-populated legacy bag plus the keys that must SURVIVE cleanup. */
async function seedStorage(): Promise<void> {
  const bag: Record<string, unknown> = {};
  for (const field of POLICY_FIELDS) bag[field] = field === "disabledTools" ? ["page_eval"] : 1;
  bag.requireEnrollment = false;
  // Survivors: browser-owned settings and every policy-sync key.
  bag.allowAllSites = true;
  bag.groupTabs = false;
  bag.uiLanguage = "zh_CN";
  await fakeBrowser.storage.local.set(bag);
}

/** Both deletion preconditions: cutover armed AND the bag shipped. */
async function armAndMarkSent(): Promise<void> {
  await fakeBrowser.storage.local.set({ bridgePolicyCutover: true, legacySettingsSent: true });
}

async function storedKeys(): Promise<string[]> {
  return Object.keys(await fakeBrowser.storage.local.get(null));
}

beforeEach(() => {
  fakeBrowser.reset();
  resetStorageHardeningForTests();
  // The #32 hardening gate runs before every sweep; fakeBrowser has no
  // setAccessLevel, so stub a succeeding one (the unhardenable test below
  // overrides it with a failing stub).
  stubAccessLevel(() => Promise.resolve());
});

function stubAccessLevel(fn: () => Promise<void>): void {
  (fakeBrowser.storage.local as unknown as Record<string, unknown>).setAccessLevel = fn;
  (fakeBrowser.storage.session as unknown as Record<string, unknown>).setAccessLevel = fn;
}

describe("cleanupLegacySettings", () => {
  test("covers exactly the 15 policy fields plus requireEnrollment", () => {
    expect([...LEGACY_SETTINGS_KEYS].sort()).toEqual(
      [...POLICY_FIELDS, "requireEnrollment"].sort(),
    );
  });

  test("pre-cutover (flag absent): deletes nothing, even with the bag sent", async () => {
    await seedStorage();
    await fakeBrowser.storage.local.set({ legacySettingsSent: true });
    const before = await storedKeys();
    await cleanupLegacySettings();
    expect((await storedKeys()).sort()).toEqual(before.sort());
  });

  test("armed but the bag NEVER SHIPPED: deletes nothing (the keys are the only copy of the missed migration)", async () => {
    // Cutover arms BEFORE the record write and the bag ships only
    // pre-cutover, so armed+unsent means the bag can never ship anymore -
    // deleting now would destroy the migration source permanently.
    await seedStorage();
    await fakeBrowser.storage.local.set({ bridgePolicyCutover: true });
    const before = await storedKeys();
    await cleanupLegacySettings();
    expect((await storedKeys()).sort()).toEqual(before.sort());
  });

  test("armed AND sent: deletes the legacy keys, keeps the survivors, idempotently", async () => {
    await seedStorage();
    await armAndMarkSent();
    await cleanupLegacySettings();
    const after = await fakeBrowser.storage.local.get(null);
    for (const key of LEGACY_SETTINGS_KEYS) expect(key in after).toBe(false);
    // The survivors, untouched - the sent flag especially: deleting it
    // would re-open the send-once gate (the replant vector).
    expect(after.allowAllSites).toBe(true);
    expect(after.groupTabs).toBe(false);
    expect(after.uiLanguage).toBe("zh_CN");
    expect(after.legacySettingsSent).toBe(true);
    expect(after.bridgePolicyCutover).toBe(true);
    // Idempotent: a second sweep changes nothing.
    await cleanupLegacySettings();
    expect(await fakeBrowser.storage.local.get(null)).toEqual(after);
  });

  test.each([["garbage"], [1], [{ armed: true }], [false]])(
    "a corrupt cutover flag (%j) deletes NOTHING (fail-safe on ambiguity)",
    async (corrupt) => {
      await seedStorage();
      await fakeBrowser.storage.local.set({
        bridgePolicyCutover: corrupt,
        legacySettingsSent: true,
      });
      const before = await storedKeys();
      await cleanupLegacySettings();
      expect((await storedKeys()).sort()).toEqual(before.sort());
    },
  );

  test.each([["garbage"], [1], [{ sent: true }], [false]])(
    "a corrupt sent flag (%j) deletes NOTHING (only the exact written value warrants destruction)",
    async (corrupt) => {
      // The send-once GATE reads any present value as sent (fail closed
      // against a resend); DELETION deliberately does not share that
      // reading - destroying data needs the one value the code writes.
      await seedStorage();
      await fakeBrowser.storage.local.set({
        bridgePolicyCutover: true,
        legacySettingsSent: corrupt,
      });
      const before = await storedKeys();
      await cleanupLegacySettings();
      expect((await storedKeys()).sort()).toEqual(before.sort());
    },
  );

  test("#32: unhardenable storage sweeps nothing, whatever the flags claim", async () => {
    await seedStorage();
    await armAndMarkSent();
    stubAccessLevel(() => Promise.reject(new Error("unsupported")));
    await cleanupLegacySettings();
    expect("pageEvalEnabled" in (await fakeBrowser.storage.local.get(null))).toBe(true);
  });
});

describe("installLegacyCleanup", () => {
  test("startup sweep: an armed-and-sent state from a previous SW life is cleaned", async () => {
    await seedStorage();
    await armAndMarkSent();
    installLegacyCleanup();
    await new Promise((r) => setTimeout(r, 0)); // let the void sweep settle
    const after = await fakeBrowser.storage.local.get(null);
    for (const key of LEGACY_SETTINGS_KEYS) expect(key in after).toBe(false);
    expect(after.legacySettingsSent).toBe(true);
  });

  test("NO mid-life trigger: arming after startup does not delete until the next SW start (race closed by construction)", async () => {
    // Startup-sweep-only is the design, not an omission: with no mid-life
    // deletion, getEffectivePolicy's posture-then-keys reads can never
    // observe a deletion between them. The keys are inert post-cutover, so
    // the deferral to the next SW life costs tidiness, never enforcement.
    await seedStorage();
    installLegacyCleanup();
    await new Promise((r) => setTimeout(r, 0));
    await armAndMarkSent();
    await new Promise((r) => setTimeout(r, 0));
    expect("pageEvalEnabled" in (await fakeBrowser.storage.local.get(null))).toBe(true);
    // The next SW start (a fresh install call) sweeps.
    installLegacyCleanup();
    await new Promise((r) => setTimeout(r, 0));
    expect("pageEvalEnabled" in (await fakeBrowser.storage.local.get(null))).toBe(false);
  });
});
