import { beforeEach, describe, expect, test } from "vitest";
import { fakeBrowser } from "wxt/testing";
import { DEFAULTS, getSetting } from "@/lib/shared/settings";

describe("DEFAULTS", () => {
  test("has exactly the browser-owned keys and values (ADR-0032 Phase 5)", () => {
    // The 15 policy fields are host-owned (policy.gen.ts) and requireEnrollment
    // is retired; only the browser-owned settings remain here. A key appearing
    // in this list again means the Phase 5 split regressed.
    expect(Object.keys(DEFAULTS).sort()).toEqual(["allowAllSites", "groupTabs", "uiLanguage"]);
    expect(DEFAULTS.allowAllSites).toBe(false);
    expect(DEFAULTS.groupTabs).toBe(true);
    // Display language defaults to English on every surface; browser-locale
    // matching ("auto") and Chinese are explicit choices.
    expect(DEFAULTS.uiLanguage).toBe("en");
  });
});

describe("getSetting", () => {
  beforeEach(() => {
    fakeBrowser.reset();
  });

  test("returns the stored value when present", async () => {
    await fakeBrowser.storage.local.set({ groupTabs: false });
    expect(await getSetting("groupTabs")).toBe(false);
  });

  test("falls back to the default when absent", async () => {
    expect(await getSetting("allowAllSites")).toBe(false);
    expect(await getSetting("uiLanguage")).toBe("en");
  });
});
