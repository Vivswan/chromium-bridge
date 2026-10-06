import { DEFAULTS } from "@chromium-bridge/shared/settings";
import { beforeEach, describe, expect, test } from "vitest";
import { fakeBrowser } from "wxt/testing/fake-browser";
import { getSetting, readSettings } from "@/lib/shared/settings";

beforeEach(() => {
  fakeBrowser.reset();
});

describe("getSetting", () => {
  test("returns the stored value when present", async () => {
    await fakeBrowser.storage.local.set({ groupTabs: false });
    expect(await getSetting("groupTabs")).toBe(false);
  });

  test("falls back to the schema default when absent", async () => {
    expect(await getSetting("allowAllSites")).toBe(DEFAULTS.allowAllSites);
    expect(await getSetting("uiLanguage")).toBe(DEFAULTS.uiLanguage);
  });
});

describe("readSettings", () => {
  // A whole-bag parse would take every field down with one bad one; the per-field salvage is the behaviour the
  // schema alone cannot express.
  test("a bad field falls back to its default while the healthy fields survive and unknown keys are dropped", async () => {
    await fakeBrowser.storage.local.set({
      allowAllSites: true,
      groupTabs: "corrupted",
      uiLanguage: "zh_CN",
      unknownKey: "ignored",
    });
    expect(await readSettings()).toEqual({
      allowAllSites: true,
      groupTabs: DEFAULTS.groupTabs,
      uiLanguage: "zh_CN",
    });
  });

  test("an empty store reads as the defaults", async () => {
    expect(await readSettings()).toEqual(DEFAULTS);
  });
});
