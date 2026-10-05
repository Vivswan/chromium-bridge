import { DEFAULTS } from "@chromium-bridge/shared/settings";
import { beforeEach, describe, expect, test } from "vitest";
import { fakeBrowser } from "wxt/testing/fake-browser";
import { getSetting } from "@/lib/shared/settings";

describe("getSetting", () => {
  beforeEach(() => {
    fakeBrowser.reset();
  });

  test("returns the stored value when present", async () => {
    await fakeBrowser.storage.local.set({ groupTabs: false });
    expect(await getSetting("groupTabs")).toBe(false);
  });

  test("falls back to the schema default when absent", async () => {
    expect(await getSetting("allowAllSites")).toBe(DEFAULTS.allowAllSites);
    expect(await getSetting("uiLanguage")).toBe(DEFAULTS.uiLanguage);
  });
});
