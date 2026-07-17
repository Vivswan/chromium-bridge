// The post-confirmation tab re-validation (dispatch.recheckTab): a tab that
// navigated to a DIFFERENT origin while a confirmation was open must fail
// closed; same-origin navigation (SPA route change) passes and the FRESH tab
// object is what the backend acts on.

import { beforeEach, describe, expect, test } from "vitest";
import type { Browser } from "wxt/browser";
import { fakeBrowser } from "wxt/testing";
import { recheckTab } from "@/lib/background/dispatch";

beforeEach(() => {
  fakeBrowser.reset();
});

describe("recheckTab", () => {
  test("fails closed when the tab moved to another origin", async () => {
    const tab = (await fakeBrowser.tabs.create({
      url: "https://bank.example/home",
    })) as Browser.tabs.Tab;
    await fakeBrowser.tabs.update(tab.id!, { url: "https://evil.example/steal" });
    await expect(recheckTab(tab)).rejects.toThrow("navigated to a different origin");
  });

  test("same-origin navigation passes and returns the fresh tab", async () => {
    const tab = (await fakeBrowser.tabs.create({
      url: "https://bank.example/home",
    })) as Browser.tabs.Tab;
    await fakeBrowser.tabs.update(tab.id!, { url: "https://bank.example/transfer" });
    const current = await recheckTab(tab);
    expect(current.url).toBe("https://bank.example/transfer");
  });
});
