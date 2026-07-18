import { beforeEach, describe, expect, test } from "vitest";
import { fakeBrowser } from "wxt/testing";
import { DEFAULTS, getSetting } from "@/lib/shared/settings";

describe("DEFAULTS", () => {
  test("has the expected keys and values", () => {
    expect(Object.keys(DEFAULTS).sort()).toEqual(
      [
        "allowAllSites",
        "cdpMode",
        "clickToastTimeoutMs",
        "confirmGraceMs",
        "confirmHighRiskClick",
        "confirmPageEval",
        "confirmTabClose",
        "disabledTools",
        "evalMask",
        "evalToastTimeoutMs",
        "fileUploadEnabled",
        "groupTabs",
        "handleDialogEnabled",
        "hostReverifyMs",
        "pageEvalEnabled",
        "requireEnrollment",
        "touchIdConfirm",
        "uiLanguage",
        "warnPreciseSnapshot",
      ].sort(),
    );
    expect(DEFAULTS.pageEvalEnabled).toBe(true);
    expect(DEFAULTS.confirmGraceMs).toBe(60000);
    expect(DEFAULTS.disabledTools).toEqual([]);
    expect(DEFAULTS.allowAllSites).toBe(false);
    expect(DEFAULTS.cdpMode).toBe(false);
    expect(DEFAULTS.groupTabs).toBe(true);
    // page_upload and page_handle_dialog are OFF by default (local-file egress /
    // un-confirmable blocked dialog); the opt-in setting is their gate.
    expect(DEFAULTS.fileUploadEnabled).toBe(false);
    expect(DEFAULTS.handleDialogEnabled).toBe(false);
    // Enrollment is on by default (ADR-0021): the bridge fails closed until a
    // host key is paired and pinned.
    expect(DEFAULTS.requireEnrollment).toBe(true);
    // Periodic host re-verification is opt-in; 0 keeps the session-granularity
    // default (verify at pairing and on demand only).
    expect(DEFAULTS.hostReverifyMs).toBe(0);
    // Per-action Touch ID confirmations (ADR-0031) default ON; they take
    // effect only on a capable, enrolled device, and opting out falls back to
    // the off-DOM window confirmation.
    expect(DEFAULTS.touchIdConfirm).toBe(true);
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
    await fakeBrowser.storage.local.set({ pageEvalEnabled: false });
    expect(await getSetting("pageEvalEnabled")).toBe(false);
  });

  test("falls back to the default when absent", async () => {
    expect(await getSetting("confirmGraceMs")).toBe(60000);
    expect(await getSetting("allowAllSites")).toBe(false);
  });
});
