// The pre-attach info toast decode (background/precise.ts): the reply is
// parsed into a three-variant outcome, so a user's Cancel actually prevents
// the debugger attach (it used to be dead code behind truthiness sniffing),
// and anything outside the envelope is refused rather than guessed at.

import { beforeEach, describe, expect, test, vi } from "vitest";
import { browser } from "wxt/browser";
import { fakeBrowser } from "wxt/testing";
import { decodeToastReply, snapshotPrecise } from "@/lib/background/precise";

// The toast strings resolve SW-side; the locale machinery is not under test.
vi.mock("@/lib/i18n", () => ({
  initI18n: async () => {},
  t: (key: string) => key,
}));

beforeEach(() => {
  vi.restoreAllMocks();
  fakeBrowser.reset();
});

describe("decodeToastReply", () => {
  test("a cancelled toast is honored (the caller returns before attaching)", () => {
    expect(decodeToastReply({ ok: true, data: { cancelled: true } })).toEqual({
      kind: "cancelled",
    });
  });

  test("an un-cancelled toast proceeds", () => {
    expect(decodeToastReply({ ok: true, data: { cancelled: false } })).toEqual({
      kind: "proceed",
    });
  });

  test("an in-page toast failure is 'unavailable' (courtesy notice, not a gate)", () => {
    expect(decodeToastReply({ ok: false, error: "no DOM yet" })).toEqual({
      kind: "unavailable",
      reason: "no DOM yet",
    });
  });

  test("legacy and drifted replies are refused, not guessed at", () => {
    // The old wire shapes: a bare boolean and the `data || {}` collapse.
    expect(() => decodeToastReply(false)).toThrow("does not match the reply envelope");
    expect(() => decodeToastReply(true)).toThrow("does not match the reply envelope");
    expect(() => decodeToastReply({})).toThrow("does not match the reply envelope");
    expect(() => decodeToastReply({ __cancelled: true })).toThrow(
      "does not match the reply envelope",
    );
    // A conforming envelope with an unknown payload is refused too.
    expect(() => decodeToastReply({ ok: true, data: { pong: true } })).toThrow(
      "carries an unknown payload",
    );
    expect(() => decodeToastReply({ ok: true })).toThrow("carries an unknown payload");
  });
});

describe("snapshotPrecise honors the toast", () => {
  test("a cancelled toast means the debugger is NEVER attached", async () => {
    // allowAllSites skips the allowlist prompt; warnPreciseSnapshot defaults
    // to true, so the toast IS consulted.
    await fakeBrowser.storage.local.set({ allowAllSites: true });
    const tab = await fakeBrowser.tabs.create({ url: "https://example.com/x" });
    const attach = vi.fn();
    // fakeBrowser ships no debugger API; install a spy so an attach attempt
    // is a visible assertion failure instead of a confusing TypeError.
    (browser as unknown as { debugger: unknown }).debugger = { attach };
    vi.spyOn(browser.tabs, "sendMessage").mockImplementation(async (_tabId, msg) => {
      if ((msg as { op?: string }).op === "ping") return { ok: true, data: { pong: true } };
      // The user cancels the pre-attach notice.
      return { ok: true, data: { cancelled: true } };
    });
    await expect(snapshotPrecise(tab.id, {})).resolves.toEqual({ cancelled: true });
    expect(attach).not.toHaveBeenCalled();
  });
});
