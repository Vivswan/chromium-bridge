// The backend-independent preflight (confirm/gate.ts): risk classification,
// settings gates, grace-window behavior, and the deny paths - driven with a
// fake backend and a fake confirmation provider.

import type { ConfirmPayload } from "@chromium-bridge/shared";
import { beforeEach, describe, expect, test } from "vitest";
import type { Browser } from "wxt/browser";
import { fakeBrowser } from "wxt/testing";
import { preflightPageOp, resetClickGraceWindow } from "@/lib/background/confirm/gate";
import { installConfirmationProvider, resolveConfirm } from "@/lib/background/confirm/service";
import type { PageBackend } from "@/lib/background/page-backend";
import type { ClickProbe } from "@/lib/dom/page-api";

const TAB = { id: 7, url: "https://example.com/x", title: "Example" } as Browser.tabs.Tab;

function fakeBackend(probe: ClickProbe): PageBackend {
  return {
    probeClick: async () => probe,
    run: async () => ({}),
  };
}

const SUBMIT: ClickProbe = {
  tagName: "BUTTON",
  role: "button",
  type: "submit",
  hasHref: false,
  name: "Pay",
};
const PLAIN: ClickProbe = { tagName: "DIV", role: "", type: "", hasHref: false, name: "" };

// Auto-answering provider: records what was asked and answers immediately.
function autoProvider(approve: boolean) {
  const asked: ConfirmPayload[] = [];
  installConfirmationProvider({
    present(payload) {
      asked.push(payload);
      // Answer through the router path (resolveConfirm), like the window.
      queueMicrotask(() => resolveConfirm(payload.id, approve));
      return { verdict: new Promise<boolean>(() => {}), dismiss() {} };
    },
  });
  return asked;
}

beforeEach(() => {
  fakeBrowser.reset();
  resetClickGraceWindow();
});

describe("page_click", () => {
  test("a plain click needs no confirmation", async () => {
    const asked = autoProvider(false); // would deny if ever asked
    await preflightPageOp("page_click", { selector: "#x" }, TAB, fakeBackend(PLAIN));
    expect(asked.length).toBe(0);
  });

  test("a submit click asks, and a denial throws", async () => {
    const asked = autoProvider(false);
    await expect(
      preflightPageOp("page_click", { selector: "#x" }, TAB, fakeBackend(SUBMIT)),
    ).rejects.toThrow("user denied: submit");
    expect(asked.length).toBe(1);
    expect(asked[0]?.kind).toBe("click");
    expect(asked[0]?.origin).toBe("https://example.com");
  });

  test("an approval opens the grace window for the same tab+origin+action", async () => {
    const asked = autoProvider(true);
    await preflightPageOp("page_click", { selector: "#x" }, TAB, fakeBackend(SUBMIT));
    await preflightPageOp("page_click", { selector: "#y" }, TAB, fakeBackend(SUBMIT));
    expect(asked.length).toBe(1); // second ride was within the window
  });

  test("the grace window does NOT cross tabs", async () => {
    const asked = autoProvider(true);
    await preflightPageOp("page_click", { selector: "#x" }, TAB, fakeBackend(SUBMIT));
    const otherTab = { ...TAB, id: 8 } as Browser.tabs.Tab;
    await preflightPageOp("page_click", { selector: "#x" }, otherTab, fakeBackend(SUBMIT));
    expect(asked.length).toBe(2);
  });

  test("confirmGraceMs=0 reconfirms every click", async () => {
    await fakeBrowser.storage.local.set({ confirmGraceMs: 0 });
    const asked = autoProvider(true);
    await preflightPageOp("page_click", { selector: "#x" }, TAB, fakeBackend(SUBMIT));
    await preflightPageOp("page_click", { selector: "#x" }, TAB, fakeBackend(SUBMIT));
    expect(asked.length).toBe(2);
  });

  test("confirmHighRiskClick=false skips the gate (explicit opt-out)", async () => {
    await fakeBrowser.storage.local.set({ confirmHighRiskClick: false });
    const asked = autoProvider(false);
    await preflightPageOp("page_click", { selector: "#x" }, TAB, fakeBackend(SUBMIT));
    expect(asked.length).toBe(0);
  });
});

describe("page_press / page_select confirm on every call", () => {
  test("press asks every time, even after approvals", async () => {
    const asked = autoProvider(true);
    await preflightPageOp("page_press", { keys: "Enter" }, TAB, fakeBackend(PLAIN));
    await preflightPageOp("page_press", { keys: "Enter" }, TAB, fakeBackend(PLAIN));
    expect(asked.length).toBe(2);
    expect(asked[0]?.kind).toBe("press");
    expect(asked[0]?.detail).toBe("Enter");
  });

  test("select denial throws", async () => {
    autoProvider(false);
    await expect(
      preflightPageOp("page_select", { selector: "#s", value: "b" }, TAB, fakeBackend(PLAIN)),
    ).rejects.toThrow("user denied: select b");
  });
});

describe("page_eval", () => {
  test("the kill switch refuses before any prompt", async () => {
    await fakeBrowser.storage.local.set({ pageEvalEnabled: false });
    const asked = autoProvider(true);
    await expect(
      preflightPageOp("page_eval", { code: "return 1;" }, TAB, fakeBackend(PLAIN)),
    ).rejects.toThrow("page_eval disabled in settings");
    expect(asked.length).toBe(0);
  });

  test("every eval reconfirms - approval opens NO grace window", async () => {
    const asked = autoProvider(true);
    await preflightPageOp("page_eval", { code: "return 1;" }, TAB, fakeBackend(PLAIN));
    await preflightPageOp("page_eval", { code: "return 2;" }, TAB, fakeBackend(PLAIN));
    expect(asked.length).toBe(2);
    expect(asked[0]?.kind).toBe("eval");
    expect(asked[0]?.detail).toBe("return 1;"); // the FULL code is shown
  });

  test("denial throws and empty code is refused", async () => {
    autoProvider(false);
    await expect(
      preflightPageOp("page_eval", { code: "return 1;" }, TAB, fakeBackend(PLAIN)),
    ).rejects.toThrow("user denied page_eval");
    await expect(
      preflightPageOp("page_eval", { code: "  " }, TAB, fakeBackend(PLAIN)),
    ).rejects.toThrow("page_eval needs non-empty `code`");
  });

  test("confirmPageEval=false runs unprompted (explicit opt-out)", async () => {
    await fakeBrowser.storage.local.set({ confirmPageEval: false });
    const asked = autoProvider(false);
    await preflightPageOp("page_eval", { code: "return 1;" }, TAB, fakeBackend(PLAIN));
    expect(asked.length).toBe(0);
  });
});

describe("ungated ops", () => {
  test("page_snapshot has no preflight gate", async () => {
    const asked = autoProvider(false);
    await preflightPageOp("page_snapshot", {}, TAB, fakeBackend(PLAIN));
    expect(asked.length).toBe(0);
  });
});
