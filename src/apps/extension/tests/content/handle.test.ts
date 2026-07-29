// The content script's trust boundary (lib/content/handle.ts): every message
// is parsed ONCE against ContentMsgSchema, page-acting ops are refused
// without their guard, the origin binding is enforced unconditionally, and
// _info_toast reports cancellation as structured data (so a cancel survives
// the reply envelope instead of collapsing into a falsy value).

import type { ClickProbeWire } from "@chromium-bridge/shared";
import { beforeEach, describe, expect, test, vi } from "vitest";
import { handle } from "@/lib/content/handle";
import type { ClickProbe } from "@/lib/dom/page-api";

// The toast draws and animates; the contract under test is handle()'s
// structured result, so stub the drawing. (vi.mock is hoisted above the
// imports, so the factory state must be hoisted too.)
const showInfoToast = vi.hoisted(() => vi.fn<(m: string, c?: string) => Promise<boolean>>());
vi.mock("@/lib/content/info-toast", () => ({ showInfoToast }));

// happy-dom's default document origin for this suite.
const HERE = location.origin;
const ELSEWHERE = "https://elsewhere.example";

beforeEach(() => {
  vi.clearAllMocks();
  document.body.innerHTML = "";
});

describe("the parse boundary fails closed", () => {
  test("a guardless page op is REFUSED, not run with the check skipped", async () => {
    document.body.innerHTML = `<button id="s">Go</button>`;
    await expect(handle({ op: "page_snapshot", args: {} })).rejects.toThrow(
      "does not match the SW envelope",
    );
  });

  test("a guard with an empty origin is refused", async () => {
    await expect(
      handle({ op: "page_snapshot", args: {}, guard: { expectOrigin: "" } }),
    ).rejects.toThrow("does not match the SW envelope");
  });

  test("page_click without the approved descriptor is refused", async () => {
    document.body.innerHTML = `<button id="s">Go</button>`;
    await expect(
      handle({
        op: "page_click",
        args: { selector: "#s" },
        guard: { expectOrigin: HERE },
      }),
    ).rejects.toThrow("does not match the SW envelope");
  });

  test("unknown ops and malformed envelopes are refused", async () => {
    await expect(handle({ op: "steal_cookies", args: {} })).rejects.toThrow(
      "does not match the SW envelope",
    );
    await expect(handle(null)).rejects.toThrow("does not match the SW envelope");
    await expect(handle("page_snapshot")).rejects.toThrow("does not match the SW envelope");
  });
});

describe("the origin binding is enforced unconditionally", () => {
  test("a page op bound to a different origin is refused", async () => {
    document.body.innerHTML = `<button id="s">Go</button>`;
    await expect(
      handle({ op: "page_snapshot", args: {}, guard: { expectOrigin: ELSEWHERE } }),
    ).rejects.toThrow("the page origin changed while the request was in flight");
  });

  test("a page op bound to THIS origin acts", async () => {
    document.body.innerHTML = `<button id="s">Go</button>`;
    const out = (await handle({
      op: "page_snapshot",
      args: {},
      guard: { expectOrigin: HERE },
    })) as { refCount: number };
    expect(out.refCount).toBe(1);
  });

  test("a fully-guarded click acts and is held to the approved descriptor", async () => {
    document.body.innerHTML = `<button id="s" type="submit">Pay</button>`;
    let clicked = false;
    document.getElementById("s")?.addEventListener("click", () => {
      clicked = true;
    });
    const approved: ClickProbe = {
      tagName: "BUTTON",
      role: "button",
      type: "submit",
      hasHref: false,
      name: "Pay",
    };
    // The wire descriptor and the page API's are the same shape (two-way
    // compile-time parity).
    const wire: ClickProbeWire = approved;
    const back: ClickProbe = wire;
    await handle({
      op: "page_click",
      args: { selector: "#s" },
      guard: { expectOrigin: HERE, clickExpect: back },
    });
    expect(clicked).toBe(true);
    // A swapped target is refused by the in-page re-probe.
    document.body.innerHTML = `<button id="s" type="submit">Pay $5000</button>`;
    await expect(
      handle({
        op: "page_click",
        args: { selector: "#s" },
        guard: { expectOrigin: HERE, clickExpect: approved },
      }),
    ).rejects.toThrow("click target changed");
  });
});

describe("internal ops (the only guard-less messages)", () => {
  test("ping answers without touching the page", async () => {
    expect(await handle({ op: "ping" })).toEqual({ pong: true });
  });

  test("_probe_click is a pre-approval DOM read", async () => {
    document.body.innerHTML = `<button id="s" type="submit">Pay</button>`;
    const probe = (await handle({
      op: "_probe_click",
      args: { selector: "#s" },
    })) as ClickProbe;
    expect(probe.type).toBe("submit");
  });

  test("_info_toast reports a cancel as structured data", async () => {
    showInfoToast.mockResolvedValueOnce(false); // the user cancelled
    expect(await handle({ op: "_info_toast", args: { message: "heads up" } })).toEqual({
      cancelled: true,
    });
    showInfoToast.mockResolvedValueOnce(true); // timeout elapsed / proceed
    expect(await handle({ op: "_info_toast", args: { message: "heads up" } })).toEqual({
      cancelled: false,
    });
  });
});
