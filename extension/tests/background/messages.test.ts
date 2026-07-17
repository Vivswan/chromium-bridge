// Sender gating (#32): the runtime router refuses EVERY message from a
// non-extension-page sender, and confirm_* from anything but the confirmation
// window. A content script sends the router nothing, so a content-script sender
// for any of these is a compromised renderer reaching for the trust state
// (allowlist, pin, enrollment status) and must be refused. Without this gate a
// content script on an approved origin could add_allow{evil.com}.

import type { RuntimeMsg } from "@chromium-bridge/shared";
import { beforeEach, describe, expect, test } from "vitest";
import type { Browser } from "wxt/browser";
import { fakeBrowser } from "wxt/testing";
import { route } from "@/lib/background/messages";

const EXT_ID = "test-ext-id";

// A content-script sender: our extension id (content scripts share it), but an
// http(s) page URL - the discriminator the gate keys on.
const contentScriptSender = {
  id: EXT_ID,
  url: "https://evil.example/attack",
} as Browser.runtime.MessageSender;
// An extension-page sender (options/popup).
const optionsSender = {
  id: EXT_ID,
  url: `chrome-extension://${EXT_ID}/options.html`,
} as Browser.runtime.MessageSender;
// The confirmation window specifically.
const confirmSender = {
  id: EXT_ID,
  url: `chrome-extension://${EXT_ID}/confirm.html?id=x`,
} as Browser.runtime.MessageSender;

function call(msg: RuntimeMsg, sender: Browser.runtime.MessageSender): { resp: unknown } {
  const out: { resp: unknown } = { resp: undefined };
  route(msg, sender, (r) => {
    out.resp = r;
  });
  return out;
}

beforeEach(() => {
  fakeBrowser.reset();
  (fakeBrowser.runtime as unknown as Record<string, unknown>).id = EXT_ID;
});

// Every message a content script could try, and the mutating ones especially.
const GATED: RuntimeMsg[] = [
  { type: "get_allowlist" },
  { type: "add_allow", glob: "https://evil.example/*" },
  { type: "remove_allow", glob: "https://good.example/*" },
  { type: "resolve_allow", id: "allow_1", allow: true },
  { type: "get_status" },
  { type: "get_enrollment" },
  { type: "enroll_pair" },
  { type: "enroll_verify" },
  { type: "enroll_approve" },
  { type: "enroll_reject" },
  { type: "enroll_revoke" },
];

/** Invoke the router and resolve with the response the handler eventually
 * delivers. route() calls sendResponse synchronously for sync handlers and
 * later for async ones, so resolving with it as the callback covers both. */
function callAsync(msg: RuntimeMsg, sender: Browser.runtime.MessageSender): Promise<unknown> {
  return new Promise((resolve) => {
    route(msg, sender, resolve);
  });
}

describe("router sender gating (#32)", () => {
  for (const msg of GATED) {
    test(`refuses ${msg.type} from a content-script sender`, () => {
      const { resp } = call(msg, contentScriptSender);
      expect(resp).toEqual({
        ok: false,
        error: "this action is only accepted from extension pages",
      });
    });
  }

  test("a content script CANNOT seed the allowlist via add_allow", async () => {
    call({ type: "add_allow", glob: "https://evil.example/*" }, contentScriptSender);
    // Give any (refused) async path a tick; nothing should have been written.
    await new Promise((r) => setTimeout(r, 0));
    const { allowlist } = await fakeBrowser.storage.local.get("allowlist");
    expect(allowlist ?? []).toEqual([]);
  });

  test("an extension page (options) is allowed for get_allowlist and gets the list", async () => {
    await fakeBrowser.storage.local.set({ allowlist: ["https://good.example/*"] });
    const resp = (await callAsync({ type: "get_allowlist" }, optionsSender)) as { list?: string[] };
    expect(resp.list).toEqual(["https://good.example/*"]);
  });

  test("an extension page can add to the allowlist (the legit path is unbroken)", async () => {
    const resp = (await callAsync(
      { type: "add_allow", glob: "https://ok.example/deep/path" },
      optionsSender,
    )) as { ok?: boolean; list?: string[] };
    expect(resp.ok).toBe(true);
    expect(resp.list).toEqual(["https://ok.example/*"]);
  });

  test("confirm_ready/confirm_resolve require the confirm window, not any extension page", () => {
    // From the options page (an extension page) - refused as confirm-window-only.
    expect(call({ type: "confirm_ready", id: "x" }, optionsSender).resp).toEqual({
      ok: false,
      error: "confirmations are confirm-window-only",
    });
    expect(call({ type: "confirm_resolve", id: "x", approved: true }, optionsSender).resp).toEqual({
      ok: false,
      error: "confirmations are confirm-window-only",
    });
    // From a content script - refused by the top-level gate first.
    expect(
      call({ type: "confirm_resolve", id: "x", approved: true }, contentScriptSender).resp,
    ).toEqual({ ok: false, error: "this action is only accepted from extension pages" });
  });

  test("the confirm window is accepted for confirm_ready", () => {
    // No pending confirmation, so payload is null - but NOT the refusal.
    const { resp } = call({ type: "confirm_ready", id: "x" }, confirmSender);
    expect(resp).toEqual({ payload: null });
  });
});
