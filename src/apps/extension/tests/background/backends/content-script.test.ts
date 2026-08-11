// ContentScriptBackend's transport is a trust boundary in BOTH directions:
// the outbound message must match ContentMsgSchema (a page-acting message
// without its guard is refused in the SW, before anything is sent) and the
// reply must match the PageReply envelope (anything else is refused, never
// shape-sniffed - in particular, a success payload carrying error-like fields
// is data, not a transport failure).

import { beforeEach, describe, expect, test, vi } from "vitest";
import { browser } from "wxt/browser";
import { fakeBrowser } from "wxt/testing/fake-browser";
import { ContentScriptBackend } from "@/lib/background/backends/content-script";
import type { PageOpGuard } from "@/lib/background/confirm/gate";
import type { ResolvedTab } from "@/lib/background/tabs";

const TAB = { id: 7, url: "https://example.com/x", active: true } as ResolvedTab;
const GUARD: PageOpGuard = { expectOrigin: "https://example.com" };
const PROBE = { tagName: "BUTTON", role: "button", type: "submit", hasHref: false, name: "Pay" };

// Route the backend's messaging through a scripted content script: ping (the
// injection probe) always pongs; everything else gets the canned reply.
function scriptedContent(reply: unknown) {
  const sent: unknown[] = [];
  vi.spyOn(browser.tabs, "sendMessage").mockImplementation(async (_tabId, msg) => {
    if ((msg as { op?: string }).op === "ping") return { ok: true, data: { pong: true } };
    sent.push(msg);
    return reply;
  });
  return sent;
}

beforeEach(() => {
  vi.restoreAllMocks();
  fakeBrowser.reset();
});

describe("reply envelope (parsed once, fail closed)", () => {
  test("a snapshot payload crosses the envelope unchanged (exact tool-result shape)", async () => {
    // Guards the browser suite's contract without a browser: what the content
    // script wraps as { ok: true, data } must come out of the receive
    // boundary as EXACTLY the op payload - nodes array, roles, and names
    // intact, no extra nesting and no envelope fields leaking through.
    const snapshot = {
      refCount: 2,
      nodes: [
        { ref: "e1", role: "textbox", name: "Search box", selector: "input#search" },
        { ref: "e2", role: "button", name: "Search", selector: "button#go" },
      ],
      url: "https://example.com/x",
      title: "Fixture",
    };
    scriptedContent({ ok: true, data: snapshot });
    const backend = new ContentScriptBackend();
    const out = (await backend.run("page_snapshot", {}, TAB, GUARD)) as typeof snapshot;
    expect(out).toEqual(snapshot);
    expect(out.nodes.map((n) => n.role)).toEqual(["textbox", "button"]);
    expect(out).not.toHaveProperty("ok");
    expect(out).not.toHaveProperty("data");
  });

  test("a success payload that LOOKS like an error is data, not a throw", async () => {
    // page_eval returning an Error serializes to { __error: true, ... } -
    // under the envelope that is a success payload and must come back as-is.
    const payload = { __error: true, name: "TypeError", message: "boom" };
    scriptedContent({ ok: true, data: payload });
    const backend = new ContentScriptBackend();
    await expect(
      backend.run("page_eval", { code: "return new Error('boom')" }, TAB, GUARD),
    ).resolves.toEqual(payload);
  });

  test("a failure arm throws its error", async () => {
    scriptedContent({ ok: false, error: "selector matched nothing: #x" });
    const backend = new ContentScriptBackend();
    await expect(backend.run("page_snapshot", {}, TAB, GUARD)).rejects.toThrow(
      "selector matched nothing: #x",
    );
  });

  test("a non-conforming reply is refused, never interpreted", async () => {
    scriptedContent({ some: "legacy shape" });
    const backend = new ContentScriptBackend();
    await expect(backend.run("page_snapshot", {}, TAB, GUARD)).rejects.toThrow(
      "does not match the reply envelope",
    );
  });
});

describe("outbound guard enforcement (refused before sending)", () => {
  test("a page op with an unbound guard never leaves the SW", async () => {
    const sent = scriptedContent({ ok: true, data: {} });
    const backend = new ContentScriptBackend();
    await expect(
      backend.run("page_snapshot", {}, TAB, { expectOrigin: "" } as PageOpGuard),
    ).rejects.toThrow("refusing to send a malformed content message");
    expect(sent).toHaveLength(0);
  });

  test("page_click without the approved descriptor never leaves the SW", async () => {
    const sent = scriptedContent({ ok: true, data: {} });
    const backend = new ContentScriptBackend();
    await expect(backend.run("page_click", { selector: "#s" }, TAB, GUARD)).rejects.toThrow(
      "refusing to send a malformed content message",
    );
    expect(sent).toHaveLength(0);
  });

  test("a fully-guarded click is sent with its guard intact", async () => {
    const sent = scriptedContent({ ok: true, data: { clicked: "#s", role: "button" } });
    const backend = new ContentScriptBackend();
    const guard: PageOpGuard = { expectOrigin: "https://example.com", clickExpect: PROBE };
    await backend.run("page_click", { selector: "#s" }, TAB, guard);
    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({ op: "page_click", guard });
  });

  test("_probe_click is the guard-less pre-approval read", async () => {
    const sent = scriptedContent({ ok: true, data: PROBE });
    const backend = new ContentScriptBackend();
    await expect(backend.probeClick({ selector: "#s" }, TAB)).resolves.toEqual(PROBE);
    expect(sent[0]).toMatchObject({ op: "_probe_click" });
    expect(sent[0]).not.toHaveProperty("guard");
  });

  test("an adversarial probe reply is refused at the receive boundary", async () => {
    // The probe descriptor drives the risk decision and confirmation text
    // BEFORE the click act's ContentMsgSchema check, so a drifted shape must
    // fail closed HERE, not flow into authorization. A probe that omits the
    // risk-relevant fields (e.g. `type`/`hasHref`) must not be read as a
    // low-risk plain element.
    for (const bad of [
      { tagName: "BUTTON", role: "button" }, // missing type/hasHref/name
      { tagName: "BUTTON", role: "button", type: "submit", hasHref: "no", name: "x" }, // wrong types
      "just a string",
      null,
    ]) {
      scriptedContent({ ok: true, data: bad });
      const backend = new ContentScriptBackend();
      await expect(backend.probeClick({ selector: "#s" }, TAB)).rejects.toThrow(
        "not a valid descriptor",
      );
    }
  });
});
