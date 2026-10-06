// The extension half of the kill switch. Pins the properties the design leans
// on:
// - the gate's fail-closed matrix over the SW-only mirror (absent allows,
//   alive allows, killed/unknown/malformed all refuse);
// - the mirror is written only from host kill_status_result frames, and an
//   ok:false result maps to "unknown" (refused), never to a permissive state;
// - a page can NEVER toggle the switch: the router's sender gate is pinned in
//   messages.test.ts; here we pin that even a REFUSED set_kill leaves the
//   mirror untouched;
// - the audit ring is bounded, strict on read, and appends survive
//   interleaving.

import { isKillStatusFrame } from "@chromium-bridge/shared/enclave";
import { beforeEach, describe, expect, test, vi } from "vitest";
import type { Browser } from "wxt/browser";
import { fakeBrowser } from "wxt/testing/fake-browser";
import { auditEvent, readRing, resetAuditForTests } from "@/lib/background/audit-log";
import {
  collaborator,
  engageKill,
  getKillMirror,
  handleKillFrame,
  type KillControlFrame,
  killGate,
  requestKillStatus,
  resetKillForTests,
} from "@/lib/background/kill";
import { route } from "@/lib/background/messages";
import {
  assertPresence,
  beginKillRelease,
  handleWebAuthnFrame,
  resetWebAuthnForTests,
  collaborator as webauthn,
} from "@/lib/webauthn/exchange";
import { attach } from "./fake-connection";

const EXT_ID = "test-ext-id";

beforeEach(() => {
  fakeBrowser.reset();
  (fakeBrowser.runtime as unknown as Record<string, unknown>).id = EXT_ID;
  resetKillForTests();
  resetAuditForTests();
});

describe("kill gate fail-closed matrix", () => {
  // Absent allows (a fresh install must not be bricked; the host enforces), so a malformed value mapped to absent
  // would fail OPEN: every malformed shape must refuse.
  test.each([
    ["absent", undefined, true],
    ["alive", { state: "alive", at: 1 }, true],
    ["killed", { state: "killed", at: 1 }, false],
    ["unknown (the host cannot read its own state)", { state: "unknown", at: 1 }, false],
    ["null", null, false],
    ["a number", 42, false],
    ["a bare string", "killed", false],
    ["missing at", { state: "alive" }, false],
    ["an unknown field", { state: "alive", at: 1, extra: true }, false],
    ["an unknown state word", { state: "dead", at: 1 }, false],
  ])("%s", async (_case, stored, allowed) => {
    // Planted at the read, not through set(): the fake's set() drops a null value where Chrome stores it.
    vi.spyOn(fakeBrowser.storage.local, "get").mockImplementationOnce((async () => ({
      bridgeKillMirror: stored,
    })) as typeof fakeBrowser.storage.local.get);
    const verdict = killGate();
    vi.restoreAllMocks();
    await expect(verdict).resolves.toEqual(
      allowed ? { allowed: true } : { allowed: false, reason: expect.any(String) },
    );
  });
});

describe("kill mirror updates from host frames only", () => {
  test("an ok result adopts the host's state", async () => {
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    expect((await getKillMirror())?.state).toBe("killed");
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: false });
    expect((await getKillMirror())?.state).toBe("alive");
  });

  test("an unchanged state is not rewritten (no storage.onChanged query loop)", async () => {
    // The options panel refreshes on every mirror change and queries the
    // host, whose reply lands back here; rewriting an unchanged state (with
    // a fresh `at`) would close that loop into an infinite query cycle.
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    const first = await getKillMirror();
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    expect(await getKillMirror()).toEqual(first);
  });

  test("overlapping frames apply strictly in arrival order", async () => {
    // Without serialization, the older frame's storage write could finish
    // after the newer one's and leave the mirror on the stale state.
    const p1 = handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    const p2 = handleKillFrame({ type: "kill_status_result", ok: true, killed: false });
    await Promise.all([p1, p2]);
    expect((await getKillMirror())?.state).toBe("alive");
  });

  test("the frame lane holds until the settled request has read its view, so a queued frame cannot overtake it", async () => {
    // A request's view is the host's answer to THAT request. The lane releasing before the view's storage read
    // let the next frame's write land first, and the view reported the later push's state (alive) instead.
    attach(collaborator);
    const view = requestKillStatus();
    const original = fakeBrowser.storage.local.get.bind(fakeBrowser.storage.local);
    let mirrorReads = 0;
    vi.spyOn(fakeBrowser.storage.local, "get").mockImplementation(async (...args) => {
      // Mirror reads only (the audit ring reads between them): the first is the frame's own write, the
      // second is the settled view's, the third is the next frame's write. Defer the view's past a macrotask.
      if (args[0] === "bridgeKillMirror" && ++mirrorReads === 2) {
        await new Promise((r) => setTimeout(r, 0));
      }
      return original(...(args as Parameters<typeof original>));
    });
    const p1 = handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    const p2 = handleKillFrame({ type: "kill_status_result", ok: true, killed: false });
    await Promise.all([p1, p2]);
    vi.restoreAllMocks();
    expect(mirrorReads).toBe(3);
    await expect(view).resolves.toMatchObject({ ok: true, sent: true, state: "killed" });
    expect((await getKillMirror())?.state).toBe("alive");
  });

  test("an ok:false result becomes unknown (refused), whatever it claims", async () => {
    // Even a malicious ok:false frame that smuggles killed:false must not
    // produce a permissive mirror.
    await handleKillFrame({ type: "kill_status_result", ok: false, killed: false });
    expect((await getKillMirror())?.state).toBe("unknown");
    expect((await killGate()).allowed).toBe(false);
  });

  test("an ok:false result also fails a kill_release waiting for its presence request", async () => {
    // The handoff is exchange.ts's claimKillRelease; this pins it from the real frame.
    resetWebAuthnForTests();
    attach(webauthn);
    const release = beginKillRelease();
    await handleKillFrame({
      type: "kill_status_result",
      ok: false,
      error: "trust record unreadable",
    });
    await expect(release).resolves.toEqual({ ok: false, error: "trust record unreadable" });
    expect((await getKillMirror())?.state).toBe("unknown");
  });

  // The host writes the record, then emits presence_result ok followed by kill_status_result: ok killed:false
  // when the switch released, ok:false with the error when the write failed. The panel's answer is that frame.
  test.each([
    {
      name: "the record wrote: the answer is ok and the mirror is alive",
      frame: { type: "kill_status_result" as const, ok: true, killed: false },
      verdict: { ok: true },
      mirror: "alive",
    },
    {
      name: "the record did not write: the answer is the host's error and the mirror is unknown",
      frame: {
        type: "kill_status_result" as const,
        ok: false,
        error: "trust record: permission denied",
      },
      verdict: { ok: false, error: "trust record: permission denied" },
      mirror: "unknown",
    },
  ])(
    "a release answered with presence_result ok settles from the kill_status_result that follows ($name)",
    async ({ frame, verdict, mirror }) => {
      resetWebAuthnForTests();
      attach(webauthn);
      await fakeBrowser.storage.local.set({ bridgeKillMirror: { state: "killed", at: 5 } });
      const release = beginKillRelease();
      const request = {
        type: "presence_request",
        challenge: "cHJlc2VuY2U",
        nonce: "nonce-0002",
        action: "release the kill switch",
        allowed_credential_ids: ["Y3JlZC1h"],
      };
      handleWebAuthnFrame(request as never);
      await release;
      const answered = assertPresence({
        nonce: "nonce-0002",
        credential_id: "Y3JlZC1h",
        authenticator_data: "YXV0aA",
        client_data_json: "Y2Rq",
        signature: "c2ln",
      });
      handleWebAuthnFrame({ type: "presence_result", ok: true });
      await handleKillFrame(frame);
      await expect(answered).resolves.toEqual(verdict);
      expect((await getKillMirror())?.state).toBe(mirror);
    },
  );

  test("a status reply arriving while a kill_release awaits its presence request leaves that exchange waiting", async () => {
    // The connect-time kill_status query's reply says killed:true; it is not an answer to the release.
    resetWebAuthnForTests();
    attach(webauthn);
    const release = beginKillRelease();
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    const request = {
      type: "presence_request",
      challenge: "cHJlc2VuY2U",
      nonce: "nonce-0002",
      action: "release the kill switch",
      allowed_credential_ids: ["Y3JlZC1h"],
    };
    handleWebAuthnFrame(request as never);
    await expect(release).resolves.toEqual({ ok: true, request });
  });

  test("an older frame still writing the mirror cannot settle a release outcome created after it arrived", async () => {
    // Frames are claimed at arrival: the release's own kill_status_result, not the stalled earlier one, is its answer.
    resetWebAuthnForTests();
    attach(webauthn);
    await fakeBrowser.storage.local.set({ bridgeKillMirror: { state: "killed", at: 5 } });
    let resume!: () => void;
    const stalled = new Promise<void>((resolve) => {
      resume = resolve;
    });
    const realGet = fakeBrowser.storage.local.get.bind(fakeBrowser.storage.local);
    vi.spyOn(fakeBrowser.storage.local, "get").mockImplementationOnce(async (keys) => {
      await stalled;
      return realGet(keys as never);
    });
    const earlier = handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    const release = beginKillRelease();
    handleWebAuthnFrame({
      type: "presence_request",
      challenge: "cHJlc2VuY2U",
      nonce: "nonce-0002",
      action: "release the kill switch",
      allowed_credential_ids: ["Y3JlZC1h"],
    } as never);
    await release;
    const answered = assertPresence({
      nonce: "nonce-0002",
      credential_id: "Y3JlZC1h",
      authenticator_data: "YXV0aA",
      client_data_json: "Y2Rq",
      signature: "c2ln",
    });
    handleWebAuthnFrame({ type: "presence_result", ok: true });
    const outcome = handleKillFrame({ type: "kill_status_result", ok: true, killed: false });
    resume();
    await Promise.all([earlier, outcome]);
    await expect(answered).resolves.toEqual({ ok: true });
    expect((await getKillMirror())?.state).toBe("alive");
  });

  test("an ok result missing the killed flag is unknown too", async () => {
    await handleKillFrame({ type: "kill_status_result", ok: true });
    expect((await getKillMirror())?.state).toBe("unknown");
  });

  test("an engage with no port fails without touching the mirror", async () => {
    await fakeBrowser.storage.local.set({ bridgeKillMirror: { state: "killed", at: 5 } });
    const r = await engageKill();
    expect(r.ok).toBe(false);
    expect((await getKillMirror())?.state).toBe("killed");
  });

  test("a refused (content-script) set_kill leaves an engaged mirror engaged", async () => {
    await fakeBrowser.storage.local.set({ bridgeKillMirror: { state: "killed", at: 5 } });
    const contentScriptSender = {
      id: EXT_ID,
      url: "https://evil.example/attack",
    } as Browser.runtime.MessageSender;
    const resp = await new Promise((resolve) => {
      route({ type: "set_kill", on: true }, contentScriptSender, resolve);
    });
    expect(resp).toEqual({
      ok: false,
      error: "this action is only accepted from extension pages",
    });
    expect((await getKillMirror())?.state).toBe("killed");
  });

  test("a failed mirror write settles the pending exchange ok:false, never ok:true over a stale mirror", async () => {
    // The host answered, but the STORED state - the only thing killGate
    // enforces on - could not adopt it. Reporting ok:true with the stale
    // mirror would tell the caller (options page, panic path) that the
    // transition took when the gate is still enforcing the old state.
    attach(collaborator);
    const view = requestKillStatus();
    const spy = vi
      .spyOn(fakeBrowser.storage.local, "set")
      .mockRejectedValueOnce(new Error("storage write refused"));
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    spy.mockRestore();
    const r = await view;
    expect(r.ok).toBe(false);
    expect(r.error).toContain("mirror");
    // And the mirror itself was never half-updated.
    expect(await getKillMirror()).toBeNull();
  });
});

describe("kill frame boundaries", () => {
  test("malformed or non-result frames are refused at the receive boundary", () => {
    // port.ts classifies inbound frames with this predicate; anything it
    // rejects never reaches handleKillFrame, so an adversarial frame cannot
    // touch the mirror or settle a pending exchange.
    for (const bad of [
      null,
      "kill_status_result",
      { type: "kill_status" }, // an outbound control frame, not a result
      { type: "kill_engage" },
      { type: "kill_status_result" }, // missing ok
      { type: "kill_status_result", ok: "yes" }, // non-boolean ok
      { type: "kill_status_result", ok: true, killed: "no" }, // non-boolean killed
      { type: "KILL_STATUS_RESULT", ok: true }, // case-mangled tag
    ]) {
      expect(isKillStatusFrame(bad), JSON.stringify(bad)).toBe(false);
    }
    expect(isKillStatusFrame({ type: "kill_status_result", ok: true, killed: false })).toBe(true);
  });

  test("outbound control frames are a closed union", () => {
    const post = (frame: KillControlFrame): KillControlFrame => frame;
    expect(post({ type: "kill_engage" }).type).toBe("kill_engage");
    // @ts-expect-error - a typo'd control frame must not compile; the old
    // string-sniffed cast would have posted it for real without ever arming
    // the panic-brake re-post
    post({ type: "kill_engag" });
  });

  test("a status request never arms the engage re-post", async () => {
    attach(collaborator);
    const view = requestKillStatus();
    collaborator.onDetach(); // fails the pending exchange; the frame was already posted
    const frames: object[] = [];
    attach(collaborator, (frame) => {
      frames.push(frame);
      return true;
    });
    // Only an unconfirmed kill_engage re-posts on reconnect (pinned in
    // deny-kill.test.ts); a status query must not masquerade as one.
    expect(frames).toEqual([]);
    await view;
  });
});

describe("audit ring", () => {
  test("appends land and read back newest-last", async () => {
    auditEvent("confirm_shown", { tool: "eval", name: "https://a.example" });
    auditEvent("confirm_denied", { tool: "eval", name: "https://a.example" });
    // Appends are serialized on a promise chain; give it a tick.
    await new Promise((r) => setTimeout(r, 0));
    const ring = await readRing();
    expect(ring.map((e) => e.kind)).toEqual(["confirm_shown", "confirm_denied"]);
  });

  test("the ring is bounded (oldest entries fall off)", async () => {
    for (let i = 0; i < 210; i += 1) {
      auditEvent("confirm_shown", { detail: `evt-${i}` });
    }
    await new Promise((r) => setTimeout(r, 0));
    const ring = await readRing();
    expect(ring.length).toBe(200);
    expect(ring[0]?.detail).toBe("evt-10");
    expect(ring[199]?.detail).toBe("evt-209");
  });

  test("malformed stored entries are dropped on read, not guessed at", async () => {
    await fakeBrowser.storage.local.set({
      auditRing: [
        { at: 1, kind: "confirm_shown" },
        { at: 2, kind: "not_a_kind" },
        "garbage",
        { at: 3, kind: "confirm_denied", extra: true },
      ],
    });
    const ring = await readRing();
    expect(ring).toEqual([{ at: 1, kind: "confirm_shown" }]);
  });

  test("a non-array ring reads as empty", async () => {
    await fakeBrowser.storage.local.set({ auditRing: { sneaky: true } });
    expect(await readRing()).toEqual([]);
  });
});
