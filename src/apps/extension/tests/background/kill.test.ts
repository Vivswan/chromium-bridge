// ADR-0030: the extension half of the kill switch. Pins the properties the
// design leans on:
// - the gate's fail-closed matrix over the SW-only mirror (absent allows,
//   alive allows, killed/unknown/malformed all refuse);
// - the mirror is written only from host kill_status_result frames, and an
//   ok:false result maps to "unknown" (refused), never to a permissive state;
// - a page can NEVER toggle the switch: the router's sender gate is pinned in
//   messages.test.ts; here we pin that even a REFUSED set_kill leaves the
//   mirror untouched;
// - the audit ring is bounded, strict on read, and appends survive
//   interleaving.

import { beforeEach, describe, expect, test, vi } from "vitest";
import type { Browser } from "wxt/browser";
import { fakeBrowser } from "wxt/testing/fake-browser";
import { auditEvent, readRing, resetAuditForTests } from "@/lib/background/audit-log";
import {
  attachPort,
  detachPort,
  engageKill,
  getKillMirror,
  handleKillFrame,
  isKillStatusFrame,
  type KillControlFrame,
  killGate,
  killGateFromStored,
  requestKillStatus,
  resetKillForTests,
} from "@/lib/background/kill";
import { route } from "@/lib/background/messages";

const EXT_ID = "test-ext-id";

beforeEach(() => {
  fakeBrowser.reset();
  (fakeBrowser.runtime as unknown as Record<string, unknown>).id = EXT_ID;
  resetKillForTests();
  resetAuditForTests();
});

describe("kill gate fail-closed matrix", () => {
  test("absent mirror allows (fresh install; the host side enforces)", () => {
    expect(killGateFromStored(undefined)).toEqual({ allowed: true });
  });

  test("alive allows", () => {
    expect(killGateFromStored({ state: "alive", at: 1 }).allowed).toBe(true);
  });

  test("killed refuses", () => {
    const gate = killGateFromStored({ state: "killed", at: 1 });
    expect(gate.allowed).toBe(false);
  });

  test("unknown refuses (host cannot read its own state)", () => {
    expect(killGateFromStored({ state: "unknown", at: 1 }).allowed).toBe(false);
  });

  test("malformed mirror values refuse, never map to absent", () => {
    // Mapping garbage to absent would fail OPEN (absent allows); a planted or
    // corrupted value must therefore refuse.
    for (const bad of [
      null,
      42,
      "killed",
      { state: "alive" }, // missing at
      { state: "alive", at: 1, extra: true }, // strict: unknown field
      { state: "dead", at: 1 }, // unknown state word
    ]) {
      expect(killGateFromStored(bad).allowed, JSON.stringify(bad)).toBe(false);
    }
  });

  test("killGate reads the stored mirror", async () => {
    await fakeBrowser.storage.local.set({ bridgeKillMirror: { state: "killed", at: 5 } });
    expect((await killGate()).allowed).toBe(false);
    await fakeBrowser.storage.local.set({ bridgeKillMirror: { state: "alive", at: 6 } });
    expect((await killGate()).allowed).toBe(true);
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

  test("an ok:false result becomes unknown (refused), whatever it claims", async () => {
    // Even a malicious ok:false frame that smuggles killed:false must not
    // produce a permissive mirror.
    await handleKillFrame({ type: "kill_status_result", ok: false, killed: false });
    expect((await getKillMirror())?.state).toBe("unknown");
    expect((await killGate()).allowed).toBe(false);
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
    attachPort(() => true);
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
    attachPort(() => true);
    const view = requestKillStatus();
    detachPort(); // fails the pending exchange; the frame was already posted
    const frames: KillControlFrame[] = [];
    attachPort((frame) => {
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
