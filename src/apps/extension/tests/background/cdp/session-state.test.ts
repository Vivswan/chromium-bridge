// The CdpSession lifecycle state machine: a session is exactly detached,
// attaching, or attached - one value. These guards pin the interleaving the
// old attached-boolean + attaching-promise pair got wrong: a detach during
// an in-flight attach used to no-op (both fields read "not attached"),
// leaving an ownerless live debugger attach that cdpMode-off teardown could
// never reach (stuck banner).
//
// Residual gap: only an isolated browser can prove the real
// browser.debugger behavior (banner lifecycle, Chrome-initiated onDetach) -
// the checks.yml browser job covers that; these tests prove the state
// machine against a scripted debugger API.

import { beforeEach, describe, expect, test, vi } from "vitest";

const dbg = vi.hoisted(() => ({
  attach: vi.fn<() => Promise<void>>(() => Promise.resolve()),
  detach: vi.fn<() => Promise<void>>(() => Promise.resolve()),
  sendCommand: vi.fn(() => Promise.resolve({})),
}));
vi.mock("wxt/browser", () => ({ browser: { debugger: dbg } }));

import { CdpSession } from "@/lib/background/cdp/session";

function deferred() {
  let resolve!: () => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<void>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

beforeEach(() => {
  dbg.attach.mockReset().mockImplementation(() => Promise.resolve());
  dbg.detach.mockReset().mockImplementation(() => Promise.resolve());
});

describe("CdpSession state machine", () => {
  test("concurrent attaches share one in-flight browser.debugger.attach", async () => {
    const gate = deferred();
    dbg.attach.mockImplementation(() => gate.promise);
    const s = new CdpSession(1, () => true);
    const a = s.attach();
    const b = s.attach();
    gate.resolve();
    await Promise.all([a, b]);
    expect(dbg.attach).toHaveBeenCalledTimes(1);
    expect(s.isAttached).toBe(true);
  });

  test("a detach during an in-flight attach tears the won attach down", async () => {
    // The orphan case: detach used to see attached=false and no-op, so the
    // attach settling later left a live debugger attach nothing owned.
    const gate = deferred();
    dbg.attach.mockImplementation(() => gate.promise);
    const s = new CdpSession(1, () => true);
    const attaching = s.attach();
    const detaching = s.detach(); // arrives while the attach is in flight
    gate.resolve();
    await attaching;
    await detaching;
    expect(dbg.detach).toHaveBeenCalledTimes(1);
    expect(s.isAttached).toBe(false);
  });

  test("a detach during an attach that FAILS detaches nothing", async () => {
    const gate = deferred();
    dbg.attach.mockImplementation(() => gate.promise);
    const s = new CdpSession(1, () => true);
    const attaching = s.attach();
    const detaching = s.detach();
    gate.reject(new Error("tab gone"));
    await expect(attaching).rejects.toThrow("tab gone");
    await detaching;
    expect(dbg.detach).not.toHaveBeenCalled();
    expect(s.isAttached).toBe(false);
  });

  test("Chrome pulling the session mid-attach is not resurrected when the attach settles", async () => {
    const gate = deferred();
    dbg.attach.mockImplementation(() => gate.promise);
    const s = new CdpSession(1, () => true);
    const attaching = s.attach();
    s.markDetached(); // onDetach fired while our attach was in flight
    gate.resolve();
    await attaching;
    expect(s.isAttached).toBe(false);
  });

  test("a won attach nobody holds (markDetached mid-attach) is cleaned up, not orphaned", async () => {
    // The mirror of the detach-during-attach bug: markDetached lands while the
    // attach is in flight, the attach then WINS a real browser.debugger
    // attach, but the session no longer holds it. The debugger must be
    // detached so no session is left orphaned (stuck banner).
    const gate = deferred();
    dbg.attach.mockImplementation(() => gate.promise);
    const s = new CdpSession(1, () => true);
    const attaching = s.attach();
    s.markDetached();
    gate.resolve();
    await attaching;
    await Promise.resolve(); // let the settle handler's cleanup detach run
    expect(s.isAttached).toBe(false);
    expect(dbg.detach).toHaveBeenCalledTimes(1);
  });

  test("an attach failure ends detached and a later attach retries", async () => {
    dbg.attach.mockRejectedValueOnce(new Error("Another debugger is already attached"));
    const s = new CdpSession(1, () => true);
    await expect(s.attach()).rejects.toThrow(/DevTools is open on this tab/);
    expect(s.isAttached).toBe(false);
    await s.attach(); // the state consumed the failure; a retry is a fresh attach
    expect(dbg.attach).toHaveBeenCalledTimes(2);
    expect(s.isAttached).toBe(true);
  });

  test("detach while already detached is a no-op", async () => {
    const s = new CdpSession(1, () => true);
    await s.detach();
    expect(dbg.detach).not.toHaveBeenCalled();
  });

  test("attach when already attached issues no second attach", async () => {
    const s = new CdpSession(1, () => true);
    await s.attach();
    await s.attach();
    expect(dbg.attach).toHaveBeenCalledTimes(1);
  });
});
