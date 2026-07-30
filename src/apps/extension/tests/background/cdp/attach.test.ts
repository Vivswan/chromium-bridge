// withCdpAttach: the single owner of the reuse-or-attach / conditional-
// detach protocol the debugger-backed ops used to repeat by hand. The guard
// that matters: a transient attach is detached on EVERY exit path, and the
// registry's persistent session is NEVER detached here - the copy-pasted
// version of this protocol was one forgotten `!reusing` away from killing
// CDP mode for a tab on every later op.
//
// Residual gap: real banner/debugger behavior needs an isolated browser
// (checks.yml browser job); these tests script the debugger API.

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

const dbg = vi.hoisted(() => ({
  attach: vi.fn<() => Promise<void>>(() => Promise.resolve()),
  detach: vi.fn<() => Promise<void>>(() => Promise.resolve()),
  sendCommand: vi.fn(() => Promise.resolve({})),
}));
vi.mock("wxt/browser", () => ({ browser: { debugger: dbg } }));

import { withCdpAttach } from "@/lib/background/cdp/attach";
import { cdpRegistry } from "@/lib/background/cdp/registry";

beforeEach(() => {
  dbg.attach.mockReset().mockImplementation(() => Promise.resolve());
  dbg.detach.mockReset().mockImplementation(() => Promise.resolve());
});

afterEach(async () => {
  await cdpRegistry.teardownAll();
});

describe("withCdpAttach", () => {
  test("with no persistent session: attaches, runs, detaches", async () => {
    const result = await withCdpAttach(1, "tool_x", async ({ reused }) => {
      expect(reused).toBe(false);
      expect(dbg.attach).toHaveBeenCalledTimes(1);
      expect(dbg.detach).not.toHaveBeenCalled(); // still attached while fn runs
      return "ok";
    });
    expect(result).toBe("ok");
    expect(dbg.detach).toHaveBeenCalledTimes(1);
  });

  test("a transient attach is detached even when the op throws", async () => {
    await expect(
      withCdpAttach(1, "tool_x", async () => {
        throw new Error("op failed");
      }),
    ).rejects.toThrow("op failed");
    expect(dbg.detach).toHaveBeenCalledTimes(1);
  });

  test("rides the registry's persistent attach and NEVER detaches it", async () => {
    await cdpRegistry.get(7); // CDP mode holds the tab
    expect(dbg.attach).toHaveBeenCalledTimes(1);

    const result = await withCdpAttach(7, "tool_x", async ({ reused }) => {
      expect(reused).toBe(true);
      return 42;
    });
    expect(result).toBe(42);
    // No second attach was issued and - the forgotten-!reusing bug - the
    // persistent session was not torn down.
    expect(dbg.attach).toHaveBeenCalledTimes(1);
    expect(dbg.detach).not.toHaveBeenCalled();
    expect(cdpRegistry.hasSession(7)).toBe(true);
  });

  test("the persistent session survives even an op that throws", async () => {
    await cdpRegistry.get(7);
    await expect(
      withCdpAttach(7, "tool_x", async () => {
        throw new Error("op failed");
      }),
    ).rejects.toThrow("op failed");
    expect(dbg.detach).not.toHaveBeenCalled();
    expect(cdpRegistry.hasSession(7)).toBe(true);
  });

  test("maps the another-debugger failure to a per-tool DevTools hint", async () => {
    dbg.attach.mockRejectedValueOnce(new Error("Another debugger is already attached"));
    await expect(withCdpAttach(1, "console_get", async () => "unreachable")).rejects.toThrow(
      "console_get cannot attach: DevTools is open on this tab. Close DevTools and retry.",
    );
    expect(dbg.detach).not.toHaveBeenCalled(); // nothing to tear down
  });

  test("other attach failures propagate unmapped, with no detach", async () => {
    dbg.attach.mockRejectedValueOnce(new Error("No tab with given id"));
    await expect(withCdpAttach(1, "tool_x", async () => "unreachable")).rejects.toThrow(
      "No tab with given id",
    );
    expect(dbg.detach).not.toHaveBeenCalled();
  });

  test("the DevTools hint is mapped per tool on the REUSED path too", async () => {
    // A persistent-session attach that fails the conflict check reports it
    // already session-mapped ("DevTools is open"); the helper must still
    // surface the PER-TOOL hint on the reused path, not the generic message.
    await cdpRegistry.get(9); // hasSession(9) is now true -> reused branch
    const getSpy = vi
      .spyOn(cdpRegistry, "get")
      .mockRejectedValueOnce(
        new Error(
          "CDP mode cannot attach: DevTools is open on this tab. Close DevTools and retry.",
        ),
      );
    await expect(withCdpAttach(9, "console_get", async () => "unreachable")).rejects.toThrow(
      "console_get cannot attach: DevTools is open on this tab. Close DevTools and retry.",
    );
    expect(dbg.detach).not.toHaveBeenCalled(); // reused path never detaches
    getSpy.mockRestore();
  });
});

describe("orphan-cleanup identity (registry-wired sessions)", () => {
  test("a stale session's late-won attach cannot detach the NEWER session on its tab", async () => {
    // Session A's attach is delayed; Chrome pulls it (onDetach ->
    // handleExternalDetach) and a NEW session B attaches to the same tab.
    // When A's attach finally wins, its orphan cleanup must NOT fire the
    // TAB-scoped dbgDetach - that would rip down B's live attach.
    let resolveA!: () => void;
    dbg.attach.mockImplementationOnce(
      () =>
        new Promise<void>((r) => {
          resolveA = r;
        }),
    );
    const aPending = cdpRegistry.get(1); // session A, attach in flight
    cdpRegistry.handleExternalDetach(1); // Chrome pulled it; the registry forgets A
    const b = await cdpRegistry.get(1); // session B attaches immediately
    expect(b.isAttached).toBe(true);

    resolveA(); // A's attach wins, late
    await aPending;
    await Promise.resolve(); // let A's settle handler run
    expect(dbg.detach).not.toHaveBeenCalled();
    expect(b.isAttached).toBe(true);
    expect(cdpRegistry.hasSession(1)).toBe(true);
  });

  test("with NO current session on the tab, the late-won attach still cleans itself up", async () => {
    // Same interleaving without a successor: nobody owns the tab, so the
    // won-but-unheld attach must be detached (no ownerless debugger).
    let resolveA!: () => void;
    dbg.attach.mockImplementationOnce(
      () =>
        new Promise<void>((r) => {
          resolveA = r;
        }),
    );
    const aPending = cdpRegistry.get(2);
    cdpRegistry.handleExternalDetach(2); // forgotten; nobody re-attaches
    resolveA();
    await aPending;
    await Promise.resolve();
    expect(dbg.detach).toHaveBeenCalledTimes(1);
    expect(cdpRegistry.hasSession(2)).toBe(false);
  });
});
