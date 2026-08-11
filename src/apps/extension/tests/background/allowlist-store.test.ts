// Central allowlist add-validation (defense-in-depth: not UI-only). A
// submitted URL is reduced to a bare origin glob for an http(s) origin;
// anything else is refused so a malformed entry no ensureAllowed check would
// match cannot be seeded from any surface.
//
// The pending-approval flow is covered here too: the popup mirror and the
// badge are DERIVED from the resolver map through one store function, so
// concurrent prompts cannot shadow each other and a resolution cannot
// orphan another prompt's record. What only an isolated browser can prove:
// the real badge rendering and the popup surface (checks.yml browser job).

import type { PendingApproval } from "@chromium-bridge/shared";
import { beforeEach, describe, expect, test, vi } from "vitest";
import { fakeBrowser } from "wxt/testing/fake-browser";
import {
  addAllow,
  canonicalOriginGlob,
  ensureAllowed,
  getAllowlist,
  resolvePendingAllow,
  syncPendingMirror,
} from "@/lib/background/allowlist-store";

beforeEach(() => {
  fakeBrowser.reset();
});

async function readPending(): Promise<PendingApproval[] | undefined> {
  const { pendingAllow } = await fakeBrowser.storage.local.get("pendingAllow");
  return pendingAllow as PendingApproval[] | undefined;
}

/** Track a prompt's outcome without leaving an unhandled rejection. */
function outcomeOf(p: Promise<unknown>): Promise<"allowed" | "denied"> {
  return p.then(
    () => "allowed" as const,
    () => "denied" as const,
  );
}

describe("canonicalOriginGlob", () => {
  test("reduces any http(s) URL to protocol://host/*", () => {
    expect(canonicalOriginGlob("https://example.com/path?q=1")).toBe("https://example.com/*");
    expect(canonicalOriginGlob("http://a.b.example.com:8080/")).toBe(
      "http://a.b.example.com:8080/*",
    );
    expect(canonicalOriginGlob("  https://x.test  ")).toBe("https://x.test/*");
  });

  test("drops embedded credentials", () => {
    expect(canonicalOriginGlob("https://user:pass@example.com/")).toBe("https://example.com/*");
  });

  test("refuses non-http(s) and unparsable input", () => {
    expect(canonicalOriginGlob("file:///etc/passwd")).toBeNull();
    expect(canonicalOriginGlob("javascript:alert(1)")).toBeNull();
    expect(canonicalOriginGlob("not a url")).toBeNull();
    expect(canonicalOriginGlob("")).toBeNull();
    expect(canonicalOriginGlob(123)).toBeNull();
  });
});

describe("addAllow", () => {
  test("persists the canonical glob and reports ok", async () => {
    const r = await addAllow("https://example.com/deep/path");
    expect(r.ok).toBe(true);
    expect(r.list).toEqual(["https://example.com/*"]);
    expect(await getAllowlist()).toEqual(["https://example.com/*"]);
  });

  test("refuses an invalid origin without persisting", async () => {
    const r = await addAllow("file:///x");
    expect(r.ok).toBe(false);
    expect(r.error).toContain("not a valid");
    expect(await getAllowlist()).toEqual([]);
  });

  test("de-duplicates", async () => {
    await addAllow("https://example.com/a");
    const r = await addAllow("https://example.com/b");
    expect(r.list).toEqual(["https://example.com/*"]);
  });
});

describe("pending approvals (the popup mirror is derived, not parallel)", () => {
  test("two concurrent prompts are both recorded and resolve independently", async () => {
    const p1 = outcomeOf(ensureAllowed("https://a.test/page"));
    const p2 = outcomeOf(ensureAllowed("https://b.test/page"));
    // Both outstanding requests are visible - the single last-write record
    // used to let the second prompt shadow the first off the popup.
    await vi.waitFor(async () => expect(await readPending()).toHaveLength(2));
    const records = (await readPending())!;
    expect(records.map((r) => r.glob)).toEqual(["https://a.test/*", "https://b.test/*"]);
    expect(records.every((r) => r.expiresAt > Date.now())).toBe(true);
    expect(await fakeBrowser.action.getBadgeText({})).toBe("!");

    // Approving one must not orphan the other's record or badge.
    expect((await resolvePendingAllow(records[0]!.id, true)).ok).toBe(true);
    expect(await p1).toBe("allowed");
    await vi.waitFor(async () => expect(await readPending()).toHaveLength(1));
    expect((await readPending())![0]!.glob).toBe("https://b.test/*");
    expect(await fakeBrowser.action.getBadgeText({})).toBe("!");

    // Denying the last one clears the record and the badge together.
    expect((await resolvePendingAllow(records[1]!.id, false)).ok).toBe(true);
    expect(await p2).toBe("denied");
    await vi.waitFor(async () => {
      expect(await readPending()).toBeUndefined();
      expect(await fakeBrowser.action.getBadgeText({})).toBe("");
    });
    expect(await getAllowlist()).toEqual(["https://a.test/*"]);
  });

  test("the auto-deny deadline settles only its own request", async () => {
    vi.useFakeTimers();
    try {
      const p1 = outcomeOf(ensureAllowed("https://a.test/1"));
      await vi.advanceTimersByTimeAsync(0); // arm p1's deadline at t=0
      await vi.advanceTimersByTimeAsync(30_000);
      const p2 = outcomeOf(ensureAllowed("https://b.test/2"));
      await vi.advanceTimersByTimeAsync(0); // arm p2's deadline at t=30s
      expect(await readPending()).toHaveLength(2);

      // The first prompt's 60s deadline: only IT is denied.
      await vi.advanceTimersByTimeAsync(30_000);
      expect(await p1).toBe("denied");
      expect(await readPending()).toHaveLength(1);
      expect(await fakeBrowser.action.getBadgeText({})).toBe("!");

      // The second one's deadline clears everything.
      await vi.advanceTimersByTimeAsync(30_000);
      expect(await p2).toBe("denied");
      expect(await readPending()).toBeUndefined();
      expect(await fakeBrowser.action.getBadgeText({})).toBe("");
    } finally {
      vi.useRealTimers();
    }
  });

  test("an unknown id sweeps ghost records a dead worker left behind", async () => {
    // A previous service-worker life persisted a record and died; its
    // resolver is gone. Answering it must fail - and sweep the ghost so the
    // popup stops offering an approval nobody can deliver.
    await fakeBrowser.storage.local.set({
      pendingAllow: [
        { id: "allow_ghost", glob: "https://g.test/*", expiresAt: Date.now() + 60_000 },
      ],
    });
    const r = await resolvePendingAllow("allow_ghost", true);
    expect(r.ok).toBe(false);
    expect(r.error).toContain("no such pending request");
    expect(await readPending()).toBeUndefined();
    // And crucially: no grant happened.
    expect(await getAllowlist()).toEqual([]);
  });

  test("approve racing the deadline: exactly one winner, no approval persists after a denial", async () => {
    // The settlement TOCTOU: resolvePendingAllow used to read the resolver,
    // then AWAIT the allowlist write BEFORE claiming - so the 60s deadline
    // could settle the request false DURING that await while the approve
    // still persisted the glob and returned ok, leaving an approval that
    // outlived its denial. The claim is synchronous now, so exactly one of
    // {approve, deadline} wins and the outcome is self-consistent.
    vi.useFakeTimers();
    // Park the approve mid-flight: gate the allowlist read so the deadline
    // fires while resolvePendingAllow is between "seen" and "persisted". Only
    // arm the gate for the read INSIDE resolvePendingAllow, not ensureAllowed's.
    let armed = false;
    let gateEntered = false;
    let releaseRead!: () => void;
    const readGate = new Promise<void>((r) => {
      releaseRead = r;
    });
    // get() is overloaded (promise form + Chrome callback forms); bind and
    // mockImplementation both resolve to the callback overload, so pin the
    // promise form the code under test actually calls.
    type StorageGet = (keys?: string | string[] | null) => Promise<Record<string, unknown>>;
    const realGet = fakeBrowser.storage.local.get.bind(fakeBrowser.storage.local) as StorageGet;
    const getSpy = vi.spyOn(fakeBrowser.storage.local, "get").mockImplementation((async (
      keys?: Parameters<StorageGet>[0],
    ) => {
      if (armed && keys === "allowlist") {
        gateEntered = true;
        await readGate;
      }
      return realGet(keys);
    }) as typeof fakeBrowser.storage.local.get);
    try {
      const p = outcomeOf(ensureAllowed("https://race.test/x"));
      await vi.advanceTimersByTimeAsync(0);
      const records = (await readPending())!;
      const id = records[0]!.id;

      armed = true;
      const approve = resolvePendingAllow(id, true); // claims synchronously
      await Promise.resolve(); // let it reach the gated read
      // The deadline fires WHILE the approve is parked mid-persist.
      await vi.advanceTimersByTimeAsync(60_000);
      releaseRead();
      const approveResult = await approve;
      // The race is only exercised if the approve actually reached the gated
      // read; without this the "approve wins" outcome is indistinguishable
      // from the un-raced path.
      expect(gateEntered).toBe(true);

      // Exactly one winner, and it is consistent: the synchronous claim means
      // approve took the slot, so the request is ALLOWED and its glob is on
      // the list. Pre-fix, the deadline denied the promise mid-await yet the
      // glob still landed - an approval surviving its denial.
      expect(await p).toBe("allowed");
      expect(approveResult.ok).toBe(true);
      expect(await getAllowlist()).toEqual(["https://race.test/*"]);
    } finally {
      getSpy.mockRestore();
      vi.useRealTimers();
    }
  });

  test("a persist failure denies the approval rather than unblocking an unrecorded origin", async () => {
    const p = outcomeOf(ensureAllowed("https://persist.test/x"));
    await vi.waitFor(async () => expect(await readPending()).toHaveLength(1));
    const id = (await readPending())![0]!.id;
    const spy = vi.spyOn(fakeBrowser.storage.local, "set").mockRejectedValueOnce(new Error("disk"));
    const r = await resolvePendingAllow(id, true);
    expect(r.ok).toBe(false);
    expect(await p).toBe("denied");
    expect(await getAllowlist()).toEqual([]);
    spy.mockRestore();
  });

  test("the SW-side sweep preserves a live request minted after a ghost was read", async () => {
    // The popup read an unparsable old-shape record and asked the SW to sweep
    // (sweep_pending). Between that read and the sweep, the SW minted a LIVE
    // request. The sweep re-derives storage from the resolver map, so the
    // live record is REWRITTEN, never deleted - the popup-side remove() this
    // path replaces would have deleted it here and stranded its resolver
    // until the deadline.
    await fakeBrowser.storage.local.set({ pendingAllow: { id: "old-shape", glob: "x" } });
    const p = outcomeOf(ensureAllowed("https://live.test/x"));
    await vi.waitFor(async () => expect(await readPending()).toHaveLength(1));
    await syncPendingMirror(); // the popup-triggered sweep lands late
    const records = (await readPending())!;
    expect(records).toHaveLength(1);
    expect(records[0]!.glob).toBe("https://live.test/*");
    // The live request is still answerable - nothing was stranded.
    expect((await resolvePendingAllow(records[0]!.id, true)).ok).toBe(true);
    expect(await p).toBe("allowed");
    expect(await getAllowlist()).toEqual(["https://live.test/*"]);
  });
});
