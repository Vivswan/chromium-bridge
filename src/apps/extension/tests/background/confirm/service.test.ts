// The confirmation service's fail-closed contract, driven with a fake
// provider (no browser window needed). What CANNOT be tested here: the real
// popup window; the isolated-browser suite proves the guarded page cannot
// reach it.

import { type ConfirmPayload, isPresenceGated } from "@chromium-bridge/shared/confirm";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { readRing } from "@/lib/background/audit-log";
import { currentPanicEpoch } from "@/lib/background/brake";
import type { Presentation } from "@/lib/background/confirm/service";
import {
  confirmWithUser,
  getPendingConfirm,
  installConfirmationProvider,
  installPresenceProvider,
  resolveConfirm,
} from "@/lib/background/confirm/service";

interface FakePresentation extends Presentation {
  payload: ConfirmPayload;
  deny(): void;
  dismissed: boolean;
}

function fakeProvider() {
  const presented: FakePresentation[] = [];
  installConfirmationProvider({
    present(payload) {
      let deny!: () => void;
      const verdict = new Promise<boolean>((resolve) => {
        deny = () => resolve(false);
      });
      const p: FakePresentation = {
        payload,
        verdict,
        deny,
        dismissed: false,
        dismiss() {
          p.dismissed = true;
        },
      };
      presented.push(p);
      return p;
    },
  });
  return presented;
}

const REQ = {
  kind: "eval" as const,
  origin: "https://example.com",
  tabTitle: "Example",
  detail: "return 1;",
  timeoutMs: 5000,
  presenceRouting: false,
  // The decision-start epoch, captured the way a real caller does.
  // This suite never panics, so the module's epoch never moves.
  panicEpoch: currentPanicEpoch(),
};

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(async () => {
  // Drain anything left pending so state never leaks across tests.
  await vi.runAllTimersAsync();
  vi.useRealTimers();
});

describe("confirmWithUser", () => {
  test("approves only on an explicit resolveConfirm(true)", async () => {
    const presented = fakeProvider();
    const verdict = confirmWithUser(REQ);
    await vi.advanceTimersByTimeAsync(0);
    const shown = presented[0];
    expect(shown).toBeDefined();
    expect(resolveConfirm(shown!.payload.id, true).ok).toBe(true);
    await expect(verdict).resolves.toBe(true);
    expect(shown!.dismissed).toBe(true);
  });

  test("denies on resolveConfirm(false)", async () => {
    const presented = fakeProvider();
    const verdict = confirmWithUser(REQ);
    await vi.advanceTimersByTimeAsync(0);
    resolveConfirm(presented[0]!.payload.id, false);
    await expect(verdict).resolves.toBe(false);
  });

  test("times out to a denial and dismisses the surface", async () => {
    const presented = fakeProvider();
    const verdict = confirmWithUser(REQ);
    await vi.advanceTimersByTimeAsync(REQ.timeoutMs + 1);
    await expect(verdict).resolves.toBe(false);
    expect(presented[0]!.dismissed).toBe(true);
  });

  test("a closed surface (provider verdict=false) denies", async () => {
    const presented = fakeProvider();
    const verdict = confirmWithUser(REQ);
    await vi.advanceTimersByTimeAsync(0);
    presented[0]!.deny();
    await expect(verdict).resolves.toBe(false);
  });

  test("with no provider installed everything denies", async () => {
    // @ts-expect-error deliberately clearing the provider
    installConfirmationProvider(null);
    await expect(confirmWithUser(REQ)).resolves.toBe(false);
  });

  test("a throwing provider denies", async () => {
    installConfirmationProvider({
      present() {
        throw new Error("boom");
      },
    });
    await expect(confirmWithUser(REQ)).resolves.toBe(false);
  });

  test("resolution is single-use and id-checked", async () => {
    const presented = fakeProvider();
    const verdict = confirmWithUser(REQ);
    await vi.advanceTimersByTimeAsync(0);
    const id = presented[0]!.payload.id;
    expect(resolveConfirm("someone-elses-id", true).ok).toBe(false);
    expect(resolveConfirm(id, false).ok).toBe(true);
    // A second answer for the same id is refused - the approval cannot be
    // flipped after the fact.
    expect(resolveConfirm(id, true).ok).toBe(false);
    await expect(verdict).resolves.toBe(false);
  });

  test("requests are serialized FIFO; a queued request waits for the active one", async () => {
    const presented = fakeProvider();
    const first = confirmWithUser(REQ);
    const second = confirmWithUser({ ...REQ, detail: "second" });
    await vi.advanceTimersByTimeAsync(0);
    expect(presented.length).toBe(1);
    resolveConfirm(presented[0]!.payload.id, true);
    await first;
    await vi.advanceTimersByTimeAsync(0);
    expect(presented.length).toBe(2);
    expect(presented[1]!.payload.detail).toBe("second");
    resolveConfirm(presented[1]!.payload.id, false);
    await expect(second).resolves.toBe(false);
  });

  test("a presentation whose verdict cannot be observed denies without wedging the queue", async () => {
    // The wedge the old queue+running pair allowed: a run() step that threw
    // after claiming occupancy left `running` stuck true, so every later
    // confirmation waited forever. The serializer must deny THIS request
    // and still present the next one.
    const presented: FakePresentation[] = [];
    let calls = 0;
    installConfirmationProvider({
      present(payload) {
        calls += 1;
        if (calls === 1) {
          // A presentation whose verdict accessor itself throws.
          return {
            get verdict(): Promise<boolean> {
              throw new Error("broken presentation");
            },
            dismiss() {},
          };
        }
        let deny!: () => void;
        const verdict = new Promise<boolean>((resolve) => {
          deny = () => resolve(false);
        });
        const p: FakePresentation = {
          payload,
          verdict,
          deny,
          dismissed: false,
          dismiss() {
            p.dismissed = true;
          },
        };
        presented.push(p);
        return p;
      },
    });
    const first = confirmWithUser(REQ);
    const second = confirmWithUser({ ...REQ, detail: "second" });
    await vi.advanceTimersByTimeAsync(0);
    await expect(first).resolves.toBe(false);
    await vi.advanceTimersByTimeAsync(0);
    // The queue advanced past the broken presentation.
    expect(presented.length).toBe(1);
    expect(presented[0]!.payload.detail).toBe("second");
    expect(resolveConfirm(presented[0]!.payload.id, true).ok).toBe(true);
    await expect(second).resolves.toBe(true);
  });

  test("a rejecting verdict denies and the queue advances (regression guard)", async () => {
    // Not a red-against-pre-fix guard - the old code already handled a
    // rejected verdict - but a regression pin that the serializer keeps
    // draining after one.
    let calls = 0;
    const presented = (() => {
      const list: FakePresentation[] = [];
      installConfirmationProvider({
        present(payload) {
          calls += 1;
          if (calls === 1) {
            return {
              verdict: Promise.reject(new Error("surface exploded")),
              dismiss() {},
            };
          }
          let deny!: () => void;
          const verdict = new Promise<boolean>((resolve) => {
            deny = () => resolve(false);
          });
          const p: FakePresentation = {
            payload,
            verdict,
            deny,
            dismissed: false,
            dismiss() {
              p.dismissed = true;
            },
          };
          list.push(p);
          return p;
        },
      });
      return list;
    })();
    const first = confirmWithUser(REQ);
    const second = confirmWithUser({ ...REQ, detail: "second" });
    await expect(first).resolves.toBe(false);
    await vi.advanceTimersByTimeAsync(0);
    expect(presented.length).toBe(1);
    resolveConfirm(presented[0]!.payload.id, false);
    await expect(second).resolves.toBe(false);
  });
});

describe("getPendingConfirm", () => {
  test("hands out only the active payload, by exact id", async () => {
    const presented = fakeProvider();
    const verdict = confirmWithUser(REQ);
    await vi.advanceTimersByTimeAsync(0);
    const id = presented[0]!.payload.id;
    expect(getPendingConfirm(id)?.detail).toBe(REQ.detail);
    expect(getPendingConfirm("other")).toBeNull();
    resolveConfirm(id, false);
    await verdict;
    expect(getPendingConfirm(id)).toBeNull();
  });
});

describe("the shown record follows the surface", () => {
  // The presence route asks the host before any window opens, so a presentation may end with no surface ever
  // in front of the user; the trail must not say one was shown. The ring persists across this file's tests,
  // so each case reads what it alone appended.
  async function appendedKinds(run: () => Promise<unknown>): Promise<string[]> {
    const before = (await readRing()).length;
    await run();
    await vi.advanceTimersByTimeAsync(0); // the ring write trails the verdict (log-after-decide)
    return (await readRing()).slice(before).map((e) => e.kind);
  }

  test("a presentation that ends before any surface opened leaves a denial and no confirm_shown row", async () => {
    installPresenceProvider({
      present() {
        return { verdict: Promise.resolve(false), shown: Promise.resolve(false), dismiss() {} };
      },
    });
    const kinds = await appendedKinds(() =>
      expect(confirmWithUser({ ...REQ, presenceRouting: true })).resolves.toBe(false),
    );
    expect(kinds).toEqual(["confirm_denied"]);
  });

  test("a surface that opens is recorded shown before its verdict", async () => {
    installPresenceProvider({
      present() {
        return { verdict: Promise.resolve(true), shown: Promise.resolve(true), dismiss() {} };
      },
    });
    const kinds = await appendedKinds(() =>
      expect(confirmWithUser({ ...REQ, presenceRouting: true })).resolves.toBe(true),
    );
    expect(kinds).toEqual(["confirm_shown", "confirm_allowed"]);
  });
});

describe("presence routing (the verdict travels in the request)", () => {
  // The routing decision is computed by the CALLER at decision time from its
  // per-request policy snapshot and carried in the ConfirmRequest (one snapshot
  // per decision): providerFor consults nothing live, so neither a policy push
  // nor a provider/predicate reinstall during the queue wait can re-route an
  // in-flight confirmation - the old paired-predicate race is gone with the
  // predicate itself.
  test("a true decision-time verdict presents on the presence provider, presence-marked", async () => {
    const windowShown = fakeProvider();
    const presenceShown: ConfirmPayload[] = [];
    installPresenceProvider({
      present(payload) {
        presenceShown.push(payload);
        return { verdict: Promise.resolve(false), dismiss() {} };
      },
    });
    const verdict = confirmWithUser({ ...REQ, presenceRouting: true });
    await vi.advanceTimersByTimeAsync(0);
    expect(windowShown.length).toBe(0);
    expect(presenceShown.length).toBe(1);
    expect(isPresenceGated(presenceShown[0]!)).toBe(true);
    await expect(verdict).resolves.toBe(false);
  });

  test("a false verdict routes to the window, consulting no presence provider", async () => {
    const windowShown = fakeProvider();
    const presenceShown: ConfirmPayload[] = [];
    installPresenceProvider({
      present(payload) {
        presenceShown.push(payload);
        return { verdict: Promise.resolve(false), dismiss() {} };
      },
    });
    const verdict = confirmWithUser(REQ);
    await vi.advanceTimersByTimeAsync(0);
    expect(presenceShown.length).toBe(0);
    expect(windowShown.length).toBe(1);
    expect(isPresenceGated(windowShown[0]!.payload)).toBe(false);
    resolveConfirm(windowShown[0]!.payload.id, false);
    await expect(verdict).resolves.toBe(false);
  });
});
