// The confirmation service's fail-closed contract, driven with a fake
// provider (no browser window needed). What CANNOT be tested here: the real
// popup window; the isolated-browser suite proves the guarded page cannot
// reach it.

import type { ConfirmPayload } from "@chromium-bridge/shared";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import type { Presentation } from "@/lib/background/confirm/service";
import {
  confirmWithUser,
  getPendingConfirm,
  installConfirmationProvider,
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
