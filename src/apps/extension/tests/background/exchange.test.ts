// The one host round trip, pinned to the protocol facts the host side relies on and the source cannot express:
// control frames carry no ids, the host answers in order on one pipe, and an unanswered frame is a refusal at
// the deadline, never a hang. A detach-then-attach leaves nothing from the old connection (its waiter, its
// deadline) able to settle a request on the new one; a frame the OLD port still delivers never reaches an
// exchange, since port.ts drops it at its identity gate before the demux.

import { afterEach, describe, expect, test, vi } from "vitest";
import type { Connection } from "@/lib/background/connection";
import {
  type Claimed,
  exchange,
  type Failure,
  HOST_REPLY_TIMEOUT_MS,
} from "@/lib/background/exchange";

type Reply = { type: "a_result" | "b_result"; n: number };

function connection(accept = true): { conn: Connection; posted: object[] } {
  const posted: object[] = [];
  const conn: Connection = {
    generation: 1,
    post(frame) {
      if (accept) posted.push(frame);
      return accept;
    },
  };
  return { conn, posted };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("one request, one reply", () => {
  test("the frame posts on the attached connection and the host's reply settles the view through the reader", async () => {
    const x = exchange<Reply>("busy");
    const { conn, posted } = connection();
    x.attach(conn);
    const { posted: sent, view } = x.request(
      { type: "a" },
      { read: (r) => ({ ok: true, n: r.n }) },
    );
    expect(sent).toBe(true);
    expect(posted).toEqual([{ type: "a" }]);
    expect(x.isOpen()).toBe(true);
    expect(x.answer({ type: "a_result", n: 7 })).toBe(true);
    await expect(view).resolves.toEqual({ ok: true, n: 7 });
    // The slot is free again, and the same reply arriving twice is unsolicited the second time.
    expect(x.isOpen()).toBe(false);
    expect(x.answer({ type: "a_result", n: 7 })).toBe(false);
  });

  test("a reply wearing a tag the request did not ask for is unsolicited and the request stays open", async () => {
    const x = exchange<Reply>("busy");
    x.attach(connection().conn);
    const { view } = x.request({ type: "a" }, { replies: ["a_result"], read: (r) => r.n });
    expect(x.answer({ type: "b_result", n: 1 })).toBe(false);
    expect(x.isOpen()).toBe(true);
    expect(x.answer({ type: "a_result", n: 2 })).toBe(true);
    await expect(view).resolves.toBe(2);
  });
});

describe("every way a reply fails to arrive is a refusal, never a hang", () => {
  // One axis varies: how the reply fails to arrive. The whole Failure is asserted, since kill.ts maps
  // `why` and `posted` onto what the options page paints.
  const cases: Array<{
    name: string;
    arrange: (x: ReturnType<typeof exchange<Reply>>) => void;
    act: (x: ReturnType<typeof exchange<Reply>>) => void;
    failure: Failure;
  }> = [
    {
      name: "no connection",
      arrange: () => {},
      act: () => {},
      failure: { why: "not-connected", error: "native host not connected", posted: false },
    },
    {
      name: "a request already open",
      arrange: (x) => {
        x.attach(connection().conn);
        x.request({ type: "first" }, { read: () => null });
      },
      act: () => {},
      failure: { why: "busy", error: "the exchange's own busy text", posted: false },
    },
    {
      name: "the port refuses the frame",
      arrange: (x) => x.attach(connection(false).conn),
      act: () => {},
      failure: {
        why: "post-failed",
        error: "failed to send the request to the native host",
        posted: false,
      },
    },
    {
      name: "no reply before the deadline",
      arrange: (x) => {
        vi.useFakeTimers();
        x.attach(connection().conn);
      },
      act: () => vi.advanceTimersByTime(HOST_REPLY_TIMEOUT_MS + 1),
      failure: {
        why: "timed-out",
        error: "no reply from the native host (timed out)",
        posted: true,
      },
    },
    {
      name: "the connection detaches while the request is open",
      arrange: (x) => x.attach(connection().conn),
      act: (x) => x.detach(),
      failure: { why: "detached", error: "native host disconnected", posted: true },
    },
    {
      name: "a fresh connection attaches over the open request (the port never does this; the cell still cannot hold both)",
      arrange: (x) => x.attach(connection().conn),
      act: (x) => x.attach(connection().conn),
      failure: { why: "detached", error: "native host disconnected", posted: true },
    },
  ];

  test.each(cases)("$name", async ({ arrange, act, failure }) => {
    const x = exchange<Reply>("the exchange's own busy text");
    arrange(x);
    const seen: Failure[] = [];
    const { posted, view } = x.request(
      { type: "probe" },
      {
        read: () => "never",
        refused: (f) => {
          seen.push(f);
          return "mapped";
        },
      },
    );
    expect(posted).toBe(failure.posted);
    act(x);
    await expect(view).resolves.toBe("mapped");
    expect(seen).toEqual([failure]);
  });
});

describe("claim: close now, settle later", () => {
  test("a claimed request leaves the slot free for the next request, and only its own waiter hears the late settle", async () => {
    const x = exchange<Reply>("busy");
    x.attach(connection().conn);
    const first = x.request({ type: "a" }, { read: (r) => `first:${r.n}` });
    const claimed = x.claim();
    expect(claimed).not.toBeNull();
    expect(x.isOpen()).toBe(false);
    expect(x.claim()).toBeNull();
    expect(x.answer({ type: "a_result", n: 0 })).toBe(false);
    const second = x.request({ type: "a" }, { read: (r) => `second:${r.n}` });
    expect(second.posted).toBe(true);
    claimed?.settle({ type: "a_result", n: 1 });
    await expect(first.view).resolves.toBe("first:1");
    expect(x.isOpen()).toBe(true);
    expect(x.answer({ type: "a_result", n: 2 })).toBe(true);
    await expect(second.view).resolves.toBe("second:2");
  });

  test("a claim names the tag it answers: another request's reply set is not claimed, and a claimed fail reaches the waiter as failed", async () => {
    const x = exchange<Reply>("busy");
    x.attach(connection().conn);
    const seen: Failure[] = [];
    const { view } = x.request(
      { type: "a" },
      {
        replies: ["a_result"],
        read: () => "never",
        refused: (f) => {
          seen.push(f);
          return "failed";
        },
      },
    );
    expect(x.claim("b_result")).toBeNull();
    expect(x.isOpen()).toBe(true);
    x.claim("a_result")?.fail("the mirror could not be written");
    await expect(view).resolves.toBe("failed");
    expect(seen).toEqual([
      { why: "failed", error: "the mirror could not be written", posted: true },
    ]);
  });
});

describe("hold: a reply owed by another collaborator", () => {
  test("a hold takes the slot like a request, posts nothing, and is settled through claim() or the deadline", async () => {
    vi.useFakeTimers();
    const x = exchange<Reply>("busy");
    const { conn, posted } = connection();
    x.attach(conn);
    const held = x.hold({ replies: ["b_result"], read: (r) => `held:${r.n}` });
    expect(posted).toEqual([]);
    expect(x.isOpen()).toBe(true);
    expect(x.request({ type: "a" }, { read: () => null }).posted).toBe(false);
    expect(x.claim("a_result")).toBeNull();
    expect(x.claim()).toBeNull();
    expect(x.isOpen()).toBe(true);
    x.claim("b_result")?.settle({ type: "b_result", n: 3 });
    await expect(held).resolves.toBe("held:3");
    const unanswered = x.hold({ read: () => "never" });
    vi.advanceTimersByTime(HOST_REPLY_TIMEOUT_MS + 1);
    await expect(unanswered).resolves.toEqual({
      ok: false,
      error: "no reply from the native host (timed out)",
    });
  });
});

test("a reader narrowed to its replies cannot be handed another tag: the types refuse, so a stale @ts-expect-error fails the typecheck", () => {
  // Detached, so neither line reaches a reader; the pins are the compile errors.
  const x = exchange<Reply>("busy");
  // @ts-expect-error - a reader narrowed to one tag must name that tag in `replies`
  void x.request({ type: "a" }, { read: (r: Reply & { type: "a_result" }) => r.n }).view;
  // @ts-expect-error - a tagged claim settles with a reply wearing that tag only
  void x.claim("b_result")?.settle({ type: "a_result", n: 0 });
  // @ts-expect-error - a tagged claim cannot be widened to one over every reply
  const widened: Claimed<Reply> | null = x.claim("b_result");
  void widened;
  expect(x.isOpen()).toBe(false);
});

test("a tag the types cannot pin (a union-typed claim) is held by the value: a foreign reply throws at the claimed settle", () => {
  const x = exchange<Reply>("busy");
  x.attach(connection().conn);
  void x.hold({ replies: ["a_result"], read: (r) => r.n });
  const claimed = x.claim("a_result" as Reply["type"]);
  expect(() => claimed?.settle({ type: "b_result", n: 1 })).toThrow(/claimed for a_result/);
});

describe("detach, then attach", () => {
  test("the detach fails the old request and disarms its deadline, so the new connection starts with nothing owed", async () => {
    vi.useFakeTimers();
    const x = exchange<Reply>("busy");
    const old = connection();
    x.attach(old.conn);
    const stale = x.request({ type: "a" }, { read: () => "stale" });
    vi.advanceTimersByTime(HOST_REPLY_TIMEOUT_MS - 1_000);
    x.detach();
    await expect(stale.view).resolves.toEqual({ ok: false, error: "native host disconnected" });
    const fresh = connection();
    x.attach(fresh.conn);
    // With nothing open, the reply the old host owed is unsolicited; once a request opens on the new connection
    // the host's in-order answer to it is the next reply, and port.ts keeps the old port's frames from arriving.
    expect(x.answer({ type: "a_result", n: 1 })).toBe(false);
    const next = x.request({ type: "a" }, { read: (r) => `fresh:${r.n}` });
    expect(fresh.posted).toEqual([{ type: "a" }]);
    expect(old.posted).toEqual([{ type: "a" }]);
    // Past the old request's deadline the new request is still open: the detach disarmed that deadline. Left
    // armed, it would close whichever request is open at the time, and that is now the fresh one.
    vi.advanceTimersByTime(2_000);
    expect(x.isOpen()).toBe(true);
    expect(x.answer({ type: "a_result", n: 2 })).toBe(true);
    await expect(next.view).resolves.toBe("fresh:2");
  });

  test("an uncorrelated post rides the attached connection and is refused when detached", () => {
    const x = exchange<Reply>("busy");
    expect(x.post({ type: "engage" })).toBe(false);
    const { conn, posted } = connection();
    x.attach(conn);
    x.request({ type: "a" }, { read: () => null });
    expect(x.post({ type: "engage" })).toBe(true);
    expect(posted).toEqual([{ type: "a" }, { type: "engage" }]);
    x.detach();
    expect(x.post({ type: "engage" })).toBe(false);
  });
});
