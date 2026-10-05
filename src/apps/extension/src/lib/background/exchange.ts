// One host round trip over the Connection: post a control frame, await the reply the host answers with. Control
// frames carry no ids and the host answers in order on one pipe, so an exchange is single-flight and a reply
// correlates by arrival. A module holds one exchange per reply family it owns and routes its inbound frame to it.
// Fail closed: an open request settles at the deadline or on detach, never hangs, and cannot outlive the
// connection it was posted on; a claimed request is its claimer's to settle.

import type { Refusal } from "@chromium-bridge/shared/runtime-msg";
import { inLife } from "../shared/in-life";
import type { Connection } from "./connection";

/** How long the host has to answer. Nothing behind an exchange waits on the user: a presence tap happens in the
 * page before its frame is posted, and a registration repair is a local file write. */
export const HOST_REPLY_TIMEOUT_MS = 10_000;

/** Why a request settled without the host's reply. `posted` is whether the frame reached the pipe, so the host
 * may still have applied it. */
export interface Failure {
  readonly why: "not-connected" | "busy" | "post-failed" | "timed-out" | "detached" | "failed";
  readonly error: string;
  readonly posted: boolean;
}

/** How one request reads its outcome. `refused` defaults to the runtime contract's refusal. `replies` names the
 * tags that answer this request when the exchange's reply type has several; absent, any reply answers. */
export interface Reading<TReply extends { type: string }, TView> {
  readonly replies?: readonly TReply["type"][];
  read(reply: TReply): TView | Promise<TView>;
  refused?(failure: Failure): TView | Promise<TView>;
}

/** A request closed by claim(): the slot is free, this waiter is still owed its outcome. Both settle once the
 * waiter's view has been read, so a caller serializing frames can hold its lane until then (kill.ts does). */
export interface Claimed<TReply> {
  settle(reply: TReply): Promise<void>;
  fail(error: string): Promise<void>;
}

export interface Exchange<TReply extends { type: string }> {
  /** port.ts detaches before it attaches, so an open request here is a contract break; it fails as detached. */
  attach(conn: Connection): void;
  detach(): void;
  isOpen(): boolean;
  /** A frame outside any correlation (kill.ts's panic engage while a request is open). False when detached. */
  post(frame: object): boolean;
  /** `posted` is known in the same synchronous turn: kill.ts anchors the brake on it before the view settles. */
  request<TView>(
    frame: object,
    how: Reading<TReply, TView>,
  ): { posted: boolean; view: Promise<TView | Refusal> };
  /** Open the slot for a reply with no frame of this exchange's to post: the reply another collaborator hands
   * over (webauthn's release outcome, delivered through claim() by kill.ts). */
  hold<TView>(how: Reading<TReply, TView>): Promise<TView | Refusal>;
  /** False when nothing is open, or the open request did not ask for this tag: the frame is unsolicited. */
  answer(reply: TReply): boolean;
  /** Close the open request now, settle it later. With `tag`, only a request that asked for that tag. */
  claim(tag?: TReply["type"]): Claimed<TReply> | null;
}

/** `settle` and `fail` resolve the waiter and return once its view has been read, whichever way that went. */
type Open<TReply> = {
  readonly state: "open";
  readonly conn: Connection;
  readonly replies: ReadonlySet<string> | null;
  readonly timer: ReturnType<typeof setTimeout>;
  readonly settle: (reply: TReply) => Promise<void>;
  readonly fail: (failure: Failure) => Promise<void>;
};

type Link<TReply> =
  | { readonly state: "detached" }
  | { readonly state: "attached"; readonly conn: Connection }
  | Open<TReply>;

const DETACHED: Failure = { why: "detached", error: "native host disconnected", posted: true };

export function exchange<TReply extends { type: string }>(
  busy: string,
  timeoutMs: number = HOST_REPLY_TIMEOUT_MS,
): Exchange<TReply> {
  const link = inLife<Link<TReply>>(() => ({ state: "detached" }));

  function close(tag?: string): Open<TReply> | null {
    const current = link.value;
    if (current.state !== "open") return null;
    if (tag !== undefined && current.replies !== null && !current.replies.has(tag)) return null;
    clearTimeout(current.timer);
    link.value = { state: "attached", conn: current.conn };
    return current;
  }

  function detach(): void {
    const open = close();
    link.value = { state: "detached" };
    void open?.fail(DETACHED);
  }

  /** Take the slot, or refuse without taking it; `conn` is the connection the slot was opened on, null when
   * refused. */
  function open<TView>(how: Reading<TReply, TView>): {
    view: Promise<TView | Refusal>;
    conn: Connection | null;
  } {
    const refused = (failure: Failure): TView | Refusal | Promise<TView> =>
      how.refused ? how.refused(failure) : { ok: false, error: failure.error };
    const current = link.value;
    if (current.state === "detached") {
      const error = "native host not connected";
      const failure: Failure = { why: "not-connected", error, posted: false };
      return { view: Promise.resolve(refused(failure)), conn: null };
    }
    if (current.state === "open") {
      const failure: Failure = { why: "busy", error: busy, posted: false };
      return { view: Promise.resolve(refused(failure)), conn: null };
    }
    const view = new Promise<TView | Refusal>((resolve) => {
      const deliver = (outcome: TView | Refusal | Promise<TView>): Promise<void> => {
        resolve(outcome);
        return Promise.resolve(outcome).then(
          () => undefined,
          () => undefined,
        );
      };
      const timer = setTimeout(() => {
        const error = "no reply from the native host (timed out)";
        void close()?.fail({ why: "timed-out", error, posted: true });
      }, timeoutMs);
      link.value = {
        state: "open",
        conn: current.conn,
        replies: how.replies ? new Set<string>(how.replies) : null,
        timer,
        settle: (reply) => deliver(how.read(reply)),
        fail: (failure) => deliver(refused(failure)),
      };
    });
    return { view, conn: current.conn };
  }

  return {
    attach(conn) {
      detach();
      link.value = { state: "attached", conn };
    },
    detach,
    isOpen: () => link.value.state === "open",
    post: (frame) => link.value.state !== "detached" && link.value.conn.post(frame),
    request<TView>(frame: object, how: Reading<TReply, TView>) {
      const { view, conn } = open(how);
      if (!conn) return { posted: false, view };
      const posted = conn.post(frame);
      if (!posted) {
        const error = "failed to send the request to the native host";
        void close()?.fail({ why: "post-failed", error, posted: false });
      }
      return { posted, view };
    },
    hold: (how) => open(how).view,
    answer(reply) {
      const open = close(reply.type);
      if (!open) return false;
      void open.settle(reply);
      return true;
    },
    claim(tag) {
      const open = close(tag);
      if (!open) return null;
      return {
        settle: open.settle,
        fail: (error) => open.fail({ why: "failed", error, posted: true }),
      };
    },
  };
}
