// One host round trip over the Connection: post a control frame, await the reply the host answers with. Control
// frames carry no ids and the host answers in order on one pipe, so an exchange is single-flight and a reply
// correlates by arrival. A module holds one exchange per reply family it owns and routes its inbound frame to it.
// Fail closed: an open request settles at the deadline or on detach, never hangs, and cannot outlive the
// connection it was posted on; a claimed request is its claimer's to settle.

import type { Refusal } from "@genkan/shared/runtime-msg";
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

/** How one request reads its outcome. `refused` defaults to the runtime contract's refusal. The readers are
 * properties, not methods, so a reader narrower than its reading does not typecheck. */
export interface AnyReading<TReply, TView> {
  readonly replies?: undefined;
  readonly read: (reply: TReply) => TView | Promise<TView>;
  readonly refused?: (failure: Failure) => TView | Promise<TView>;
}
export interface NamedReading<TReply extends { type: string }, TView, R extends TReply["type"]> {
  readonly replies: readonly R[];
  readonly read: (reply: TReply & { type: R }) => TView | Promise<TView>;
  readonly refused?: (failure: Failure) => TView | Promise<TView>;
}
export type Reading<TReply extends { type: string }, TView, R extends TReply["type"]> =
  | AnyReading<TReply, TView>
  | NamedReading<TReply, TView, R>;

/** A request closed by claim(): the slot is free, this waiter is still owed its outcome. Both settle once the
 * waiter's view has been read, so a caller serializing frames can hold its lane until then (kill.ts does).
 * Properties, not methods, so a tagged claim cannot be widened to one over every reply. */
export interface Claimed<TReply> {
  readonly settle: (reply: TReply) => Promise<void>;
  readonly fail: (error: string) => Promise<void>;
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
    how: AnyReading<TReply, TView>,
  ): { posted: boolean; view: Promise<TView | Refusal> };
  request<TView, R extends TReply["type"]>(
    frame: object,
    how: NamedReading<TReply, TView, R>,
  ): { posted: boolean; view: Promise<TView | Refusal> };
  /** Open the slot for a reply with no frame of this exchange's to post: the reply another collaborator hands
   * over (webauthn's release outcome, delivered through claim() by kill.ts). */
  hold<TView>(how: AnyReading<TReply, TView>): Promise<TView | Refusal>;
  hold<TView, R extends TReply["type"]>(
    how: NamedReading<TReply, TView, R>,
  ): Promise<TView | Refusal>;
  /** False when nothing is open, or the open request did not ask for this tag: the frame is unsolicited. */
  answer(reply: TReply): boolean;
  /** Close the open request now, settle it later. Which request a tag may take is close()'s rule. */
  claim(): Claimed<TReply> | null;
  claim<R extends TReply["type"]>(tag: R): Claimed<TReply & { type: R }> | null;
}

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

  function take(): Open<TReply> | null {
    const current = link.value;
    if (current.state !== "open") return null;
    clearTimeout(current.timer);
    link.value = { state: "attached", conn: current.conn };
    return current;
  }

  /** The one admission to a narrowed reader: a request that named its replies is closed only by a tag among
   * them, and untagged only when it named none; a tagged claim's settle then takes that tag by type. The cast
   * at the settle site states this. */
  function close(tag?: string): Open<TReply> | null {
    const current = link.value;
    if (current.state !== "open") return null;
    const admitted = current.replies === null || (tag !== undefined && current.replies.has(tag));
    return admitted ? take() : null;
  }

  function detach(): void {
    const open = take();
    link.value = { state: "detached" };
    void open?.fail(DETACHED);
  }

  /** Take the slot, or refuse without taking it; `conn` is the connection the slot was opened on, null when
   * refused. */
  function open<TView, R extends TReply["type"]>(
    how: Reading<TReply, TView, R>,
  ): {
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
        void take()?.fail({ why: "timed-out", error, posted: true });
      }, timeoutMs);
      link.value = {
        state: "open",
        conn: current.conn,
        replies: how.replies ? new Set<string>(how.replies) : null,
        timer,
        settle: (reply) => deliver(how.read(reply as TReply & { type: R })),
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
    request<TView, R extends TReply["type"]>(frame: object, how: Reading<TReply, TView, R>) {
      const { view, conn } = open(how);
      if (!conn) return { posted: false, view };
      const posted = conn.post(frame);
      if (!posted) {
        const error = "failed to send the request to the native host";
        void take()?.fail({ why: "post-failed", error, posted: false });
      }
      return { posted, view };
    },
    hold<TView, R extends TReply["type"]>(how: Reading<TReply, TView, R>) {
      return open(how).view;
    },
    answer(reply) {
      const open = close(reply.type);
      if (!open) return false;
      void open.settle(reply);
      return true;
    },
    claim(tag?: TReply["type"]) {
      const open = close(tag);
      if (!open) return null;
      return {
        settle: open.settle,
        fail: (error: string) => open.fail({ why: "failed", error, posted: true }),
      };
    },
  };
}
