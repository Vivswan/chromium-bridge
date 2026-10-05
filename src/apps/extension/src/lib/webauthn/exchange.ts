// The service-worker half of the WebAuthn ceremonies: request/reply exchanges over the one Connection, and
// the host-pushed presence request held for the options page. The WebAuthn calls themselves run in the page
// (ceremony.ts): a service worker has no `navigator.credentials`. port.ts drives `collaborator`;
// messages.ts routes the page's actions here. This module never imports port.ts, so there is no cycle.
//
//   enroll_begin      -> enroll_options (the page runs create) or enroll_result { ok: false }
//   enroll_finish     -> enroll_result
//   presence_request  -> held as the pending request; the page fetches it, runs get, answers
//   presence_assert   -> presence_result
//
// Fail closed: every exchange carries a deadline and resolves to a refusal, never a hang; a detach fails the
// outstanding exchange and drops the pending request, since the host that asked is gone with the port.

import {
  type EnrollBeginWire,
  type EnrollFinishWire,
  type EnrollOptionsFrame,
  EnrollOptionsFrameSchema,
  EnrollResultFrameSchema,
  type PresenceAssertWire,
  type PresenceRequestFrame,
  PresenceRequestFrameSchema,
  PresenceResultFrameSchema,
} from "@chromium-bridge/shared/envelope.gen";
import {
  type PresenceAnswer,
  type RegistrationResponse,
  type WebAuthnInboundFrame,
  WebAuthnInboundFrameSchema,
} from "@chromium-bridge/shared/webauthn";
import { browser } from "wxt/browser";
import type { Connection, PortCollaborator } from "../background/connection";
import { inLife } from "../background/in-life";

/** How long the host has to answer before an exchange fails closed. Nothing here waits on the user: the
 * tap happens in the page before the frame is posted, so a local round trip is all this covers. */
export const WEBAUTHN_EXCHANGE_TIMEOUT_MS = 10_000;

export type Refused = { ok: false; error: string };
export type EnrollBeginView = { ok: true; options: EnrollOptionsFrame } | Refused;
export type EnrollFinishView = { ok: true; credentialId: string } | Refused;
export type PresenceAssertView = { ok: true } | Refused;

type ReplyTag = WebAuthnInboundFrame["type"];

/** One request awaiting a reply wearing one of `replies`. Claimed synchronously before the post, so a reply
 * cannot arrive to an empty slot; a reply wearing another tag is unsolicited and dropped. */
interface Outstanding {
  replies: readonly ReplyTag[];
  timer: ReturnType<typeof setTimeout>;
  settle: (frame: WebAuthnInboundFrame) => void;
  fail: (error: string) => void;
}

const conn = inLife<Connection | null>(() => null);
const outstanding = inLife<Outstanding | null>(() => null);
const pendingRequest = inLife<PresenceRequestFrame | null>(() => null);

export const collaborator: PortCollaborator = {
  onAttach(c) {
    conn.value = c;
  },
  onDetach() {
    conn.value = null;
    pendingRequest.value = null;
    failOutstanding("native host disconnected");
  },
  onFrame(msg) {
    if (!isWebAuthnFrame(msg)) return false;
    handleWebAuthnFrame(msg);
    return true;
  },
};

/** Classification for the port demux: one of the four host->extension WebAuthn frames. */
export function isWebAuthnFrame(msg: unknown): msg is WebAuthnInboundFrame {
  return WebAuthnInboundFrameSchema.safeParse(msg).success;
}

function failOutstanding(error: string): void {
  const current = outstanding.value;
  outstanding.value = null;
  if (current) {
    clearTimeout(current.timer);
    current.fail(error);
  }
}

/** Why a frame cannot be posted right now, or null when the slot is free. Single-flight: the host answers
 * in order on one pipe, so a second exchange is refused, never queued behind the first. */
function slotRefusal(): Refused | null {
  if (!conn.value) return { ok: false, error: "native host not connected" };
  if (outstanding.value) return { ok: false, error: "a WebAuthn exchange is already in flight" };
  return null;
}

/** Post `frame` and await a reply wearing one of `replies`, interpreted by `onReply`. `onPosted` runs once
 * the frame is on the pipe, so state that must change only for a frame the host can see changes there. */
function exchange<T>(
  frame: EnrollBeginWire | EnrollFinishWire | PresenceAssertWire,
  replies: readonly ReplyTag[],
  onReply: (frame: WebAuthnInboundFrame) => T | Refused,
  onPosted: () => void = () => {},
): Promise<T | Refused> {
  const live = conn.value;
  const refused = slotRefusal();
  if (!live || refused)
    return Promise.resolve(refused ?? { ok: false, error: "native host not connected" });
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      outstanding.value = null;
      resolve({ ok: false, error: "no reply from the native host (timed out)" });
    }, WEBAUTHN_EXCHANGE_TIMEOUT_MS);
    outstanding.value = {
      replies,
      timer,
      settle: (reply) => resolve(onReply(reply)),
      fail: (error) => resolve({ ok: false, error }),
    };
    if (!live.post(frame)) {
      clearTimeout(timer);
      outstanding.value = null;
      resolve({ ok: false, error: "failed to send the request to the native host" });
      return;
    }
    onPosted();
  });
}

/** Ask the host for the creation options of a new credential for this browser. */
export function beginEnrollment(): Promise<EnrollBeginView> {
  return exchange(
    { type: "enroll_begin" } satisfies EnrollBeginWire,
    ["enroll_options", "enroll_result"],
    (frame): EnrollBeginView => {
      if (frame.type === "enroll_options") {
        const parsed = EnrollOptionsFrameSchema.safeParse(frame);
        return parsed.success
          ? { ok: true, options: parsed.data }
          : { ok: false, error: "malformed enroll_options from host" };
      }
      const result = EnrollResultFrameSchema.safeParse(frame);
      if (!result.success || result.data.ok) {
        return { ok: false, error: "malformed enroll_result from host" };
      }
      return { ok: false, error: result.data.reason };
    },
  );
}

/** Hand the host the `navigator.credentials.create` response the page produced. */
export function finishEnrollment(response: RegistrationResponse): Promise<EnrollFinishView> {
  return exchange(
    { type: "enroll_finish", ...response } satisfies EnrollFinishWire,
    ["enroll_result"],
    (frame): EnrollFinishView => {
      const result = EnrollResultFrameSchema.safeParse(frame);
      if (!result.success) return { ok: false, error: "malformed enroll_result from host" };
      return result.data.ok
        ? { ok: true, credentialId: result.data.credential_id }
        : { ok: false, error: result.data.reason };
    },
  );
}

/** The host-pushed presence request awaiting the user's tap, or null. The page reads it, shows the
 * action, runs `navigator.credentials.get`, and answers through assertPresence. */
export function pendingPresenceRequest(): PresenceRequestFrame | null {
  return pendingRequest.value;
}

/** Hand the host the `navigator.credentials.get` response the page produced for the pending request. The
 * answer names the request's nonce: a tap made for a request the host has since replaced answers nothing,
 * and the newer request stays pending for the page to read. The request is consumed only once the answer
 * is on the pipe, so neither a busy worker nor a failed post loses a tap the user already made. */
export function assertPresence(answer: PresenceAnswer): Promise<PresenceAssertView> {
  if (!pendingRequest.value) {
    return Promise.resolve({ ok: false, error: "no presence request is pending" });
  }
  if (pendingRequest.value.nonce !== answer.nonce) {
    return Promise.resolve({ ok: false, error: "the presence request was superseded" });
  }
  const { nonce: _answered, ...response } = answer;
  return exchange(
    { type: "presence_assert", ...response } satisfies PresenceAssertWire,
    ["presence_result"],
    (frame): PresenceAssertView => {
      const result = PresenceResultFrameSchema.safeParse(frame);
      if (!result.success) return { ok: false, error: "malformed presence_result from host" };
      return result.data.ok ? { ok: true } : { ok: false, error: result.data.reason };
    },
    () => {
      pendingRequest.value = null;
    },
  );
}

/** Route one inbound WebAuthn frame: a presence request is held for the page (a newer one replaces an
 * unanswered older one, since the host has moved on); anything else answers the outstanding exchange or,
 * with none outstanding, is dropped. */
export function handleWebAuthnFrame(msg: WebAuthnInboundFrame): void {
  if (msg.type === "presence_request") {
    const parsed = PresenceRequestFrameSchema.safeParse(msg);
    if (!parsed.success) {
      console.warn("[bb] dropping malformed presence_request");
      return;
    }
    if (pendingRequest.value)
      console.warn("[bb] a newer presence request replaces the unanswered one");
    pendingRequest.value = parsed.data;
    // The page is where the tap happens, and it shows the action before asking for it.
    void browser.runtime.openOptionsPage().catch((e: unknown) => {
      console.warn("[bb] could not open the options page for the presence request", e);
    });
    return;
  }
  const current = outstanding.value;
  if (!current?.replies.includes(msg.type)) {
    console.warn(`[bb] dropping unsolicited ${msg.type}`);
    return;
  }
  outstanding.value = null;
  clearTimeout(current.timer);
  current.settle(msg);
}

/** Tests only: the first life's state again. */
export function resetWebAuthnForTests(): void {
  const current = outstanding.value;
  if (current) clearTimeout(current.timer);
  conn.reset();
  outstanding.reset();
  pendingRequest.reset();
}
