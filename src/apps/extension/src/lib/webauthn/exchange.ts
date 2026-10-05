// The service-worker half of the WebAuthn ceremonies: request/reply exchanges over the one Connection, and
// the host-pushed presence request held for the options page. The WebAuthn calls themselves run in the page
// (lib/shared/webauthn-ceremony.ts): a service worker has no `navigator.credentials`. port.ts drives `collaborator`;
// messages.ts routes the page's actions here. This module never imports port.ts, so there is no cycle.
//
//   enroll_begin      -> enroll_options (the page runs create) or enroll_result { ok: false }; on a machine
//                        with enrollments the host pushes presence_request and answers presence_required,
//                        and the enroll_begin AFTER the approved presence_assert gets the options
//   enroll_finish     -> enroll_result; an ok records the credential for the options page (recordedEnrollment)
//   kill_release      -> the pushed presence_request is the reply; the answer to that request is settled through
//                        claimKillRelease (kill.ts's handoff), not by presence_result
//   presence_request  -> held as the pending request; the page fetches it, runs get, answers
//   presence_assert   -> presence_result
//   presence_confirm  -> presence_result (the window's answer, for a browser with no enrolled credential)
//
// Fail closed: every exchange carries a deadline and resolves to a refusal, never a hang; a detach fails the
// outstanding exchange and drops the pending request, since the host that asked is gone with the port.

import {
  type EnrollBeginWire,
  type EnrollFinishWire,
  type EnrollOptionsFrame,
  EnrollOptionsFrameSchema,
  EnrollResultFrameSchema,
  type KillReleaseWire,
  type PresenceAssertWire,
  type PresenceConfirmWire,
  type PresenceRequestFrame,
  PresenceRequestFrameSchema,
  PresenceResultFrameSchema,
} from "@chromium-bridge/shared/envelope.gen";
import {
  WEBAUTHN_ENROLLMENT_KEY,
  type WebAuthnEnrollment,
  WebAuthnEnrollmentSchema,
} from "@chromium-bridge/shared/runtime-msg";
import {
  type PresenceAnswer,
  type RegistrationResponse,
  type WebAuthnInboundFrame,
  WebAuthnInboundFrameSchema,
} from "@chromium-bridge/shared/webauthn";
import { browser } from "wxt/browser";
import type { Connection, PortCollaborator } from "../background/connection";
import { inLife } from "../shared/in-life";

/** How long the host has to answer before an exchange fails closed. Nothing here waits on the user: the
 * tap happens in the page before the frame is posted, so a local round trip is all this covers. */
export const WEBAUTHN_EXCHANGE_TIMEOUT_MS = 10_000;

export type Refused = { ok: false; error: string };
export type EnrollBeginView = { ok: true; options: EnrollOptionsFrame } | Refused;
export type EnrollFinishView = { ok: true; credentialId: string } | Refused;
export type PresenceAssertView = { ok: true } | Refused;
export type KillReleaseView = { ok: true; request: PresenceRequestFrame } | Refused;
export type EnrollmentNoteView = { ok: true; enrollment: WebAuthnEnrollment | null } | Refused;

type ReplyTag = WebAuthnInboundFrame["type"];

/** The one exchange in flight. A `reply` awaits a frame wearing one of `replies`, claimed synchronously before
 * the post so a reply cannot arrive to an empty slot (a reply wearing another tag is unsolicited and dropped). A
 * `release_outcome` awaits kill.ts's handoff (claimKillRelease). */
type Outstanding =
  | {
      kind: "reply";
      replies: readonly ReplyTag[];
      timer: ReturnType<typeof setTimeout>;
      settle: (frame: WebAuthnInboundFrame) => void;
      fail: (error: string) => void;
    }
  | {
      kind: "release_outcome";
      timer: ReturnType<typeof setTimeout>;
      settle: (view: PresenceAssertView) => void;
    };

/** The host-pushed request awaiting the page's answer; `forRelease` when a kill_release asked for it, so the
 * answer's verdict is the release outcome rather than the presence verdict. */
interface PendingRequest {
  frame: PresenceRequestFrame;
  forRelease: boolean;
}

const conn = inLife<Connection | null>(() => null);
const outstanding = inLife<Outstanding | null>(() => null);
const pendingRequest = inLife<PendingRequest | null>(() => null);

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
  if (!current) return;
  clearTimeout(current.timer);
  if (current.kind === "reply") current.fail(error);
  else current.settle({ ok: false, error });
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
  frame:
    | EnrollBeginWire
    | EnrollFinishWire
    | PresenceAssertWire
    | PresenceConfirmWire
    | KillReleaseWire,
  replies: readonly ReplyTag[],
  onReply: (frame: WebAuthnInboundFrame) => T | Refused | Promise<T | Refused>,
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
      kind: "reply",
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

/** Hand the host the `navigator.credentials.create` response the page produced. An ok is noted in storage
 * for the options page; a failed note changes nothing about the enrollment the host already recorded. */
export async function finishEnrollment(response: RegistrationResponse): Promise<EnrollFinishView> {
  const view = await exchange(
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
  if (view.ok) {
    const note: WebAuthnEnrollment = { credentialId: view.credentialId, enrolledAt: Date.now() };
    await browser.storage.local.set({ [WEBAUTHN_ENROLLMENT_KEY]: note }).catch((e: unknown) => {
      console.warn("[bb] could not note the enrolled credential", e);
    });
  }
  return view;
}

/** The credential this browser last enrolled, as the worker noted it: null when nothing was ever noted here,
 * a refusal when a note is present but does not parse (so a damaged note never reads as "not enrolled"). The
 * host's trust record decides what the credential can still do. */
export async function recordedEnrollment(): Promise<EnrollmentNoteView> {
  const { [WEBAUTHN_ENROLLMENT_KEY]: value } =
    await browser.storage.local.get(WEBAUTHN_ENROLLMENT_KEY);
  if (value === undefined) return { ok: true, enrollment: null };
  const parsed = WebAuthnEnrollmentSchema.safeParse(value);
  return parsed.success
    ? { ok: true, enrollment: parsed.data }
    : { ok: false, error: "the stored enrollment note is malformed" };
}

/** Ask the host to release the kill switch. The reply is the presence request the host pushes for it, which
 * the page answers through assertPresence (or confirmPresence when the request admits no credential). */
export function beginKillRelease(): Promise<KillReleaseView> {
  return exchange(
    { type: "kill_release" } satisfies KillReleaseWire,
    ["presence_request"],
    (frame): KillReleaseView => {
      const parsed = PresenceRequestFrameSchema.safeParse(frame);
      return parsed.success
        ? { ok: true, request: parsed.data }
        : { ok: false, error: "malformed presence_request from host" };
    },
  );
}

/** The handoff from kill.ts, the one statement of it. The host's reply to a kill_release crosses the two
 * collaborators: a presence_request here, and after the page's answer passes presence (presence_result ok) the
 * host writes the record and reports that write in the kill_status_result there (ok killed:false, or ok:false
 * with the error when the write failed). Frame routing keeps claimers disjoint, so kill.ts calls this the
 * moment a kill_status_result ARRIVES, before its own lane and awaits, and later settles what it claimed: a
 * handler still writing an earlier frame's mirror must not settle a release that began after that frame. The
 * slot itself is taken synchronously inside the presence_result's settle (awaitReleaseOutcome), so the frame
 * that follows cannot find it empty.
 *
 *   release outcome awaited (presence passed)      -> claimed; the returned settle delivers the answer's verdict
 *   kill_release awaiting its request, ok:false     -> the exchange fails now with the host's reason (the record was
 *                                                     unreadable before any request), nothing to settle later
 *   anything else (a status reply, a push)          -> nothing; the reply to that exchange is still coming */
export function claimKillRelease(msg: {
  ok: boolean;
  error?: string;
}): ((view: PresenceAssertView) => void) | null {
  const current = outstanding.value;
  if (!current) return null;
  if (current.kind === "release_outcome") {
    outstanding.value = null;
    clearTimeout(current.timer);
    return current.settle;
  }
  if (!msg.ok && current.replies.includes("presence_request")) {
    failOutstanding(msg.error ?? "the host could not read its kill-switch state");
  }
  return null;
}

/** The release_outcome slot; its timing is claimKillRelease's. */
function awaitReleaseOutcome(): Promise<PresenceAssertView> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      outstanding.value = null;
      resolve({ ok: false, error: "no reply from the native host (timed out)" });
    }, WEBAUTHN_EXCHANGE_TIMEOUT_MS);
    outstanding.value = { kind: "release_outcome", timer, settle: resolve };
  });
}

/** The host-pushed presence request awaiting the user's tap, or null. The page reads it, shows the
 * action, runs `navigator.credentials.get`, and answers through assertPresence. */
export function pendingPresenceRequest(): PresenceRequestFrame | null {
  return pendingRequest.value?.frame ?? null;
}

/** Hand the host the `navigator.credentials.get` response the page produced for the pending request. The
 * answer names the request's nonce: a tap made for a request the host has since replaced answers nothing,
 * and the newer request stays pending for the page to read. The request is consumed only once the answer
 * is on the pipe, so neither a busy worker nor a failed post loses a tap the user already made. */
export function assertPresence(answer: PresenceAnswer): Promise<PresenceAssertView> {
  const { nonce, ...response } = answer;
  return answerPending(nonce, {
    type: "presence_assert",
    ...response,
  } satisfies PresenceAssertWire);
}

/** Answer the pending request with the window's confirmation instead of an assertion. Same nonce rule as
 * assertPresence; the host decides whether this browser may answer in software at all. */
export function confirmPresence(nonce: string): Promise<PresenceAssertView> {
  return answerPending(nonce, { type: "presence_confirm", nonce } satisfies PresenceConfirmWire);
}

/** The one lifecycle of an answer to the pending request, whichever frame carries it: the answer must name the
 * pending request's nonce (an answer to a superseded request answers nothing), and the request is consumed only
 * once the answer is on the pipe. A release's verdict comes through claimKillRelease, not presence_result. */
function answerPending(
  nonce: string,
  frame: PresenceAssertWire | PresenceConfirmWire,
): Promise<PresenceAssertView> {
  const pending = pendingRequest.value;
  if (!pending) {
    return Promise.resolve({ ok: false, error: "no presence request is pending" });
  }
  if (pending.frame.nonce !== nonce) {
    return Promise.resolve({ ok: false, error: "the presence request was superseded" });
  }
  return exchange(
    frame,
    ["presence_result"],
    (reply): PresenceAssertView | Promise<PresenceAssertView> => {
      const result = PresenceResultFrameSchema.safeParse(reply);
      if (!result.success) return { ok: false, error: "malformed presence_result from host" };
      if (!result.data.ok) return { ok: false, error: result.data.reason };
      return pending.forRelease ? awaitReleaseOutcome() : { ok: true };
    },
    () => {
      pendingRequest.value = null;
    },
  );
}

/** Route one inbound WebAuthn frame: a presence request is held for the page (a newer one replaces an
 * unanswered older one, since the host has moved on) and answers a kill_release that asked for it; anything
 * else answers the outstanding exchange or, with none outstanding, is dropped. */
export function handleWebAuthnFrame(msg: WebAuthnInboundFrame): void {
  if (msg.type === "presence_request") {
    const parsed = PresenceRequestFrameSchema.safeParse(msg);
    if (!parsed.success) {
      console.warn("[bb] dropping malformed presence_request");
      return;
    }
    if (pendingRequest.value)
      console.warn("[bb] a newer presence request replaces the unanswered one");
    // A kill_release awaiting this request is answered by it; a push nobody asked for opens the page where
    // the tap happens, which shows the action before asking for it.
    const forRelease = settleOutstanding(msg);
    pendingRequest.value = { frame: parsed.data, forRelease };
    if (!forRelease) {
      void browser.runtime.openOptionsPage().catch((e: unknown) => {
        console.warn("[bb] could not open the options page for the presence request", e);
      });
    }
    return;
  }
  if (!settleOutstanding(msg)) console.warn(`[bb] dropping unsolicited ${msg.type}`);
}

function settleOutstanding(msg: WebAuthnInboundFrame): boolean {
  const current = outstanding.value;
  if (current?.kind !== "reply" || !current.replies.includes(msg.type)) return false;
  outstanding.value = null;
  clearTimeout(current.timer);
  current.settle(msg);
  return true;
}

/** Tests only: the first life's state again. */
export function resetWebAuthnForTests(): void {
  const current = outstanding.value;
  if (current) clearTimeout(current.timer);
  conn.reset();
  outstanding.reset();
  pendingRequest.reset();
}
