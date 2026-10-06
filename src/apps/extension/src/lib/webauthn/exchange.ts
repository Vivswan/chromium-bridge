// The service-worker half of the WebAuthn ceremonies: request/reply exchanges over the one Connection, and
// the host-pushed presence request held for the options page. The WebAuthn calls themselves run in the page
// (lib/shared/webauthn-ceremony.ts): a service worker has no `navigator.credentials`. port.ts drives
// `collaborator`; messages.ts routes the page's actions here. This module never imports port.ts, so there is
// no cycle.
//
//   enroll_begin      -> enroll_options (the page runs create) or enroll_result { ok: false }; on a machine
//                        with enrollments the host pushes presence_request and answers presence_required,
//                        and the enroll_begin AFTER the approved presence_assert gets the options
//   enroll_finish     -> enroll_result; an ok records the credential for the options page (recordedEnrollment)
//   kill_release, policy_set, policy_rollback, client_pair (beginAct)
//                     -> the pushed presence_request is the reply; the answer to that request is settled through
//                        claimAct (the handoff from the collaborator that owns the act's result frame), not by
//                        presence_result; a result frame arriving before any request is the host's early answer
//   presence_begin    -> the pushed presence_request is the reply (a page operation's, asked by the confirmation
//                        service), accepted only when it names the asked act; the answer's verdict reaches the
//                        asker (beginPresence's onVerdict); a begin cancelled or timed out before the reply
//                        leaves the exchange free and its late reply is dropped
//   presence_request  -> held as the pending request; the page fetches it, runs get, answers
//   presence_assert   -> presence_result
//   presence_confirm  -> presence_result (the window's answer, for a browser with no enrolled credential)
//   browser_revoke    -> browser_revoke_result; the host forgets this browser's credentials, and the note goes
//
// One exchange carries every request, each naming the reply tags that answer it: the host answers in order on
// one pipe, so a second ceremony is refused, never queued behind the first. A detach also drops the pending
// request, since the host that asked is gone with the port.

import {
  type BrowserRevokeResultFrame,
  BrowserRevokeResultFrameSchema,
  type BrowserRevokeWire,
  type ClientPairWire,
  type EnrollBeginWire,
  type EnrollFinishWire,
  type EnrollOptionsFrame,
  EnrollOptionsFrameSchema,
  EnrollResultFrameSchema,
  type KillReleaseWire,
  type PolicyRollbackWire,
  type PolicySetWire,
  type PresenceAssertWire,
  type PresenceBeginWire,
  type PresenceConfirmWire,
  type PresenceRequestFrame,
  PresenceRequestFrameSchema,
  PresenceResultFrameSchema,
} from "@chromium-bridge/shared/generated/envelope";
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
import type { z } from "zod";
import type { PortCollaborator } from "../background/connection";
import { exchange, type NamedReading } from "../background/exchange";
import { inLife } from "../shared/in-life";
import { readKey } from "../shared/read-key";

export type Refused = { ok: false; error: string };
export type EnrollBeginView = { ok: true; options: EnrollOptionsFrame } | Refused;
export type EnrollFinishView = { ok: true; credentialId: string } | Refused;
export type PresenceAssertView = { ok: true } | Refused;
export type PresenceBeginView = { ok: true; request: PresenceRequestFrame } | Refused;

/** One asked presence request: its outcome, and the way to withdraw it while the host has not answered. */
export interface PresenceBegin {
  view: Promise<PresenceBeginView>;
  /** Give the exchange back without waiting for the host. The view resolves refused; the host's reply, if it
   * still comes, is dropped on arrival: the host answers in order, so the next presence frame is that reply,
   * whatever is asked in between. Nothing happens once the host has answered. */
  cancel(): void;
}
export type EnrollmentNoteView = { ok: true; enrollment: WebAuthnEnrollment | null } | Refused;
export type ForgetView = { ok: true } | Refused;

/** The page operations the host mints a presence request for; the wire spelling of presence_begin's action. */
export type PresenceAction = "page_eval" | "page_upload";

/** The acts a presence request gates, keyed by the frame that asks for one: the result frame the host answers
 * after presence_result ok (on the collaborator that owns that frame, so the verdict crosses back here by
 * claimAct), and whether the host may answer ok before asking for presence at all. `tap`: every ok result
 * arriving while the request is awaited is a push (kill_status_result on a transition), never the answer.
 * `tap-or-free`: the host applied the act on its free lane (a rollback that only tightens or changes nothing). */
const ACTS = {
  kill_release: { result: "kill_status_result", lanes: "tap" },
  policy_set: { result: "policy_set_result", lanes: "tap" },
  policy_rollback: { result: "policy_rollback_result", lanes: "tap-or-free" },
  client_pair: { result: "client_pair_result", lanes: "tap" },
} as const satisfies Record<string, { result: string; lanes: "tap" | "tap-or-free" }>;

type ActFrame = KillReleaseWire | PolicySetWire | PolicyRollbackWire | ClientPairWire;
type Act = (typeof ACTS)[ActFrame["type"]];
export type ActResultTag = Act["result"];

/** How an act began: the request the page must answer with a tap. */
export type TapRequiredView = { ok: true; request: PresenceRequestFrame } | Refused;

/** How an act with a free lane began: the request, or null when the host applied the act with no tap needed. */
export type ActBegunView = { ok: true; request: PresenceRequestFrame | null } | Refused;

type OutcomeTag = `${ActResultTag}_outcome`;
const outcomeTag = (tag: ActResultTag): OutcomeTag => `${tag}_outcome`;

/** The verdict a collaborator hands over for an act (claimAct), beside the host's own frames. */
type ActOutcome = { type: OutcomeTag; view: PresenceAssertView };

/** The host-pushed request awaiting the page's answer, and who asked for it: nobody (the options page answers
 * it), an act begun here (the answer's verdict is that act's outcome, not the presence verdict), or a page
 * operation's confirmation (the answer's verdict reaches it through `onVerdict`, once, false on every path
 * that ends the request without the host's ok). */
type PendingRequest = { frame: PresenceRequestFrame } & (
  | { asked: "nobody" }
  | { asked: "act"; act: Act }
  | { asked: "page_op"; onVerdict: (ok: boolean) => void }
);

const ceremony = exchange<WebAuthnInboundFrame | ActOutcome>(
  "a WebAuthn exchange is already in flight",
);
const pendingRequest = inLife<PendingRequest | null>(() => null);
/** One beginAct whose presence request is still coming: its own result frame arriving first is the host's
 * early answer (a refusal before any request, or a free lane's ok where the act has one). One record per
 * call, so a duplicate the exchange refused as busy cannot clear the admitted call's slot. */
interface AwaitingAct {
  act: Act;
}
const awaitingAct = inLife<AwaitingAct | null>(() => null);
/** How many begins given up on (cancelled, or timed out after posting) the host still owes a reply; the next
 * presence frame to arrive settles one, before any correlation, since the host answers in order. */
const unansweredBegins = inLife(() => 0);

export const collaborator: PortCollaborator = {
  onAttach(c) {
    ceremony.attach(c);
  },
  onDetach() {
    dropPending();
    awaitingAct.value = null;
    unansweredBegins.value = 0;
    ceremony.detach();
  },
  onFrame(msg) {
    if (!isWebAuthnFrame(msg)) return false;
    handleWebAuthnFrame(msg);
    return true;
  },
};

/** Classification for the port demux: one of the five host->extension WebAuthn frames. */
export function isWebAuthnFrame(msg: unknown): msg is WebAuthnInboundFrame {
  return WebAuthnInboundFrameSchema.safeParse(msg).success;
}

/** Ask the host for the creation options of a new credential for this browser. */
export function beginEnrollment(): Promise<EnrollBeginView> {
  return post({ type: "enroll_begin" } satisfies EnrollBeginWire, {
    replies: ["enroll_options", "enroll_result"],
    read(frame): EnrollBeginView {
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
  }).view;
}

/** Hand the host the `navigator.credentials.create` response the page produced. An ok is noted in storage
 * for the options page; a failed note changes nothing about the enrollment the host already recorded. */
export async function finishEnrollment(response: RegistrationResponse): Promise<EnrollFinishView> {
  const view = await post({ type: "enroll_finish", ...response } satisfies EnrollFinishWire, {
    replies: ["enroll_result"],
    read(frame): EnrollFinishView {
      const result = EnrollResultFrameSchema.safeParse(frame);
      if (!result.success) return { ok: false, error: "malformed enroll_result from host" };
      return result.data.ok
        ? { ok: true, credentialId: result.data.credential_id }
        : { ok: false, error: result.data.reason };
    },
  }).view;
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
  const stored = await readKey(WEBAUTHN_ENROLLMENT_KEY, WebAuthnEnrollmentSchema);
  switch (stored.state) {
    case "absent":
      return { ok: true, enrollment: null };
    case "corrupt":
      return { ok: false, error: "the stored enrollment note is malformed" };
    case "valid":
      return { ok: true, enrollment: stored.value };
  }
}

/** Ask the host to forget every authenticator enrolled from this browser; the host acts on its own label, so
 * no other browser can be named. The host's trust record is what stops trusting the credential; the worker's
 * note goes when the host says the browser holds nothing now (an ok, or `not_enrolled` for a note the CLI's
 * `revoke <browser>` left behind). Only an ok drops the pending presence request: the host keeps its request
 * through a refusal, and a browser with no credential still answers its own through the window. */
export async function forgetBrowser(): Promise<ForgetView> {
  const view = await ceremony.request({ type: "browser_revoke" } satisfies BrowserRevokeWire, {
    replies: ["browser_revoke_result"],
    read(frame): ForgetView {
      const result = BrowserRevokeResultFrameSchema.safeParse(frame);
      if (!result.success) return { ok: false, error: "malformed browser_revoke_result from host" };
      return result.data.ok ? { ok: true } : { ok: false, error: result.data.reason };
    },
  }).view;
  if (view.ok) pendingRequest.value = null;
  if (view.ok || view.error === ("not_enrolled" satisfies BrowserRevokeResultFrame["reason"])) {
    await browser.storage.local.remove(WEBAUTHN_ENROLLMENT_KEY).catch((e: unknown) => {
      console.warn("[bb] could not clear the enrollment note", e);
    });
  }
  return view;
}

/** Post one ceremony frame whose host handler takes the pending slot on entry (every enrollment frame and
 * every act), so the request the page may still be looking at is dropped here the moment the post succeeds;
 * a refused post (busy, detached) leaves it, since the host never saw the frame. */
function post<TView, R extends (WebAuthnInboundFrame | ActOutcome)["type"]>(
  frame: object,
  how: NamedReading<WebAuthnInboundFrame | ActOutcome, TView, R>,
): { posted: boolean; view: Promise<TView | Refused> } {
  const { posted, view } = ceremony.request(frame, how);
  if (posted) dropPending();
  return { posted, view };
}

/** Ask the host for a presence-gated act. The reply is the presence request the host pushes for it, which the
 * page answers through assertPresence (or confirmPresence when the request admits no credential); the host may
 * instead answer on the act's result frame at once, refusing before any request or applying a free rollback,
 * which claimAct carries here. */
export function beginAct(frame: PolicyRollbackWire): Promise<ActBegunView>;
export function beginAct(
  frame: KillReleaseWire | PolicySetWire | ClientPairWire,
): Promise<TapRequiredView>;
export function beginAct(frame: ActFrame): Promise<ActBegunView> {
  const act = ACTS[frame.type];
  const awaiting: AwaitingAct = { act };
  const { posted, view } = post(frame, {
    replies: ["presence_request", outcomeTag(act.result)],
    read(reply): ActBegunView {
      if (awaitingAct.value === awaiting) awaitingAct.value = null;
      // claimAct admits an early ok only on a free lane, so a tap-only act's early outcome is its refusal.
      if (reply.type !== "presence_request") {
        return reply.view.ok ? { ok: true, request: null } : reply.view;
      }
      const parsed = PresenceRequestFrameSchema.safeParse(reply);
      if (!parsed.success) return { ok: false, error: "malformed presence_request from host" };
      hold({ frame: parsed.data, asked: "act", act });
      return { ok: true, request: parsed.data };
    },
    refused(failure): Refused {
      if (awaitingAct.value === awaiting) awaitingAct.value = null;
      return { ok: false, error: failure.error };
    },
  });
  if (posted) awaitingAct.value = awaiting;
  return view;
}

/** The handoff from the collaborator that owns an act's result frame (kill.ts, host-admin.ts, clients.ts), the
 * one statement of it. The host's reply to an act crosses two collaborators: a presence_request here; then,
 * when the page's answer passes presence, the host runs the act and emits presence_result ok followed by the
 * result frame that reports it there. Frame routing keeps claimers disjoint, so the owner calls this the moment
 * its frame ARRIVES, before its own lane and awaits, and later settles what it claimed: a handler still
 * writing an earlier frame's state must not settle an act that began after that frame. The slot itself is
 * held synchronously inside the presence_result's reader (answerPending), so the frame that follows cannot
 * find it empty.
 *
 *   outcome held (presence passed)                 -> claimed; the returned settle delivers the frame's verdict
 *   this act awaiting its request                  -> the host answered before asking for presence: claimed, and the
 *                                                     settle resolves beginAct (a refusal, or a free rollback's ok);
 *                                                     an ok no lane answers early with is a push, left alone
 *   anything else (a push, another exchange open)  -> null; the frame is the owner's alone */
export function claimAct(
  tag: ActResultTag,
  msg: { ok: boolean },
): ((view: PresenceAssertView) => void) | null {
  const awaited = awaitingAct.value?.act;
  const early = awaited?.result === tag;
  if (early && msg.ok && awaited.lanes === "tap") return null;
  const claimed = ceremony.claim(outcomeTag(tag));
  if (!claimed) return null;
  if (early) awaitingAct.value = null;
  return (view) => {
    void claimed.settle({ type: outcomeTag(tag), view });
  };
}

/** Hand a write lane's result frame to the act that asked for it: the verdict as the typed producer emitted it
 * (`schema` is the frame's ok-split reader), a malformed frame as a refusal naming it. False when no act is
 * awaiting this tag, so the owner drops the frame as unsolicited. kill.ts hands over by claimAct itself, since
 * its frame also moves the mirror first. */
export function handOverVerdict(
  tag: ActResultTag,
  schema: z.ZodType<{ ok: true } | { ok: false; error: string }>,
  msg: unknown,
): boolean {
  const parsed = schema.safeParse(msg);
  const verdict: PresenceAssertView = parsed.success
    ? parsed.data.ok
      ? { ok: true }
      : { ok: false, error: parsed.data.error }
    : { ok: false, error: `malformed ${tag} from host` };
  const settle = claimAct(tag, verdict);
  if (!settle) return false;
  settle(verdict);
  return true;
}

/** Ask the host for a presence request for a page operation on `origin`, on behalf of its confirmation. The
 * reply is the request the host pushes, held for the confirmation window to answer only when its action is
 * the asked act, `<op> on <origin>` as the host spells it: a request for another act is refused and not held,
 * so the window never shows one payload over a tap that signs another. `onVerdict` receives the host's verdict
 * on that answer, or false once the request ends any other way (superseded, detached, or the answer's exchange
 * failed after posting). A refusal here (the host would not mint a request, the exchange is busy, or the host
 * is gone) is the view's error and calls nothing: the caller denies on it. */
export function beginPresence(
  action: PresenceAction,
  origin: string,
  onVerdict: (ok: boolean) => void,
): PresenceBegin {
  const expected = `${action} on ${origin}`;
  let awaiting = true;
  const { view } = ceremony.request(
    { type: "presence_begin", action, origin } satisfies PresenceBeginWire,
    {
      replies: ["presence_request", "presence_result"],
      read(frame): PresenceBeginView {
        awaiting = false;
        if (frame.type === "presence_result") {
          const result = PresenceResultFrameSchema.safeParse(frame);
          return {
            ok: false,
            error:
              result.success && !result.data.ok
                ? result.data.reason
                : "malformed presence_result from host",
          };
        }
        const parsed = PresenceRequestFrameSchema.safeParse(frame);
        if (!parsed.success) return { ok: false, error: "malformed presence_request from host" };
        if (parsed.data.action !== expected) {
          return { ok: false, error: "the host's request names another act" };
        }
        hold({ frame: parsed.data, asked: "page_op", onVerdict });
        return { ok: true, request: parsed.data };
      },
      refused(failure): PresenceBeginView {
        awaiting = false;
        // The exchange gave up on a posted begin: the host's reply is still coming and must not be taken
        // for a push (or for the next request's reply), the same debt a cancel records.
        if (failure.why === "timed-out") unansweredBegins.value += 1;
        return { ok: false, error: failure.error };
      },
    },
  );
  return {
    view,
    cancel() {
      if (!awaiting) return;
      awaiting = false;
      unansweredBegins.value += 1;
      void ceremony
        .claim("presence_request")
        ?.fail("the confirmation ended before the host answered");
    },
  };
}

/** Forget the page-op request named by `nonce`, with no verdict: its confirmation is over (settled or past
 * its deadline), so a tap made for it from now on answers nothing here. A request someone else holds, or a
 * newer one, stays. */
export function abandonPresence(nonce: string): void {
  const pending = pendingRequest.value;
  if (pending?.asked === "page_op" && pending.frame.nonce === nonce) pendingRequest.value = null;
}

/** Hold `next` as the pending request. A newer request replaces an unanswered older one, since the host has
 * moved on; a page op's confirmation waiting on the older one learns it ended without an approval. */
function hold(next: PendingRequest): void {
  if (pendingRequest.value)
    console.warn("[bb] a newer presence request replaces the unanswered one");
  dropPending();
  pendingRequest.value = next;
}

/** Clear the pending request, telling a page op's confirmation that the request ended without an approval. */
function dropPending(): void {
  const pending = pendingRequest.value;
  pendingRequest.value = null;
  if (pending?.asked === "page_op") pending.onVerdict(false);
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
 * once the answer is on the pipe. An act's verdict comes through claimAct, not presence_result; a page op's
 * confirmation gets the verdict through its onVerdict, false too when the posted answer's exchange fails (a
 * timeout, a detach), since that request is gone with it. */
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
  const verdict = (view: PresenceAssertView): PresenceAssertView => {
    if (pending.asked === "page_op") pending.onVerdict(view.ok);
    return view;
  };
  const { posted, view } = ceremony.request(frame, {
    replies: ["presence_result"],
    read(reply): PresenceAssertView | Promise<PresenceAssertView> {
      const result = PresenceResultFrameSchema.safeParse(reply);
      if (!result.success)
        return verdict({ ok: false, error: "malformed presence_result from host" });
      if (!result.data.ok) return verdict({ ok: false, error: result.data.reason });
      if (pending.asked !== "act") return verdict({ ok: true });
      return ceremony.hold({
        replies: [outcomeTag(pending.act.result)],
        read: (outcome) => outcome.view,
      });
    },
    refused(failure): PresenceAssertView {
      const view: PresenceAssertView = { ok: false, error: failure.error };
      return failure.posted ? verdict(view) : view;
    },
  });
  if (posted) pendingRequest.value = null;
  return view;
}

/** Route one inbound WebAuthn frame: a presence frame owed to a begin given up on is dropped first; the rest
 * answers the outstanding exchange (a presence request's reader holds it for the page); a presence request
 * nobody asked for is a host push, held and opening the page where the tap happens, which shows the action
 * before asking for it; anything else is dropped. */
export function handleWebAuthnFrame(msg: WebAuthnInboundFrame): void {
  if (
    unansweredBegins.value > 0 &&
    (msg.type === "presence_request" || msg.type === "presence_result")
  ) {
    // The reply to a begin given up on: the host answers in order, so it precedes the reply to whatever was
    // asked after, and must not be handed to that request or held as a push.
    unansweredBegins.value -= 1;
    return;
  }
  if (ceremony.answer(msg)) return;
  if (msg.type !== "presence_request") {
    console.warn(`[bb] dropping unsolicited ${msg.type}`);
    return;
  }
  const parsed = PresenceRequestFrameSchema.safeParse(msg);
  if (!parsed.success) {
    console.warn("[bb] dropping malformed presence_request");
    return;
  }
  hold({ frame: parsed.data, asked: "nobody" });
  void browser.runtime.openOptionsPage().catch((e: unknown) => {
    console.warn("[bb] could not open the options page for the presence request", e);
  });
}

/** Tests only: the first life's state again. */
export function resetWebAuthnForTests(): void {
  ceremony.detach();
  pendingRequest.reset();
  awaitingAct.reset();
  unansweredBegins.reset();
}
