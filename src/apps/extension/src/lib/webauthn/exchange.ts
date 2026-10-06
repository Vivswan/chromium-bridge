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
//   kill_release      -> the pushed presence_request is the reply; the answer to that request is settled through
//                        claimKillRelease (kill.ts's handoff), not by presence_result
//   presence_begin    -> the pushed presence_request is the reply (a page operation's, asked by the confirmation
//                        service); the answer's verdict reaches the asker (beginPresence's onVerdict)
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
  type EnrollBeginWire,
  type EnrollFinishWire,
  type EnrollOptionsFrame,
  EnrollOptionsFrameSchema,
  EnrollResultFrameSchema,
  type KillReleaseWire,
  type PresenceAssertWire,
  type PresenceBeginWire,
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
import type { PortCollaborator } from "../background/connection";
import { exchange } from "../background/exchange";
import { inLife } from "../shared/in-life";
import { readKey } from "../shared/read-key";

export type Refused = { ok: false; error: string };
export type EnrollBeginView = { ok: true; options: EnrollOptionsFrame } | Refused;
export type EnrollFinishView = { ok: true; credentialId: string } | Refused;
export type PresenceAssertView = { ok: true } | Refused;
export type KillReleaseView = { ok: true; request: PresenceRequestFrame } | Refused;
export type PresenceBeginView = { ok: true; request: PresenceRequestFrame } | Refused;
export type EnrollmentNoteView = { ok: true; enrollment: WebAuthnEnrollment | null } | Refused;
export type ForgetView = { ok: true } | Refused;

/** The page operations the host mints a presence request for; the wire spelling of presence_begin's action. */
export type PresenceAction = "page_eval" | "page_upload";

/** The reply kill.ts hands over for a release (claimKillRelease), beside the host's own frames. */
type ReleaseOutcome = { type: "release_outcome"; view: PresenceAssertView };

/** The host-pushed request awaiting the page's answer, and who asked for it: nobody (the options page answers
 * it), a kill_release (the answer's verdict is the release outcome, not the presence verdict), or a page
 * operation's confirmation (the answer's verdict reaches it through `onVerdict`, once, false on every path
 * that ends the request without the host's ok). */
type PendingRequest = { frame: PresenceRequestFrame } & (
  | { asked: "nobody" }
  | { asked: "release" }
  | { asked: "page_op"; onVerdict: (ok: boolean) => void }
);

const ceremony = exchange<WebAuthnInboundFrame | ReleaseOutcome>(
  "a WebAuthn exchange is already in flight",
);
const pendingRequest = inLife<PendingRequest | null>(() => null);

export const collaborator: PortCollaborator = {
  onAttach(c) {
    ceremony.attach(c);
  },
  onDetach() {
    dropPending();
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
  return ceremony.request({ type: "enroll_begin" } satisfies EnrollBeginWire, {
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
  const view = await ceremony.request(
    { type: "enroll_finish", ...response } satisfies EnrollFinishWire,
    {
      replies: ["enroll_result"],
      read(frame): EnrollFinishView {
        const result = EnrollResultFrameSchema.safeParse(frame);
        if (!result.success) return { ok: false, error: "malformed enroll_result from host" };
        return result.data.ok
          ? { ok: true, credentialId: result.data.credential_id }
          : { ok: false, error: result.data.reason };
      },
    },
  ).view;
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

/** Ask the host to release the kill switch. The reply is the presence request the host pushes for it, which
 * the page answers through assertPresence (or confirmPresence when the request admits no credential). */
export function beginKillRelease(): Promise<KillReleaseView> {
  return ceremony.request({ type: "kill_release" } satisfies KillReleaseWire, {
    replies: ["presence_request"],
    read(frame): KillReleaseView {
      const parsed = PresenceRequestFrameSchema.safeParse(frame);
      if (!parsed.success) return { ok: false, error: "malformed presence_request from host" };
      hold({ frame: parsed.data, asked: "release" });
      return { ok: true, request: parsed.data };
    },
  }).view;
}

/** Ask the host for a presence request for a page operation on `origin`, on behalf of its confirmation. The
 * reply is the request the host pushes, held for the confirmation window to answer; `onVerdict` receives the
 * host's verdict on that answer, or false once the request ends any other way (superseded, detached, or the
 * answer's exchange failed after posting). A refusal here (the host would not mint a request, the exchange is
 * busy, or the host is gone) is the view's error and calls nothing: the caller denies on it. */
export function beginPresence(
  action: PresenceAction,
  origin: string,
  onVerdict: (ok: boolean) => void,
): Promise<PresenceBeginView> {
  return ceremony.request({ type: "presence_begin", action, origin } satisfies PresenceBeginWire, {
    replies: ["presence_request", "presence_result"],
    read(frame): PresenceBeginView {
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
      hold({ frame: parsed.data, asked: "page_op", onVerdict });
      return { ok: true, request: parsed.data };
    },
  }).view;
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

/** The handoff from kill.ts, the one statement of it. The host's reply to a kill_release crosses the two
 * collaborators: a presence_request here; then, when the page's answer passes presence, the host writes the
 * record and emits presence_result ok followed by the kill_status_result that reports the write there (ok
 * killed:false, or ok:false with the error). Frame routing keeps claimers disjoint, so kill.ts calls this the
 * moment a kill_status_result ARRIVES, before its own lane and awaits, and later settles what it claimed: a
 * handler still writing an earlier frame's mirror must not settle a release that began after that frame. The
 * slot itself is held synchronously inside the presence_result's reader (answerPending), so the frame that
 * follows cannot find it empty.
 *
 *   release outcome held (presence passed)         -> claimed; the returned settle delivers the answer's verdict
 *   kill_release awaiting its request, ok:false     -> the exchange fails now with the host's reason (the record was
 *                                                     unreadable before any request), nothing to settle later
 *   anything else (a status reply, a push)          -> nothing; the reply to that exchange is still coming */
export function claimKillRelease(msg: {
  ok: boolean;
  error?: string;
}): ((view: PresenceAssertView) => void) | null {
  const outcome = ceremony.claim("release_outcome");
  if (outcome) {
    return (view) => {
      void outcome.settle({ type: "release_outcome", view });
    };
  }
  if (!msg.ok) {
    void ceremony
      .claim("presence_request")
      ?.fail(msg.error ?? "the host could not read its kill-switch state");
  }
  return null;
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
 * once the answer is on the pipe. A release's verdict comes through claimKillRelease, not presence_result; a
 * page op's confirmation gets the verdict through its onVerdict, false too when the posted answer's exchange
 * fails (a timeout, a detach), since that request is gone with it. */
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
      if (pending.asked !== "release") return verdict({ ok: true });
      return ceremony.hold({ replies: ["release_outcome"], read: (outcome) => outcome.view });
    },
    refused(failure): PresenceAssertView {
      const view: PresenceAssertView = { ok: false, error: failure.error };
      return failure.posted ? verdict(view) : view;
    },
  });
  if (posted) pendingRequest.value = null;
  return view;
}

/** Route one inbound WebAuthn frame: a presence request answers the kill_release or presence_begin that asked
 * for it (whose reader holds it for the page), or, pushed with nobody asking, is held and opens the page where
 * the tap happens, which shows the action before asking for it; anything else answers the outstanding exchange
 * or, with none outstanding, is dropped. */
export function handleWebAuthnFrame(msg: WebAuthnInboundFrame): void {
  if (msg.type === "presence_request") {
    if (ceremony.answer(msg)) return;
    const parsed = PresenceRequestFrameSchema.safeParse(msg);
    if (!parsed.success) {
      console.warn("[bb] dropping malformed presence_request");
      return;
    }
    hold({ frame: parsed.data, asked: "nobody" });
    void browser.runtime.openOptionsPage().catch((e: unknown) => {
      console.warn("[bb] could not open the options page for the presence request", e);
    });
    return;
  }
  if (!ceremony.answer(msg)) console.warn(`[bb] dropping unsolicited ${msg.type}`);
}

/** Tests only: the first life's state again. */
export function resetWebAuthnForTests(): void {
  ceremony.detach();
  pendingRequest.reset();
}
