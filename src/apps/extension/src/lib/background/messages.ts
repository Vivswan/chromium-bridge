// Runtime message router: handles requests from the popup / options page
// (allowlist approve/add/remove/list, connection + enrollment status,
// enrollment ceremony) and the confirmation window (confirm_*). The background
// entrypoint installs the listener via registerRuntimeMessageRouter().
//
// Every inbound message is parsed against RuntimeMsgSchema before anything
// acts on it: an unrecognized or malformed message is answered with a refusal
// (never interpreted loosely), so the router only ever operates on shapes the
// schema vouches for.
//
// SENDER GATING (#32, security-critical): EVERY message is refused unless it
// comes from an extension page (fromExtensionPage), and confirm_* additionally
// require the confirmation window specifically (fromConfirmPage). The content
// script sends the router NOTHING; a content-script sender for any of these
// would be a compromised renderer trying to reach the trust state, so it is
// refused. This is what makes the #32 claim true for the MEDIATED path: without
// it, a content script on an already-approved origin could add_allow{evil.com}
// to seed the allowlist, or read keyId/fingerprint out of get_enrollment.

import { isEnrollmentAction, type RuntimeMsg, RuntimeMsgSchema } from "@chromium-bridge/shared";
import type { Browser } from "wxt/browser";
import { browser } from "wxt/browser";
import { addAllow, getAllowlist, removeAllow, resolvePendingAllow } from "./allowlist-store";
import { readRing } from "./audit-log";
import { requestClientList, revokeTrustedClient } from "./clients";
import {
  denyAllConfirmations,
  getPendingConfirm,
  releasePanicDeny,
  resolveConfirm,
} from "./confirm/service";
import {
  approvePending,
  getEnrollmentStatus,
  rejectPending,
  revokePin,
  startPairing,
  verifyPinnedNow,
} from "./enrollment";
import { engageKillSwitch, requestKillStatus, setKillSwitch, whenKillStateRefuses } from "./kill";
import { isNativeConnected } from "./port";

// True only for a sender that is one of the extension's OWN pages (popup /
// options / confirm), identified by the extension id AND a chrome-extension://
// <our-id>/ URL. A content script's sender carries the http(s) page URL and its
// id is our extension id too, so the URL prefix is the discriminator. Every
// router message requires this.
function fromExtensionPage(sender: Browser.runtime.MessageSender): boolean {
  return (
    sender.id === browser.runtime.id &&
    typeof sender.url === "string" &&
    sender.url.startsWith(`chrome-extension://${browser.runtime.id}/`)
  );
}

// The confirmation verdict may come ONLY from the confirmation window
// itself - not merely any extension page - shrinking the surface that can
// approve an action to the one document the service opened. Reuses
// fromExtensionPage for the origin (a robust prefix check) and adds an EXACT
// pathname match: a prefix test would also admit /confirm.htmlfoo or
// /confirm.html/...; the query/hash stay free (the window carries ?id=...).
// Deliberately does NOT compare url.origin, which is a real tuple origin in
// Chrome for chrome-extension:// but an opaque "null" in some URL parsers -
// pathname is scheme-independent and correct in both.
function fromConfirmPage(sender: Browser.runtime.MessageSender): boolean {
  if (!fromExtensionPage(sender) || typeof sender.url !== "string") return false;
  try {
    return new URL(sender.url).pathname === "/confirm.html";
  } catch {
    return false;
  }
}

const ENROLLMENT_ACTIONS = {
  enroll_pair: startPairing,
  enroll_verify: verifyPinnedNow,
  enroll_approve: approvePending,
  enroll_reject: rejectPending,
  enroll_revoke: revokePin,
} as const;

/** The router core, exported for the sender-gating tests. */
export function route(
  msg: RuntimeMsg,
  sender: Browser.runtime.MessageSender,
  sendResponse: (response?: unknown) => void,
): boolean {
  // #32 gate: refuse EVERY message from a non-extension-page sender. A content
  // script sends the router nothing, so a content-script sender here is a
  // compromised renderer reaching for trust state (the allowlist, the pin, the
  // enrollment status). confirm_* is gated more strictly still, below.
  if (!fromExtensionPage(sender)) {
    sendResponse({ ok: false, error: "this action is only accepted from extension pages" });
    return false;
  }
  switch (msg.type) {
    case "resolve_allow":
      void resolvePendingAllow(msg.id, msg.allow).then((r) => sendResponse(r));
      return true; // async
    case "get_allowlist":
      void getAllowlist().then((list) => sendResponse({ list }));
      return true;
    case "add_allow":
      void addAllow(msg.glob).then((r) => sendResponse(r));
      return true;
    case "remove_allow":
      void removeAllow(msg.glob).then((r) => sendResponse({ ok: true, ...r }));
      return true;
    case "get_status":
      sendResponse({ nativeConnected: isNativeConnected() });
      return false;
    case "get_enrollment":
      void getEnrollmentStatus().then((st) => sendResponse(st));
      return true;
    case "get_clients":
      // ADR-0025: read the host's trusted-client allowlist. Extension-page
      // senders only (the top-level gate above): a content script must never
      // enumerate the trust set.
      void requestClientList().then((r) => sendResponse(r));
      return true;
    case "revoke_client":
      // ADR-0025: revoke one trusted client. Capability reduction only, but
      // still extension-page gated like every trust-state mutation.
      void revokeTrustedClient(msg.name).then((r) => sendResponse(r));
      return true;
    case "get_kill":
      // ADR-0030: the kill switch's state (SW-only mirror + a live host
      // query when the port is up). Extension-page senders only, like every
      // other trust-state read.
      void requestKillStatus().then((r) => sendResponse(r));
      return true;
    case "set_kill":
      // ADR-0030: engage/release the kill switch. The page-can-NEVER-toggle
      // guarantee is the top-level gate above: only the extension's own
      // pages reach this line, and the actual transition happens host-side
      // (this only relays a control frame the host decides on and audits).
      void setKillSwitch(msg.on).then((r) => sendResponse(r));
      return true;
    case "get_audit":
      // ADR-0030: the read-only audit ring for the options panel.
      void readRing().then((entries) => sendResponse({ entries }));
      return true;
    case "confirm_ready":
      // The confirmation window (ADR-0027) asking for its payload. Requires the
      // confirmation window SPECIFICALLY (not just any extension page): a
      // content script (or any other page) must never see what is pending.
      if (!fromConfirmPage(sender)) {
        sendResponse({ ok: false, error: "confirmations are confirm-window-only" });
        return false;
      }
      sendResponse({ payload: getPendingConfirm(msg.id) });
      return false;
    case "confirm_resolve":
      // The user's verdict, ONLY from the confirmation window - this
      // restriction is what makes page-side auto-approval impossible (the
      // page can neither see nor answer the request).
      if (!fromConfirmPage(sender)) {
        sendResponse({ ok: false, error: "confirmations are confirm-window-only" });
        return false;
      }
      sendResponse(resolveConfirm(msg.id, msg.approved));
      return false;
    case "confirm_deny_kill":
      // The confirm window's panic exit (ADR-0030): deny everything pending,
      // then engage the kill switch. One SW-side message, not two window-side
      // sends, for two reasons that both matter:
      // (a) ordering is airtight - denyAllConfirmations settles the in-flight
      //     op false SYNCHRONOUSLY (and latches the queue and new arrivals to
      //     auto-deny), before the kill frame is even posted, so no action
      //     can race through while the brake is in flight (a hardware tap
      //     landing after this line finds the confirmation already settled);
      // (b) the deny tears the confirm window down (settle -> dismiss), and
      //     a second message sent from that dying document could be lost -
      //     here the engage lives in the SW and survives the teardown.
      // engageKillSwitch (not setKillSwitch) so an in-flight status query or
      // release cannot cause the brake to be refused. Deny is always accepted
      // (capability reduction; hardware payloads refuse only window-side
      // APPROVALS); a stale id changes nothing - whatever is pending is
      // denied and the engage still goes out. The host decides and audits
      // the actual transition; the latch lifts when the exchange settles.
      if (!fromConfirmPage(sender)) {
        sendResponse({ ok: false, error: "confirmations are confirm-window-only" });
        return false;
      }
      denyAllConfirmations();
      // The latch lifts on the EARLIER of two proofs, because the engage's
      // own answer cannot be singled out on an id-less pipe:
      // - the stored mirror crossing into refusal (killed/unknown): from
      //   that moment the request gate refuses every op upstream, so the
      //   latch has nothing left to hold;
      // - the exchange failing (port down, send failed, timed out): nothing
      //   credible is in flight anymore, and a frame landing later still
      //   flips the mirror, whose gate needs no latch. Residual, named: a
      //   host that stays silent past the timeout and then answers "alive"
      //   leaves a lifted window - reaching it takes a fresh op AND an
      //   explicit user approval on a newly presented surface.
      void whenKillStateRefuses().then(releasePanicDeny);
      void engageKillSwitch().then((r) => {
        if (!r.ok) {
          releasePanicDeny();
          console.error("[bb] confirm-window kill engage failed", r.error);
        }
        sendResponse(r);
      });
      return true;
    default: {
      if (!isEnrollmentAction(msg.type)) {
        // The schema admits nothing else; a new message type must be added
        // both there and here, and this fails closed until it is.
        sendResponse({ ok: false, error: `unhandled message type: ${(msg as RuntimeMsg).type}` });
        return false;
      }
      // Enrollment actions change the trust anchor; the top-level gate already
      // required an extension-page sender.
      ENROLLMENT_ACTIONS[msg.type]().then((r) => sendResponse(r));
      return true;
    }
  }
}

export function registerRuntimeMessageRouter(): void {
  browser.runtime.onMessage.addListener((msg: unknown, sender, sendResponse) => {
    const parsed = RuntimeMsgSchema.safeParse(msg);
    if (!parsed.success) {
      // Answer with a refusal (rather than staying silent) so a buggy or
      // malicious sender gets a deterministic failure instead of a timeout.
      sendResponse({ ok: false, error: "malformed runtime message" });
      return false;
    }
    return route(parsed.data, sender, sendResponse);
  });
}
