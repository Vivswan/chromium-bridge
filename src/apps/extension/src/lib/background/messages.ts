// Runtime message router for the popup / options page and the confirmation
// window; the background entrypoint installs it via
// registerRuntimeMessageRouter(). Every inbound message is parsed against the
// contract's request union first, and a malformed one is answered with a
// refusal, never interpreted loosely.
//
// Sender gating is security-critical: the content script sends the router
// NOTHING, so a content-script sender is a compromised renderer reaching for
// trust state. Without the gate a content script on an approved origin could
// add_allow{evil.com} to seed the allowlist, or read keyId/fingerprint out of
// get_enrollment. Each message's gate is declared in the contract table and
// checked once here.
//   extension-page  -> any of the extension's own pages (fromExtensionPage)
//   confirm-window  -> the confirmation window alone (fromConfirmPage)

import {
  RUNTIME_CONTRACT,
  type RuntimeMsg,
  RuntimeMsgSchema,
  type RuntimeMsgType,
  type RuntimeRequest,
  type RuntimeResponse,
} from "@chromium-bridge/shared/runtime-msg";
import type { Browser } from "wxt/browser";
import { browser } from "wxt/browser";
import {
  assertPresence,
  beginEnrollment,
  beginKillRelease,
  confirmPresence,
  finishEnrollment,
  forgetBrowser,
  pendingPresenceRequest,
  recordedEnrollment,
} from "../webauthn/exchange";
import {
  addAllow,
  getAllowlist,
  removeAllow,
  resolvePendingAllow,
  syncPendingMirror,
} from "./allowlist-store";
import { readRing } from "./audit-log";
import { requestClientList, revokeTrustedClient } from "./clients";
import { denyActiveConfirmation, getPendingConfirm, resolveConfirm } from "./confirm/service";
import {
  approvePending,
  getEnrollmentStatus,
  rejectPending,
  revokePin,
  startPairing,
  verifyPinnedNow,
} from "./enrollment";
import {
  repairRegistration,
  requestHostAudit,
  requestRegistrationStatus,
  restrictPolicy,
} from "./host-admin";
import { engageKill, panicEngage, requestKillStatus } from "./kill";
import { chooseLanguage, getPolicyPosture } from "./policy-sync";
import { isNativeConnected } from "./port";

// True only for a sender that is one of the extension's OWN pages (popup /
// options / confirm), identified by the extension id AND a chrome-extension://
// <our-id>/ URL. A content script's sender carries the http(s) page URL and its
// id is our extension id too, so the URL prefix is the discriminator.
function fromExtensionPage(sender: Browser.runtime.MessageSender): boolean {
  return (
    sender.id === browser.runtime.id &&
    typeof sender.url === "string" &&
    sender.url.startsWith(`chrome-extension://${browser.runtime.id}/`)
  );
}

// Exact pathname, not a prefix (a prefix admits /confirm.htmlfoo and
// /confirm.html/...), and not url.origin, which some URL parsers render as an
// opaque "null" for chrome-extension:// while pathname is correct in both; the
// query/hash stay free (?id=...).
function fromConfirmPage(sender: Browser.runtime.MessageSender): boolean {
  if (!fromExtensionPage(sender) || typeof sender.url !== "string") return false;
  try {
    return new URL(sender.url).pathname === "/confirm.html";
  } catch {
    return false;
  }
}

type Handler<K extends RuntimeMsgType> = (
  msg: RuntimeRequest<K>,
) => RuntimeResponse<K> | Promise<RuntimeResponse<K>>;

// One handler per contract entry, each typed to that entry's declared
// response: a handler answering with another shape, or a message type without
// a handler, fails to compile.
const HANDLERS: { [K in RuntimeMsgType]: Handler<K> } = {
  resolve_allow: (msg) => resolvePendingAllow(msg.id, msg.allow),
  get_allowlist: async () => ({ ok: true, list: await getAllowlist() }),
  add_allow: (msg) => addAllow(msg.glob),
  remove_allow: async (msg) => ({ ok: true, ...(await removeAllow(msg.glob)) }),
  get_status: () => ({ ok: true, nativeConnected: isNativeConnected() }),
  get_enrollment: getEnrollmentStatus,
  get_clients: requestClientList,
  revoke_client: (msg) => revokeTrustedClient(msg.name),
  get_kill: requestKillStatus,
  // The host decides and audits the transition; this only relays a control frame. A release is the host's
  // presence request, answered by the page's tap.
  set_kill: engageKill,
  kill_release: beginKillRelease,
  get_audit: async () => ({ ok: true, entries: await readRing() }),
  get_host_audit: requestHostAudit,
  // Re-derives the pending mirror through the one serialized store path: live
  // requests are rewritten, never deleted; with none, the ghost goes and the
  // badge clears.
  sweep_pending: async () => {
    await syncPendingMirror();
    return { ok: true };
  },
  // The picker already wrote uiLanguage locally; `sent` is diagnostic only,
  // since an offline choice legitimately stays local.
  lang_choose: async (msg) => ({ ok: true, sent: await chooseLanguage(msg.value) }),
  enroll_pair: startPairing,
  enroll_verify: verifyPinnedNow,
  enroll_approve: approvePending,
  enroll_reject: rejectPending,
  enroll_revoke: revokePin,
  webauthn_enroll_begin: beginEnrollment,
  webauthn_enroll_finish: ({ attestation_object, client_data_json }) =>
    finishEnrollment({ attestation_object, client_data_json }),
  webauthn_presence_pending: () => ({ ok: true, request: pendingPresenceRequest() }),
  webauthn_enrollment: recordedEnrollment,
  webauthn_presence_assert: ({
    nonce,
    credential_id,
    authenticator_data,
    client_data_json,
    signature,
  }) => assertPresence({ nonce, credential_id, authenticator_data, client_data_json, signature }),
  webauthn_presence_confirm: ({ nonce }) => confirmPresence(nonce),
  webauthn_forget: forgetBrowser,
  get_registration: requestRegistrationStatus,
  repair_registration: (msg) => repairRegistration(msg.browsers),
  get_policy: async () => ({ ok: true, posture: await getPolicyPosture() }),
  // The host's restriction seam decides the direction and audits the verdict; this only relays.
  restrict_policy: (msg) => restrictPolicy(msg.overlay),
  confirm_ready: (msg) => ({ ok: true, payload: getPendingConfirm(msg.id) }),
  confirm_resolve: (msg) => resolveConfirm(msg.id, msg.approved),
  confirm_deny_kill: denyAndKill,
};

// The confirm window's panic exit, ONE worker-side step. Deny first: the deny settles the in-flight op and tears the
// window down, so by the time the engage is on the pipe nothing can approve it (deny-kill.test.ts asserts that
// inside the post) and no second send from the dying document is needed. The latch and what lifts it are brake.ts.
//   panicEngage, not engageKill  -> an in-flight status query cannot get the brake refused
//   stale id                     -> changes nothing; whatever is pending is denied and the engage still goes out
function denyAndKill(): Promise<RuntimeResponse<"confirm_deny_kill">> {
  denyActiveConfirmation();
  return panicEngage().then((r) => {
    if (!r.ok) console.error("[bb] confirm-window kill engage unconfirmed", r.error);
    return r;
  });
}

// `type` is passed beside `msg` so the lookup stays correlated: indexing the
// handler table with the message's own union-typed `type` would lose the
// per-arm request type.
async function dispatch<K extends RuntimeMsgType>(
  type: K,
  msg: RuntimeRequest<K>,
): Promise<RuntimeResponse<K>> {
  return HANDLERS[type](msg);
}

/** The router core, exported for the sender-gating tests. Always answers:
 * a handler that rejects is reported as a refusal rather than left to time
 * out at the sender. */
export function route(
  msg: RuntimeMsg,
  sender: Browser.runtime.MessageSender,
  sendResponse: (response: RuntimeResponse) => void,
): boolean {
  if (!fromExtensionPage(sender)) {
    sendResponse({ ok: false, error: "this action is only accepted from extension pages" });
    return false;
  }
  if (RUNTIME_CONTRACT[msg.type].gate === "confirm-window" && !fromConfirmPage(sender)) {
    sendResponse({ ok: false, error: "confirmations are confirm-window-only" });
    return false;
  }
  void dispatch(msg.type, msg).then(sendResponse, (e: unknown) => {
    console.error("[bb] runtime message handler failed", msg.type, e);
    sendResponse({ ok: false, error: `${msg.type} failed` });
  });
  return true;
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
