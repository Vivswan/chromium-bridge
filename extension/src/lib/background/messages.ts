// Runtime message router: handles requests from the popup / options page
// (allowlist approve/add/remove/list, connection status) and the content
// script's screenshot proxy. The background entrypoint installs the listener
// via registerRuntimeMessageRouter().
//
// Every inbound message is parsed against RuntimeMsgSchema before anything
// acts on it: an unrecognized or malformed message is answered with a refusal
// (never interpreted loosely), so the router only ever operates on shapes the
// schema vouches for.

import { isEnrollmentAction, type RuntimeMsg, RuntimeMsgSchema } from "@chromium-bridge/shared";
import type { Browser } from "wxt/browser";
import { browser } from "wxt/browser";
import { addAllow, getAllowlist, removeAllow, resolvePendingAllow } from "./allowlist-store";
import { getPendingConfirm, resolveConfirm } from "./confirm/service";
import {
  approvePending,
  getEnrollmentStatus,
  rejectPending,
  revokePin,
  startPairing,
  verifyPinnedNow,
} from "./enrollment";
import { isNativeConnected } from "./port";

// The enrollment actions change the extension's trust anchor, so they are
// accepted only from the extension's own pages (popup/options), never from a
// content script running in a tab. Content-script senders carry the page URL.
function fromExtensionPage(sender: Browser.runtime.MessageSender): boolean {
  return (
    sender.id === browser.runtime.id &&
    typeof sender.url === "string" &&
    sender.url.startsWith(`chrome-extension://${browser.runtime.id}/`)
  );
}

// The confirmation verdict may come ONLY from the confirmation window
// itself - not merely any extension page - shrinking the surface that can
// approve an action to the one document the service opened.
function fromConfirmPage(sender: Browser.runtime.MessageSender): boolean {
  if (sender.id !== browser.runtime.id || typeof sender.url !== "string") return false;
  // Exact document match (origin + path), not a prefix test: a prefix would
  // also admit /confirm.htmlfoo or /confirm.html/...; query/hash stay free.
  try {
    const url = new URL(sender.url);
    return (
      url.origin === `chrome-extension://${browser.runtime.id}` && url.pathname === "/confirm.html"
    );
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

function route(
  msg: RuntimeMsg,
  sender: Browser.runtime.MessageSender,
  sendResponse: (response?: unknown) => void,
): boolean {
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
    case "confirm_ready":
      // The confirmation window (ADR-0027) asking for its payload. ONLY from
      // the confirmation window: a content script (or any other page) must
      // never see what is pending.
      if (!fromConfirmPage(sender)) {
        sendResponse({ ok: false, error: "confirmations are extension-page-only" });
        return false;
      }
      sendResponse({ payload: getPendingConfirm(msg.id) });
      return false;
    case "confirm_resolve":
      // The user's verdict, ONLY from the confirmation window - this
      // restriction is what makes page-side auto-approval impossible (the
      // page can neither see nor answer the request).
      if (!fromConfirmPage(sender)) {
        sendResponse({ ok: false, error: "confirmations are extension-page-only" });
        return false;
      }
      sendResponse(resolveConfirm(msg.id, msg.approved));
      return false;
    default: {
      if (!isEnrollmentAction(msg.type)) {
        // The schema admits nothing else; a new message type must be added
        // both there and here, and this fails closed until it is.
        sendResponse({ ok: false, error: `unhandled message type: ${(msg as RuntimeMsg).type}` });
        return false;
      }
      if (!fromExtensionPage(sender)) {
        sendResponse({
          ok: false,
          error: "enrollment actions are only accepted from extension pages",
        });
        return false;
      }
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
