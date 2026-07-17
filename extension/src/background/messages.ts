// Runtime message router: handles requests from the popup / options page
// (allowlist approve/add/remove/list, connection status) and the content
// script's screenshot proxy. Registering this module installs the listener.

import type { RuntimeMsg } from "../shared/types";
import { getAllowlist, resolvePendingAllow, addAllow, removeAllow } from "./allowlist-store";
import { isNativeConnected } from "./port";
import {
  approvePending,
  getEnrollmentStatus,
  rejectPending,
  revokePin,
  startPairing,
  verifyPinnedNow,
} from "./enrollment";

// The enrollment actions change the extension's trust anchor, so they are
// accepted only from the extension's own pages (popup/options), never from a
// content script running in a tab. Content-script senders carry the page URL.
function fromExtensionPage(sender: chrome.runtime.MessageSender): boolean {
  return (
    sender.id === chrome.runtime.id &&
    typeof sender.url === "string" &&
    sender.url.startsWith(`chrome-extension://${chrome.runtime.id}/`)
  );
}

chrome.runtime.onMessage.addListener((msg: RuntimeMsg, sender, sendResponse) => {
  if (msg?.type === "resolve_allow") {
    resolvePendingAllow(msg.id, msg.allow).then((r) => sendResponse(r));
    return true; // async
  }
  if (msg?.type === "get_allowlist") {
    getAllowlist().then((list) => sendResponse({ list }));
    return true;
  }
  if (msg?.type === "add_allow") {
    const glob = msg.glob;
    if (typeof glob !== "string" || !glob) {
      sendResponse({ ok: false, error: "missing glob" });
      return false;
    }
    addAllow(glob).then((list) => sendResponse({ ok: true, list }));
    return true;
  }
  if (msg?.type === "remove_allow") {
    removeAllow(msg.glob).then((r) => sendResponse({ ok: true, ...r }));
    return true;
  }
  if (msg?.type === "get_status") {
    sendResponse({ nativeConnected: isNativeConnected() });
    return false;
  }
  if (msg?.type === "get_enrollment") {
    getEnrollmentStatus().then((st) => sendResponse(st));
    return true;
  }
  if (
    msg?.type === "enroll_pair" ||
    msg?.type === "enroll_verify" ||
    msg?.type === "enroll_approve" ||
    msg?.type === "enroll_reject" ||
    msg?.type === "enroll_revoke"
  ) {
    if (!fromExtensionPage(sender)) {
      sendResponse({
        ok: false,
        error: "enrollment actions are only accepted from extension pages",
      });
      return false;
    }
    const action = {
      enroll_pair: startPairing,
      enroll_verify: verifyPinnedNow,
      enroll_approve: approvePending,
      enroll_reject: rejectPending,
      enroll_revoke: revokePin,
    }[msg.type];
    action().then((r) => sendResponse(r));
    return true;
  }
  if (msg?.type === "capture_visible_tab") {
    // Content scripts can't call chrome.tabs.captureVisibleTab; proxy here.
    // The (options, callback) overload captures the active tab of the current
    // window — no windowId needed.
    chrome.tabs.captureVisibleTab({ format: "png" }, (dataUrl) => {
      if (chrome.runtime.lastError) {
        sendResponse({ error: chrome.runtime.lastError.message });
      } else {
        sendResponse({ dataUrl });
      }
    });
    return true; // async
  }
});
