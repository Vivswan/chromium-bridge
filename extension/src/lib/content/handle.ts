// Dispatch an inbound { op, args } message to the shared page API.
//
// The catalogue ops handled here are exactly the shared PAGE_OPS roster: the
// switch narrows on PageOp with an exhaustiveness backstop, so the roster and
// this handler cannot drift apart silently. The extension-internal ops (ping,
// the SW's click probe, and the informational notice) are handled up front.
//
// ONE page API instance drives everything (lib/dom/page-api.ts) - the same
// self-contained implementation the CDP backend ships via Runtime.evaluate -
// so the two backends cannot diverge. No settings reads, no confirmations,
// and no masking happen in this context: those are service-worker policy
// (confirm/gate.ts + egress.ts). See #32 - the content script reads NOTHING
// from extension storage.

import { unreachable } from "@chromium-bridge/shared";
import { createPageApi, REF_ATTR } from "../dom/page-api";
import { isPageOp } from "../shared/page-ops";
import type { ContentMsg } from "../shared/types";
import { runEval } from "./eval";
import { showInfoToast } from "./info-toast";

const api = createPageApi(REF_ATTR);

export async function handle(msg: ContentMsg) {
  const { op, args } = msg;
  if (op === "ping") return { pong: true };
  // The SW's allowlist check and confirmation were based on guard.expectOrigin.
  // Enforce it HERE, in the page's own event loop, atomically with the act:
  // any navigation that raced the SW-side recheck lands this script (or its
  // successor) in a document whose origin no longer matches - refuse.
  if (msg.guard?.expectOrigin !== undefined && location.origin !== msg.guard.expectOrigin) {
    throw new Error("the page origin changed while the request was in flight - re-issue the call");
  }
  if (op === "_info_toast") {
    // Informational notice (e.g. "about to attach debugger, banner will
    // flash"). Returns true unless the user cancels; NOT a confirmation.
    return await showInfoToast(args.message || "");
  }
  if (op === "_probe_click") {
    // The SW's DOM read for click-risk classification (confirm/gate.ts).
    return api.probeClick(args);
  }
  if (!isPageOp(op)) throw new Error(`content: unknown op ${op}`);
  switch (op) {
    case "page_snapshot":
      return api.snapshot();
    case "page_click":
      // msg.guard.clickExpect binds the click to the descriptor the SW
      // preflight authorized; api.click refuses if the target changed.
      return api.click({ ...args, expect: msg.guard?.clickExpect });
    case "page_fill":
      return api.fill(args);
    case "page_press":
      return api.press({ keys: args.keys ?? "" });
    case "page_hover":
      return api.hover(args);
    case "page_select":
      return api.select(args);
    case "page_text":
      return api.text();
    case "page_screenshot":
      // Captured directly by the SW backend; never reaches the content script.
      throw new Error("page_screenshot is captured in the service worker");
    case "page_scroll":
      return api.scroll(args);
    case "page_wait_for":
      return await api.waitFor(args);
    case "page_eval":
      return await runEval(args);
    case "storage_get":
      // RAW values; the SW masks them on egress (always-on, ADR-0010).
      return api.readStorage(args);
    default:
      return unreachable(op);
  }
}
