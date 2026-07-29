// Dispatch an inbound { op, args } message to the shared page API.
//
// The message is parsed ONCE at this trust boundary against ContentMsgSchema
// (@chromium-bridge/shared): a discriminated union in which every page-acting
// op carries a REQUIRED guard. A message outside the union - including a
// page op with no guard - is refused outright; there is no "guard absent,
// skip the check" state. The catalogue ops handled here are exactly the
// shared PAGE_OPS roster minus page_screenshot (captured in the SW), with an
// exhaustiveness backstop so the roster and this handler cannot drift apart
// silently. The extension-internal ops (ping, the SW's click probe, and the
// informational notice) are handled up front and are the only guard-less
// messages.
//
// ONE page API instance drives everything (lib/dom/page-api.ts) - the same
// self-contained implementation the CDP backend ships via Runtime.evaluate -
// so the two backends cannot diverge. No settings reads, no confirmations,
// and no masking happen in this context: those are service-worker policy
// (confirm/gate.ts + egress.ts). See #32 - the content script reads NOTHING
// from extension storage.

import { ContentMsgSchema, unreachable } from "@chromium-bridge/shared";
import { createPageApi, REF_ATTR } from "../dom/page-api";
import { runEval } from "./eval";
import { showInfoToast } from "./info-toast";

const api = createPageApi(REF_ATTR);

export async function handle(raw: unknown) {
  // Parse, don't validate: everything below acts on the parsed message only.
  const parsed = ContentMsgSchema.safeParse(raw);
  if (!parsed.success) {
    throw new Error("content: message does not match the SW envelope - refusing");
  }
  const msg = parsed.data;
  if (msg.op === "ping") return { pong: true };
  if (msg.op === "_info_toast") {
    // Informational notice (e.g. "about to attach debugger, banner will
    // flash"); NOT a confirmation. The result is structured so a cancel
    // survives the reply envelope instead of collapsing into a falsy value.
    const proceed = await showInfoToast(msg.args.message, msg.args.cancelLabel);
    return { cancelled: !proceed };
  }
  if (msg.op === "_probe_click") {
    // The SW's DOM read for click-risk classification (confirm/gate.ts).
    return api.probeClick(msg.args);
  }
  // Every remaining op ACTS on the page, and the schema requires its guard.
  // The SW's allowlist check and confirmation were based on
  // guard.expectOrigin - enforce it HERE, in the page's own event loop,
  // atomically with the act: any navigation that raced the SW-side recheck
  // lands this script (or its successor) in a document whose origin no
  // longer matches - refuse.
  if (location.origin !== msg.guard.expectOrigin) {
    throw new Error("the page origin changed while the request was in flight - re-issue the call");
  }
  switch (msg.op) {
    case "page_snapshot":
      return api.snapshot();
    case "page_click":
      // msg.guard.clickExpect (required by the schema for page_click) binds
      // the click to the descriptor the SW preflight authorized; api.click
      // re-probes and refuses if the target changed.
      return api.click({ ...msg.args, expect: msg.guard.clickExpect });
    case "page_fill":
      return api.fill(msg.args);
    case "page_press":
      return api.press({ keys: msg.args.keys ?? "" });
    case "page_hover":
      return api.hover(msg.args);
    case "page_select":
      return api.select(msg.args);
    case "page_text":
      return api.text();
    case "page_scroll":
      return api.scroll(msg.args);
    case "page_wait_for":
      return await api.waitFor(msg.args);
    case "page_eval":
      return await runEval(msg.args);
    case "storage_get":
      // RAW values; the SW masks them on egress (always-on, ADR-0010).
      return api.readStorage(msg.args);
    default:
      return unreachable(msg);
  }
}
