// Dispatch an inbound { op, args } message to the right content-script handler.
//
// The catalogue ops handled here are exactly the shared PAGE_OPS roster: the
// switch narrows on PageOp with an exhaustiveness backstop, so the roster and
// this handler cannot drift apart silently. The internal ops (ping and the
// toast requests the SW sends for its own confirmations) are extension-
// internal and handled up front.

import { unreachable } from "@chromium-bridge/shared";
import { isPageOp } from "../shared/page-ops";
import type { ContentMsg } from "../shared/types";
import { click, fill, hover, press, screenshot, scroll, select, text } from "./actions";
import { runEval } from "./eval";
import { snapshot } from "./snapshot";
import { storageGet } from "./storage";
import { showInfoToast, showToast } from "./toast";
import { waitFor } from "./wait";

export async function handle(msg: ContentMsg) {
  const { op, args } = msg;
  if (op === "ping") return { pong: true };
  if (op === "_info_toast") {
    // Informational toast (e.g. "about to attach debugger, infobar will
    // flash"). Returns true unless the user cancels.
    return await showInfoToast(args.message || "");
  }
  if (op === "_confirm_toast") {
    return { approved: await showToast(args.message || "Confirm action?") };
  }
  if (!isPageOp(op)) throw new Error(`content: unknown op ${op}`);
  switch (op) {
    case "page_snapshot":
      return snapshot();
    case "page_click":
      return await click(args);
    case "page_fill":
      return await fill(args);
    case "page_press":
      return await press(args);
    case "page_hover":
      return await hover(args);
    case "page_select":
      return await select(args);
    case "page_text":
      return text();
    case "page_screenshot":
      return await screenshot();
    case "page_scroll":
      return scroll(args);
    case "page_wait_for":
      return await waitFor(args);
    case "page_eval":
      return await runEval(args);
    case "storage_get":
      return storageGet(args);
    default:
      return unreachable(op);
  }
}
