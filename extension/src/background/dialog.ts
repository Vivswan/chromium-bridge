// page_handle_dialog — accept or dismiss a JavaScript dialog (alert / confirm /
// prompt) on the active tab via Chrome's debugger (CDP
// Page.handleJavaScriptDialog).
//
// SECURITY: this tool is OFF by default (handleDialogEnabled). Accepting a
// dialog can confirm a destructive action, and a dialog blocks the page, so we
// cannot render an in-page confirmation Toast the way page_click / page_eval do
// — there is no surface to draw on while the dialog is up. The explicit
// settings opt-in is therefore the gate (fail-closed: no opt-in, no dialog
// handling). See the tool description in contracts/tools.json.
//
// A dialog is only handleable if the debugger was attached (Page domain
// enabled) when it opened; that is the case under CDP mode, whose registry
// keeps a persistent attach. Without that, the native dialog is already showing
// and may not be capturable — Page.handleJavaScriptDialog then errors, which we
// surface honestly.

import type { OpArgs } from "../shared/types";
import { getSetting } from "../shared/settings";
import { ensureAllowed } from "./allowlist-store";
import { resolveTargetTab } from "./tabs";
import { dbgAttach, dbgDetach, dbgSend, isDebuggable } from "./cdp/session";
import { cdpRegistry } from "./cdp/registry";

export async function handleDialog(maybeTabId: number | undefined, args: OpArgs): Promise<unknown> {
  if ((await getSetting("handleDialogEnabled")) !== true) {
    throw new Error(
      "page_handle_dialog is disabled. Enable it in the extension settings first (it is off by default because a blocked dialog cannot show an in-page confirmation)."
    );
  }
  const action = args.action;
  if (action !== "accept" && action !== "dismiss") {
    throw new Error('page_handle_dialog needs action "accept" or "dismiss"');
  }
  const tab = await resolveTargetTab(maybeTabId);
  await ensureAllowed(tab.url);
  if (!isDebuggable(tab.url)) {
    throw new Error(
      `page_handle_dialog cannot debug this page (URL scheme not allowed): ${(tab.url || "").slice(0, 80)}`
    );
  }
  const tabId = tab.id!;

  const reusing = cdpRegistry.hasSession(tabId);
  if (reusing) {
    // Await the registry's idempotent (de-duped) attach so we never issue CDP
    // commands before a still-in-flight persistent attach has completed.
    await cdpRegistry.get(tabId);
  } else {
    try {
      await dbgAttach(tabId);
    } catch (e) {
      const msg = String((e as Error).message || e);
      if (/another debugger/i.test(msg)) {
        throw new Error(
          "该标签页已打开 DevTools,page_handle_dialog 无法附加。请关闭 DevTools 后重试。",
          { cause: e }
        );
      }
      throw e;
    }
  }
  try {
    // Page.enable is idempotent; needed so the CDP session owns dialog handling.
    await dbgSend(tabId, "Page.enable", {}).catch(() => {});
    const accept = action === "accept";
    const params: Record<string, unknown> = { accept };
    if (accept && typeof args.promptText === "string") params.promptText = args.promptText;
    await dbgSend(tabId, "Page.handleJavaScriptDialog", params);
    return { handled: action };
  } finally {
    if (!reusing) {
      await dbgSend(tabId, "Page.disable", {}).catch(() => {});
      await dbgDetach(tabId);
    }
  }
}
