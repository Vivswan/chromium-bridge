// page_handle_dialog - accept or dismiss a JavaScript dialog (alert / confirm /
// prompt) on the active tab via Chrome's debugger (CDP
// Page.handleJavaScriptDialog).
//
// SECURITY: this tool is OFF by default (handleDialogEnabled). Accepting a
// dialog can confirm a destructive action, and a dialog blocks the page, so we
// cannot render an in-page confirmation Toast the way page_click / page_eval do
// - there is no surface to draw on while the dialog is up. The explicit
// settings opt-in is therefore the gate (fail-closed: no opt-in, no dialog
// handling). See the tool description in src/packages/core/src/tools/catalogue.rs.
//
// A dialog is only handleable if the debugger was attached (Page domain
// enabled) when it opened; that is the case under CDP mode, whose registry
// keeps a persistent attach. Without that, the native dialog is already showing
// and may not be capturable - Page.handleJavaScriptDialog then errors, which we
// surface honestly.

import { type OpArgs, TOOL_GRANTS } from "@chromium-bridge/shared/ops.gen";
import type { PolicyValues } from "@chromium-bridge/shared/policy.gen";
import { ensureAllowed } from "./allowlist-store";
import { withCdpAttach } from "./cdp/attach";
import { dbgSend, isDebuggable } from "./cdp/session";
import { activeTab } from "./tabs";

export async function handleDialog(args: OpArgs, policy: PolicyValues): Promise<unknown> {
  // ONE policy snapshot for the whole decision (ADR-0032 decision 4):
  // dispatch threads its per-request snapshot in; the REQUIRED parameter is
  // what holds the invariant (tests start their own decisions via
  // withFreshPolicy). The grants come from the generated catalogue (the
  // Rust tool record is their one home), so enforcement cannot name a field
  // the policy does not carry.
  if (TOOL_GRANTS.page_handle_dialog.some((grant) => policy[grant] !== true)) {
    throw new Error(
      "page_handle_dialog is disabled. Enable it in the extension settings first (it is off by default because a blocked dialog cannot show an in-page confirmation).",
    );
  }
  const action = args.action;
  if (action !== "accept" && action !== "dismiss") {
    throw new Error('page_handle_dialog needs action "accept" or "dismiss"');
  }
  const tab = await activeTab();
  await ensureAllowed(tab.url);
  if (!isDebuggable(tab.url)) {
    throw new Error(
      `page_handle_dialog cannot debug this page (URL scheme not allowed): ${(tab.url || "").slice(0, 80)}`,
    );
  }
  const tabId = tab.id;

  return await withCdpAttach(tabId, "page_handle_dialog", async ({ reused }) => {
    // Page.enable is idempotent; needed so the CDP session owns dialog handling.
    await dbgSend(tabId, "Page.enable", {}).catch(() => {});
    const accept = action === "accept";
    const params: Record<string, unknown> = { accept };
    if (accept && typeof args.promptText === "string") params.promptText = args.promptText;
    await dbgSend(tabId, "Page.handleJavaScriptDialog", params);
    // Best-effort domain cleanup before a transient detach; the persistent
    // CDP-mode session keeps Page enabled (other ops may rely on it).
    if (!reused) await dbgSend(tabId, "Page.disable", {}).catch(() => {});
    return { handled: action };
  });
}
