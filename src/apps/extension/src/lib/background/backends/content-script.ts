// ContentScriptBackend - the DEFAULT page backend (cdpMode off): inject the
// content script if needed and message it. The content script drives the
// SAME shared page API the CDP backend ships (lib/dom/page-api.ts).
// Allowlist, confirmation, and masking policy run in dispatch.ts before and
// after this backend; here is only inject + transport - but the transport
// itself is a trust boundary, so both directions are parsed with Zod: the
// outbound message must match ContentMsgSchema (a page-acting message without
// its guard is refused before it is ever sent) and the reply must match the
// PageReply envelope (anything else is refused, never shape-sniffed).

import { ClickProbeSchema, ContentMsgSchema, PageReplySchema } from "@chromium-bridge/shared";
import { browser } from "wxt/browser";
import type { ClickProbe } from "../../dom/page-api";
import type { PageOp } from "../../shared/page-ops";
import type { OpArgs } from "../../shared/types";
import type { PageOpGuard } from "../confirm/gate";
import type { PageBackend } from "../page-backend";
import { injectIfNeeded, type ResolvedTab } from "../tabs";

export class ContentScriptBackend implements PageBackend {
  async probeClick(args: OpArgs, tab: ResolvedTab): Promise<ClickProbe> {
    // The one guard-less content message besides ping/_info_toast: a DOM read
    // that runs BEFORE any approval exists. Its result becomes the basis of
    // the risk decision, the confirmation text, AND the descriptor the click
    // is later held to - so parse it here, at the receive boundary, instead
    // of trusting the shape into the authorization decision (fail closed).
    const raw = await this.send(tab, { op: "_probe_click", args, tabId: tab.id });
    const probe = ClickProbeSchema.safeParse(raw);
    if (!probe.success) {
      throw new Error("click probe reply is not a valid descriptor - refusing");
    }
    return probe.data;
  }

  async run(op: PageOp, args: OpArgs, tab: ResolvedTab, guard: PageOpGuard): Promise<unknown> {
    if (op === "page_screenshot") {
      // Only the SW can capture, and captureVisibleTab can only capture the
      // ACTIVE tab of a window - so require the resolved tab to actually be
      // that tab, and capture ITS window. Capturing whatever happens to be
      // active would image a tab the allowlist check never covered.
      if (!tab.active || tab.windowId === undefined) {
        throw new Error("page_screenshot requires the target tab to be active in its window");
      }
      const dataUrl = await browser.tabs.captureVisibleTab(tab.windowId, { format: "png" });
      return { image: dataUrl.split(",", 2)[1], mimeType: "image/png" };
    }
    return await this.send(tab, { op, args, tabId: tab.id, guard });
  }

  private async send(tab: ResolvedTab, msg: Record<string, unknown>): Promise<unknown> {
    // Parse the OUTBOUND message against the same schema the content script
    // enforces: a page-acting message missing its guard (or a page_click
    // missing the approved descriptor) fails HERE, in the SW, before anything
    // is sent.
    const outbound = ContentMsgSchema.safeParse(msg);
    if (!outbound.success) {
      const issue = outbound.error.issues[0];
      const path = issue?.path.length ? `${issue.path.join(".")}: ` : "";
      throw new Error(
        `refusing to send a malformed content message for ${String(msg.op)}: ` +
          `${path}${issue?.message ?? "invalid"}`,
      );
    }
    await injectIfNeeded(tab.id);
    const raw = await browser.tabs.sendMessage(tab.id, outbound.data);
    // Parse the reply envelope ONCE. A reply outside the envelope is refused;
    // in particular a success payload that happens to contain error-like
    // fields (an eval that RETURNS an Error) is data, not a transport failure.
    const reply = PageReplySchema.safeParse(raw);
    if (!reply.success) {
      throw new Error("content script reply does not match the reply envelope - refusing");
    }
    if (!reply.data.ok) throw new Error(reply.data.error);
    return reply.data.data;
  }
}
