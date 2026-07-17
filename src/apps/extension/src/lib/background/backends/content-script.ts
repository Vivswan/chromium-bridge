// ContentScriptBackend - the DEFAULT page backend (cdpMode off): inject the
// content script if needed and message it. The content script drives the
// SAME shared page API the CDP backend ships (lib/dom/page-api.ts).
// Allowlist, confirmation, and masking policy run in dispatch.ts before and
// after this backend; here is only inject + transport.

import type { Browser } from "wxt/browser";
import { browser } from "wxt/browser";
import type { ClickProbe } from "../../dom/page-api";
import type { PageOp } from "../../shared/page-ops";
import type { OpArgs, PageResponse } from "../../shared/types";
import type { PageOpGuard } from "../confirm/gate";
import type { PageBackend } from "../page-backend";
import { injectIfNeeded } from "../tabs";

export class ContentScriptBackend implements PageBackend {
  async probeClick(args: OpArgs, tab: Browser.tabs.Tab): Promise<ClickProbe> {
    return (await this.send(tab, "_probe_click", args)) as ClickProbe;
  }

  async run(op: PageOp, args: OpArgs, tab: Browser.tabs.Tab, guard: PageOpGuard): Promise<unknown> {
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
    return await this.send(tab, op, args, guard);
  }

  private async send(
    tab: Browser.tabs.Tab,
    op: string,
    args: OpArgs,
    guard?: PageOpGuard,
  ): Promise<unknown> {
    if (tab.id == null) throw new Error("target tab has no id");
    await injectIfNeeded(tab.id);
    const resp = (await browser.tabs.sendMessage(tab.id, {
      op,
      args,
      tabId: tab.id,
      guard,
    })) as PageResponse;
    if (resp?.__error) throw new Error(resp.__error);
    return resp;
  }
}
