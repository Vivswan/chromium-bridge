// ContentScriptBackend — the DEFAULT page backend (cdpMode off). This is the
// original dispatch.ts page path, extracted verbatim: ensureAllowed, inject the
// content script if needed, message it, and surface `__error` as a throw.
// Behavior here must stay byte-for-byte identical to the pre-CDP-mode code.

import type { PageOp } from "../../shared/page-ops";
import type { OpArgs, PageResponse } from "../../shared/types";
import { ensureAllowed } from "../allowlist-store";
import type { PageBackend } from "../page-backend";
import { injectIfNeeded } from "../tabs";

export class ContentScriptBackend implements PageBackend {
  async run(op: PageOp, args: OpArgs, tab: chrome.tabs.Tab): Promise<unknown> {
    await ensureAllowed(tab.url);
    await injectIfNeeded(tab.id!);
    // content.js listens for these and replies.
    const resp = (await chrome.tabs.sendMessage(tab.id!, {
      op,
      args,
      tabId: tab.id,
    })) as PageResponse;
    if (resp?.__error) throw new Error(resp.__error);
    return resp;
  }
}
