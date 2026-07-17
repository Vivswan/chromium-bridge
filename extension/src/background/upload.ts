// page_upload — attach a LOCAL file to a page's file input (<input type=file>)
// via Chrome's debugger (CDP DOM.setFileInputFiles), so the page can upload it.
//
// SECURITY (CRITICAL): this is a local-file EGRESS vector — a hijacked model
// could attach the user's private files to a web page and have it uploaded.
// Two gates, both mandatory:
//   1. OFF by default (fileUploadEnabled). The user must opt in.
//   2. EVERY call shows an on-page confirmation Toast displaying the exact file
//      path before anything is attached (the page is not blocked here, so we
//      can draw the Toast in the MAIN world via Runtime.evaluate). There is no
//      grace window — every upload reconfirms, like page_eval.
//
// The path is shown UNMASKED in the confirmation on purpose: the user must see
// exactly which local file would leave their disk.

import { getSetting } from "../shared/settings";
import type { OpArgs } from "../shared/types";
import { ensureAllowed } from "./allowlist-store";
import { confirmToast } from "./cdp/page-fns";
import { cdpRegistry } from "./cdp/registry";
import {
  buildEvaluateExpression,
  dbgAttach,
  dbgDetach,
  dbgSend,
  isDebuggable,
} from "./cdp/session";
import { resolveTargetTab } from "./tabs";

interface GetDocumentResult {
  root?: { nodeId?: number };
}
interface QuerySelectorResult {
  nodeId?: number;
}
interface EvaluateResult {
  result?: { value?: unknown };
}

export async function pageUpload(maybeTabId: number | undefined, args: OpArgs): Promise<unknown> {
  if ((await getSetting("fileUploadEnabled")) !== true) {
    throw new Error(
      "page_upload is disabled. Enable it in the extension settings first (it is off by default because attaching a local file to a page can exfiltrate private files).",
    );
  }
  const selector = args.selector;
  const path = args.path;
  if (!selector) throw new Error("page_upload needs `selector` for the file input");
  if (!path) throw new Error("page_upload needs `path` (absolute local file path)");
  // Require an absolute path: a POSIX "/..." or a Windows "C:\..." / UNC "\\...".
  // A relative path would resolve against the host process's cwd, which is not
  // what the user sees in the confirmation — reject it rather than guess.
  if (!(path.startsWith("/") || /^[A-Za-z]:[\\/]/.test(path) || path.startsWith("\\\\"))) {
    throw new Error(`page_upload needs an ABSOLUTE path, got: ${path}`);
  }

  const tab = await resolveTargetTab(maybeTabId);
  await ensureAllowed(tab.url);
  if (!isDebuggable(tab.url)) {
    throw new Error(
      `page_upload cannot debug this page (URL scheme not allowed): ${(tab.url || "").slice(0, 80)}`,
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
        throw new Error("该标签页已打开 DevTools,page_upload 无法附加。请关闭 DevTools 后重试。", {
          cause: e,
        });
      }
      throw e;
    }
  }
  try {
    // Confirm EVERY call, showing the exact path. Rendered in the MAIN world via
    // Runtime.evaluate (the page is not blocked, unlike a dialog).
    const timeoutMs = await getSetting("clickToastTimeoutMs");
    const question = `Upload local file to this page?\n${path}\n(input: ${selector})`;
    const expr = buildEvaluateExpression(confirmToast, [question, timeoutMs]);
    const res = await dbgSend<EvaluateResult>(tabId, "Runtime.evaluate", {
      expression: expr,
      returnByValue: true,
      awaitPromise: true,
      userGesture: true,
    });
    if (res.result?.value !== true) {
      throw new Error(`user denied page_upload: ${path}`);
    }

    // Resolve the file input node, then set the file on it.
    const doc = await dbgSend<GetDocumentResult>(tabId, "DOM.getDocument", { depth: 0 });
    const rootNodeId = doc.root?.nodeId;
    if (rootNodeId == null) throw new Error("page_upload: could not read the page document");
    const node = await dbgSend<QuerySelectorResult>(tabId, "DOM.querySelector", {
      nodeId: rootNodeId,
      selector,
    });
    if (!node.nodeId) {
      throw new Error(`page_upload: selector matched no element: ${selector}`);
    }
    await dbgSend(tabId, "DOM.setFileInputFiles", { files: [path], nodeId: node.nodeId });
    return { uploaded: selector, path };
  } finally {
    if (!reusing) await dbgDetach(tabId);
  }
}
