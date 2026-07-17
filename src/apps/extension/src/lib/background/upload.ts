// page_upload — attach a LOCAL file to a page's file input (<input type=file>)
// via Chrome's debugger (CDP DOM.setFileInputFiles), so the page can upload it.
//
// SECURITY (CRITICAL): this is a local-file EGRESS vector — a hijacked model
// could attach the user's private files to a web page and have it uploaded.
// Two gates, both mandatory:
//   1. OFF by default (fileUploadEnabled). The user must opt in.
//   2. EVERY call shows a confirmation on the extension-owned surface
//      (ADR-0027) displaying the exact file path before anything is attached.
//      There is no grace window - every upload reconfirms, like page_eval.
//      Phase 8 routes this same confirmation through the host's Secure
//      Enclave user-presence gate (Touch ID).
//
// The path is shown UNMASKED in the confirmation on purpose: the user must see
// exactly which local file would leave their disk.

import { getSetting } from "../shared/settings";
import type { OpArgs } from "../shared/types";
import { ensureAllowed } from "./allowlist-store";
import { cdpRegistry } from "./cdp/registry";
import { dbgAttach, dbgDetach, dbgSend, isDebuggable } from "./cdp/session";
import { confirmWithUser } from "./confirm/service";
import { resolveTargetTab } from "./tabs";

interface GetDocumentResult {
  root?: { nodeId?: number; documentURL?: string };
}
interface QuerySelectorResult {
  nodeId?: number;
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

  // Confirm EVERY call, showing the exact path, BEFORE anything attaches.
  // The path is shown UNMASKED on purpose: the user must see exactly which
  // local file would leave their disk.
  const approved = await confirmWithUser({
    kind: "upload",
    origin: tab.url ? new URL(tab.url).origin : "",
    tabTitle: tab.title || "",
    detail: `${path}\n(input: ${selector})`,
    timeoutMs: await getSetting("clickToastTimeoutMs"),
  });
  if (!approved) {
    throw new Error(`user denied page_upload: ${path}`);
  }

  // The confirmation held the pipeline open; the tab may have navigated.
  // Re-fetch it and fail closed if the origin is no longer the one the user
  // approved uploading to.
  {
    const current = await resolveTargetTab(tabId);
    const originNow = current.url ? new URL(current.url).origin : "";
    const originApproved = tab.url ? new URL(tab.url).origin : "";
    if (originNow !== originApproved || !isDebuggable(current.url)) {
      throw new Error(
        "the tab navigated while the upload confirmation was open; re-issue page_upload",
      );
    }
  }

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
          "page_upload cannot attach: DevTools is open on this tab. Close DevTools and retry.",
          {
            cause: e,
          },
        );
      }
      throw e;
    }
  }
  try {
    // Resolve the file input node, then set the file on it. The document URL
    // comes from the SAME DOM.getDocument the nodeId does, so this origin
    // check is bound to the exact document the file would be attached to: a
    // navigation after it invalidates the nodeId and the attach fails. This
    // closes the window between the SW-side origin recheck and the attach.
    const doc = await dbgSend<GetDocumentResult>(tabId, "DOM.getDocument", { depth: 0 });
    const rootNodeId = doc.root?.nodeId;
    if (rootNodeId == null) throw new Error("page_upload: could not read the page document");
    const docUrl = doc.root?.documentURL;
    const approvedOrigin = tab.url ? new URL(tab.url).origin : "";
    let docOrigin = "";
    try {
      docOrigin = docUrl ? new URL(docUrl).origin : "";
    } catch {
      docOrigin = "";
    }
    if (!docOrigin || docOrigin !== approvedOrigin) {
      throw new Error(
        "the page navigated while the upload confirmation was open; re-issue page_upload",
      );
    }
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
