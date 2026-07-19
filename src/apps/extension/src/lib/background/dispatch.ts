// Route an inbound BridgeReq to the code that should act on it: SW_OPS run
// here in the service worker; PAGE_OPS are forwarded to the target tab
// through the selected page backend. The two rosters are typed against the
// generated OpName union and, together with the server-answered ops, must
// partition the catalogue exactly (enforced by the roster drift test).

import { isOpName, type OpName, unreachable } from "@chromium-bridge/shared";
import type { Browser } from "wxt/browser";
import { browser } from "wxt/browser";
import { isPageOp } from "../shared/page-ops";
import { getSetting } from "../shared/settings";
import type { BridgeReq } from "../shared/types";
import { ensureAllowed } from "./allowlist-store";
import { preflightPageOp } from "./confirm/gate";
import { consoleGet } from "./console";
import { cookieGet } from "./cookies";
import { handleDialog } from "./dialog";
import { maskOpResult } from "./egress";
import { selectBackend } from "./page-backend";
import { decide } from "./policy";
import { snapshotPrecise } from "./precise";
import {
  pageBack,
  pageForward,
  pageNavigate,
  pageReload,
  resolveTargetTab,
  tabClose,
  tabFocus,
  tabList,
  tabOpen,
} from "./tabs";
import { pageUpload } from "./upload";

// The ops handled directly in the service worker (no content script): tab
// management, navigation, and the browser.debugger / browser.cookies ops whose
// APIs only exist in the SW context.
export const SW_OPS = [
  "tab_list",
  "tab_focus",
  "tab_open",
  "tab_close",
  "page_navigate",
  "page_back",
  "page_forward",
  "page_reload",
  "page_snapshot_precise",
  "cookie_get",
  "console_get",
  "page_handle_dialog",
  "page_upload",
] as const satisfies readonly OpName[];

export type SwOp = (typeof SW_OPS)[number];

const SW_OP_SET: ReadonlySet<string> = new Set(SW_OPS);

type SwReq = Extract<BridgeReq, { op: SwOp }>;

function isSwReq(req: BridgeReq): req is SwReq {
  return SW_OP_SET.has(req.op);
}

/**
 * The disable gate, factored out for testability. Routes through the pure
 * policy `decide()` but preserves dispatch's original behavior exactly:
 *
 * - Only *known* tools (in the generated catalogue) are consulted, because
 *   `decide()` fail-closes unknown ops. Unknown/empty ops pass through
 *   untouched - parseBridgeReq refuses them at the port boundary before
 *   dispatch is ever reached.
 * - A known, disabled tool throws `tool disabled in settings: <op>` - the same
 *   message the old inline check produced (`decision.reason` is
 *   "tool disabled in settings").
 */
export function assertNotDisabled(op: string | undefined, disabledTools: string[]): void {
  if (!op || !isOpName(op)) return;
  const decision = decide(op, { disabledTools });
  if (!decision.allowed && decision.reason === "tool disabled in settings") {
    throw new Error(`${decision.reason}: ${op}`);
  }
}

/** Re-fetch a tab and require its origin to still match the one the
 * allowlist check and any confirmation were based on (fail closed on a
 * navigation raced against the pipeline). Exported for tests. */
export async function recheckTab(tab: Browser.tabs.Tab): Promise<Browser.tabs.Tab> {
  if (tab.id == null) throw new Error("target tab has no id");
  const current = await browser.tabs.get(tab.id);
  if (originOf(current.url) !== originOf(tab.url)) {
    throw new Error(
      "the tab navigated to a different origin while the request was being " +
        "confirmed; re-issue the call against the new page",
    );
  }
  return current;
}

function originOf(url: string | undefined): string {
  if (!url) return "";
  try {
    return new URL(url).origin;
  } catch {
    return url;
  }
}

export async function dispatch(req: BridgeReq): Promise<unknown> {
  // Tool enable/disable gate: if the op is in the user's disabledTools list,
  // reject before doing anything.
  const disabled = await getSetting("disabledTools");
  assertNotDisabled(req.op, disabled);

  if (isSwReq(req)) return await dispatchSw(req);

  if (isPageOp(req.op)) {
    // Page-level ops, one pipeline for both backends:
    //   resolve tab -> allowlist -> preflight (risk + confirmation, on the
    //   extension-owned surface) -> re-validate the tab -> backend act
    //   (content script or CDP per cdpMode, ADR-0017) -> egress masking.
    // Policy never lives in a backend, so it cannot drift between them.
    const tab = await resolveTargetTab(req.tabId);
    await ensureAllowed(tab.url);
    const cdpMode = (await getSetting("cdpMode")) === true;
    const backend = selectBackend(cdpMode);
    const guard = await preflightPageOp(req.op, req.args, tab, backend);
    // A confirmation can hold the pipeline open for tens of seconds, during
    // which the tab may navigate ANYWHERE. Re-fetch the SAME tab (by id, so
    // an active-tab switch cannot substitute a different one) and fail
    // closed if its origin is no longer what was checked and confirmed.
    const current = await recheckTab(tab);
    // Bind the act to the approved origin: the backends enforce this INSIDE
    // the page, atomically with the act, closing the residual race between
    // this recheck and the backend's evaluate/message.
    guard.expectOrigin = originOf(tab.url);
    const result = await backend.run(req.op, req.args, current, guard);
    return await maskOpResult(req.op, result);
  }

  // What remains is the server scope (list_browsers): answered by the MCP
  // server from its own connection registry, never forwarded to a browser.
  throw new Error(`op is answered by the MCP server, not the extension: ${req.op}`);
}

// Switching on `req.op` narrows `req.args` to that tool's schema
// (BridgeCommand), so the required args (e.g. tabId, url) are typed
// non-optional - no `!` needed. The `default` arm is the exhaustiveness
// backstop: adding an op to SW_OPS without a case here fails to compile.
async function dispatchSw(req: SwReq): Promise<unknown> {
  switch (req.op) {
    case "tab_list":
      return await tabList();
    case "tab_focus":
      return await tabFocus(req.args.tabId);
    case "tab_open":
      return await tabOpen(req.args.url);
    case "tab_close":
      return await tabClose(req.args.tabId);
    case "page_navigate":
      return await pageNavigate(req.args.url);
    case "page_back":
      return await pageBack();
    case "page_forward":
      return await pageForward();
    case "page_reload":
      return await pageReload();
    case "page_snapshot_precise":
      // Handled in SW via browser.debugger; does NOT go through content.js.
      return await snapshotPrecise(req.tabId, req.args);
    case "cookie_get":
      // browser.cookies API is only available in SW context.
      return await cookieGet(req.tabId, req.args);
    case "console_get":
      // browser.debugger (CDP Runtime/Log); SW-only, does NOT go through content.js.
      return await consoleGet(req.tabId, req.args);
    case "page_handle_dialog":
      // browser.debugger (CDP Page.handleJavaScriptDialog); SW-only.
      return await handleDialog(req.tabId, req.args);
    case "page_upload":
      // browser.debugger (CDP DOM.setFileInputFiles); SW-only. OFF by default.
      return await pageUpload(req.tabId, req.args);
    default:
      return unreachable(req);
  }
}
