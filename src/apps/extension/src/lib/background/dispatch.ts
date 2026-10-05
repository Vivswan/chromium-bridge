// Route an inbound BridgeReq to the code that should act on it: SW_OPS run
// here in the service worker; PAGE_OPS are forwarded to the target tab
// through the selected page backend. The two rosters are typed against the
// generated OpName union and, together with the server-answered ops, must
// partition the catalogue exactly (enforced by the roster drift test).
//
// This module also owns the request's life: every request is registered the moment port.ts hands it over,
// before the enrollment gate, and stays in flight until its outcome. A `cancel` signal from the server (the
// host relays it; port.ts routes it to `collaborator`) aborts that id: a pipeline not yet started never starts,
// one under way stops at its next stage boundary, and either way the outcome is `cancelled`, which port.ts
// posts nothing for.

import type { BridgeReq } from "@chromium-bridge/shared/envelope";
import { BridgeCancelSchema } from "@chromium-bridge/shared/envelope.gen";
import { isOpName, type OpName } from "@chromium-bridge/shared/ops.gen";
import type { PolicyValues } from "@chromium-bridge/shared/policy.gen";
import { unreachable } from "@chromium-bridge/shared/util";
import { browser } from "wxt/browser";
import { inLife } from "../shared/in-life";
import { isPageOp } from "../shared/page-ops";
import { ensureAllowed } from "./allowlist-store";
import { bindOrigin, preflightPageOp } from "./confirm/gate";
import { currentPanicEpoch } from "./confirm/service";
import type { PortCollaborator } from "./connection";
import { consoleGet } from "./console";
import { cookieGet } from "./cookies";
import { handleDialog } from "./dialog";
import { getEffectivePolicy } from "./effective-policy";
import { maskOpResult } from "./egress";
import type { Gate } from "./enrollment";
import { selectBackend } from "./page-backend";
import { decide } from "./policy";
import { snapshotPrecise } from "./precise";
import {
  activeTab,
  pageBack,
  pageForward,
  pageNavigate,
  pageReload,
  type ResolvedTab,
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

/** How one request ended. port.ts posts the first two as the response and nothing for `cancelled`: the server
 * stopped waiting for that id, so a reply would reach a caller that no longer exists. */
export type Dispatched =
  | { outcome: "ok"; data: unknown }
  | { outcome: "error"; error: unknown }
  | { outcome: "cancelled" };

/** The admission gate's shape (enrollment.enrollmentGate): `onAllowed` runs inside its serialized critical
 * section exactly when the verdict is allowed. */
export type AdmissionGate = (onAllowed: () => void) => Promise<Gate>;

// The requests this service-worker life holds, by id, from the frame's arrival to the outcome. The server's
// ids are unique per server process, but a server restart starts over at 1 while an op from the old connection
// may still be running, so an entry is only ever removed by the controller that owns it.
const inFlight = inLife(() => new Map<BridgeReq["id"], AbortController>());

/** Claims the server's `cancel` signal frames. A malformed one is claimed and dropped (never answered: a cancel
 * has no reply), an unknown id is ignored (answered already, or never seen). */
export const collaborator: PortCollaborator = {
  onAttach() {},
  onDetach() {},
  onFrame(frame) {
    if (typeof frame !== "object" || frame === null) return false;
    if ((frame as { type?: unknown }).type !== "cancel") return false;
    const parsed = BridgeCancelSchema.safeParse(frame);
    if (!parsed.success) {
      console.warn("[bb] dropping malformed cancel:", parsed.error.issues[0]?.message);
      return true;
    }
    inFlight.value.get(parsed.data.id)?.abort();
    return true;
  },
};

/**
 * The disable gate. Unknown or empty ops pass through untouched: parseBridgeReq refuses them at the port
 * boundary, and that contract stays there. The switch is on the typed refusal cause, exhaustively, so a cause
 * added to policy.ts fails to compile here and rewording a display `reason` cannot change what this gate does.
 */
export function assertNotDisabled(op: string | undefined, disabledTools: string[]): void {
  if (!op || !isOpName(op)) return;
  const decision = decide(op, { disabledTools });
  if (decision.allowed) return;
  switch (decision.cause) {
    case "disabled-in-settings":
      throw new Error(`tool disabled in settings: ${op}`);
    case "unknown-tool":
      // Unreachable in practice: the isOpName guard above means decide()
      // found catalogue metadata. Kept as passthrough (never a throw) so the
      // gate's contract for unknown ops stays with the port boundary.
      return;
    default:
      unreachable(decision.cause);
  }
}

/** Re-fetch a tab and require its origin to still match the one the
 * allowlist check and any confirmation were based on (fail closed on a
 * navigation raced against the pipeline). Exported for tests. */
export async function recheckTab(tab: ResolvedTab): Promise<ResolvedTab> {
  const current = await browser.tabs.get(tab.id);
  if (originOf(current.url) !== originOf(tab.url)) {
    throw new Error(
      "the tab navigated to a different origin while the request was being " +
        "confirmed; re-issue the call against the new page",
    );
  }
  // Fetched by id, so the id is necessarily present; keep the fail-closed
  // check rather than a cast.
  if (current.id == null) throw new Error("target tab has no id");
  return current as ResolvedTab;
}

function originOf(url: string | undefined): string {
  if (!url) return "";
  try {
    return new URL(url).origin;
  } catch {
    return url;
  }
}

/** Run one request from its frame's arrival to its outcome. Registered for cancel first, then the pipeline
 * starts inside the gate's critical section (a revoke landing between "allowed" and the first op is
 * impossible) and only if no cancel landed while the request waited. A refused or failing gate is an error
 * outcome; the pipeline is checked for a cancel at each stage boundary, and a stage already running (a
 * confirmation prompt, a debugger call) finishes on its own with its result discarded here. */
export function dispatch(req: BridgeReq, gate: AdmissionGate): Promise<Dispatched> {
  const controller = new AbortController();
  inFlight.value.set(req.id, controller);
  const { signal } = controller;
  const unlessCancelled = (done: Dispatched): Dispatched =>
    signal.aborted ? { outcome: "cancelled" } : done;
  return new Promise<Dispatched>((resolve) => {
    const refused = (err: unknown) =>
      resolve(
        unlessCancelled({
          outcome: "error",
          error: new Error(`enrollment gate error: ${String(err)}`),
        }),
      );
    // Gate errors are ambiguity, and ambiguity refuses; a gate that throws before returning its promise is
    // the same ambiguity, so the never-rejects contract holds for it too.
    let verdict: Promise<Gate>;
    try {
      verdict = gate(() => {
        if (signal.aborted) {
          resolve({ outcome: "cancelled" });
          return;
        }
        run(req, signal).then(
          (data) => resolve(unlessCancelled({ outcome: "ok", data })),
          (error) => resolve(unlessCancelled({ outcome: "error", error })),
        );
      });
    } catch (err) {
      refused(err);
      return;
    }
    verdict.then((gateVerdict) => {
      if (!gateVerdict.allowed) {
        resolve(unlessCancelled({ outcome: "error", error: new Error(gateVerdict.reason) }));
      }
    }, refused);
  }).finally(() => {
    if (inFlight.value.get(req.id) === controller) inFlight.value.delete(req.id);
  });
}

async function run(req: BridgeReq, signal: AbortSignal): Promise<unknown> {
  // Captured synchronously, before this request's first await: every confirmation this decision raises
  // carries it, so a deny-kill that lands AND lifts anywhere across the decision (inside the policy read, the
  // tab resolve, or the allowlist check) still denies the confirmation on the epoch mismatch.
  const panicEpoch = currentPanicEpoch();
  // ONE policy snapshot per request, never a live re-read, threaded through
  // the disable gate, the backend choice, the confirmation preflight, the
  // SW-op handlers, and egress masking: a policy push landing while this
  // request is in flight - a confirmation can hold the pipeline open for
  // tens of seconds - cannot alter the decision it started under. An
  // accepted push applies from the next request on.
  const effective = await getEffectivePolicy();
  signal.throwIfAborted();
  if (effective.state === "blocked") {
    // The enrollment gate's barrier check and this snapshot are SEPARATE awaits, so a compromise latching
    // between them must refuse HERE rather than let the request run under the deny-baseline defaults (whose
    // empty disabledTools is the permissive pole).
    throw new Error(effective.reason);
  }
  const policy = effective.values;

  // Tool enable/disable gate: if the op is in the disabledTools list, reject
  // before doing anything.
  assertNotDisabled(req.op, policy.disabledTools);

  if (isSwReq(req)) return await dispatchSw(req, policy, panicEpoch);

  if (isPageOp(req.op)) {
    // Page-level ops, one pipeline for both backends:
    //   resolve tab -> allowlist -> preflight (risk + confirmation, on the
    //   extension-owned surface) -> re-validate the tab -> backend act
    //   (content script or CDP per cdpMode) -> egress masking.
    // Policy never lives in a backend, so it cannot drift between them.
    const tab = await activeTab();
    // Before the allowlist: a non-allowlisted origin raises a 60 s approval prompt the server has stopped
    // waiting for.
    signal.throwIfAborted();
    await ensureAllowed(tab.url);
    signal.throwIfAborted();
    const backend = selectBackend(policy.cdpMode === true);
    const preflight = await preflightPageOp(req.op, req.args, tab, backend, policy, panicEpoch);
    signal.throwIfAborted();
    // A confirmation can hold the pipeline open for tens of seconds, during
    // which the tab may navigate ANYWHERE. Re-fetch the SAME tab (by id, so
    // an active-tab switch cannot substitute a different one) and fail
    // closed if its origin is no longer what was checked and confirmed.
    const current = await recheckTab(tab);
    signal.throwIfAborted();
    // Bind the act to the approved origin. backend.run only accepts a bound
    // guard (expectOrigin is required on PageOpGuard, and bindOrigin is its
    // only producer), and the backends enforce it INSIDE the page, atomically
    // with the act - closing the residual race between this recheck and the
    // backend's evaluate/message.
    const guard = bindOrigin(preflight, originOf(tab.url));
    const result = await backend.run(req.op, req.args, current, guard);
    return await maskOpResult(req.op, result, policy);
  }

  // What remains is the server scope (list_browsers): answered by the MCP
  // server from its own connection registry, never forwarded to a browser.
  throw new Error(`op is answered by the MCP server, not the extension: ${req.op}`);
}

// Switching on `req.op` narrows `req.args` to that tool's schema
// (BridgeCommand), so the required args (e.g. tabId, url) are typed
// non-optional - no `!` needed. The `default` arm is the exhaustiveness
// backstop: adding an op to SW_OPS without a case here fails to compile.
async function dispatchSw(req: SwReq, policy: PolicyValues, panicEpoch: number): Promise<unknown> {
  switch (req.op) {
    case "tab_list":
      return await tabList();
    case "tab_focus":
      return await tabFocus(req.args.tabId);
    case "tab_open":
      return await tabOpen(req.args.url);
    case "tab_close":
      return await tabClose(req.args.tabId, policy, panicEpoch);
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
      return await snapshotPrecise(req.args, policy);
    case "cookie_get":
      // browser.cookies API is only available in SW context.
      return await cookieGet(req.args);
    case "console_get":
      // browser.debugger (CDP Runtime/Log); SW-only, does NOT go through content.js.
      return await consoleGet(req.args);
    case "page_handle_dialog":
      // browser.debugger (CDP Page.handleJavaScriptDialog); SW-only.
      return await handleDialog(req.args, policy);
    case "page_upload":
      // browser.debugger (CDP DOM.setFileInputFiles); SW-only. OFF by default.
      return await pageUpload(req.args, policy, panicEpoch);
    default:
      return unreachable(req);
  }
}
