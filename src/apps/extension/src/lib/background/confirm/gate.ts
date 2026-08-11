// The backend-independent pre-flight for page ops: policy gates, risk
// classification, and the user confirmation - run BEFORE the backend acts.
// Confirmations are policy, not DOM work, so they live here once instead of
// being hand-mirrored between the content-script and CDP backends. The only
// backend involvement is the click probe (a DOM read).

import type { PolicyValues } from "@chromium-bridge/shared";
import type { ClickProbe } from "../../dom/page-api";
import type { PageOp } from "../../shared/page-ops";
import { TOOL_GATES } from "../../shared/tool-gates";
import type { OpArgs } from "../../shared/types";
import type { PageBackend } from "../page-backend";
import type { ResolvedTab } from "../tabs";
import { presenceRoutingEnabled } from "./presence";
import { describeAction, describeTarget, isHighRiskClick } from "./risk";
import { confirmWithUser } from "./service";

/** What the preflight authorized, BEFORE the origin is bound. This is not
 * what backends act on - dispatch turns it into a PageOpGuard via bindOrigin
 * after the post-confirmation tab recheck. */
export interface PreflightResult {
  /** For page_click: the probe the risk decision (and the user, when a
   * confirmation was shown) was based on. The page API re-probes and refuses
   * the click if the target no longer matches this descriptor. Always set for
   * page_click (the gate always probes). */
  clickExpect?: ClickProbe;
}

/** The guard a backend holds the act to. expectOrigin is REQUIRED: every
 * page op must carry the origin its allowlist check and any confirmation
 * were based on, enforced IN THE PAGE, atomically with the act (the SW-side
 * recheck can always be raced by one more navigation; location.origin inside
 * the page cannot). An unbound guard cannot be constructed - the only
 * producer is bindOrigin, and it refuses an empty origin. */
export interface PageOpGuard {
  expectOrigin: string;
  /** See PreflightResult.clickExpect; present exactly for page_click, and the
   * wire schema (ContentMsgSchema) plus both backends refuse a click
   * without it. */
  clickExpect?: ClickProbe;
}

/** Bind the preflight result to the origin the checks were based on. Fails
 * closed when there is no origin to bind - a page op must never run
 * origin-unchecked. */
export function bindOrigin(preflight: PreflightResult, expectOrigin: string): PageOpGuard {
  if (!expectOrigin) {
    throw new Error("page op has no origin to bind the act to - refusing");
  }
  return preflight.clickExpect
    ? { expectOrigin, clickExpect: preflight.clickExpect }
    : { expectOrigin };
}

// Same-origin, same-kind confirmation grace window for CLICKS only (ADR-0006
// tiering): keyed per-tab as well, so approving on one tab never silently
// suppresses the confirm on another same-origin tab. page_press, page_select,
// page_eval, tab_close, and page_upload always reconfirm. Lives in SW memory:
// a SW recycle simply re-prompts, which errs closed.
let lastConfirmed: { key: string | null; until: number } = { key: null, until: 0 };

function originOf(url: string | undefined): string {
  if (!url) return "";
  try {
    return new URL(url).origin;
  } catch {
    return url;
  }
}

/** Reset the grace window (tests). */
export function resetClickGraceWindow(): void {
  lastConfirmed = { key: null, until: 0 };
}

/**
 * Gate a page op before the backend acts. Throws to refuse:
 * - the user denied (or never answered) a confirmation;
 * - a policy gate is off (page_eval disabled).
 * Ops with no gate return an empty preflight immediately. The returned value
 * still has to pass through bindOrigin before any backend accepts it.
 *
 * The whole preflight runs under the ONE policy snapshot AND the ONE
 * decision-start panic epoch the caller threads in (ADR-0032 decision 4,
 * SFX-2): dispatch captures both beside each other at the decision's true
 * start, BEFORE its first await; tests start their own decisions via
 * withFreshPolicy plus currentPanicEpoch(). Both parameters are REQUIRED,
 * so the one-snapshot-per-decision invariant is held by the signature, not
 * by convention: a policy push landing mid-confirmation - the prompt can
 * hold this open for tens of seconds - cannot alter this decision's gates,
 * grace window, or timeouts; it applies from the next decision on. And a
 * deny-kill that crossed the decision anywhere - even before this preflight
 * was reached - denies every confirmation raised below on the epoch
 * mismatch.
 */
export async function preflightPageOp(
  op: PageOp,
  args: OpArgs,
  tab: ResolvedTab,
  backend: PageBackend,
  policy: PolicyValues,
  panicEpoch: number,
): Promise<PreflightResult> {
  switch (op) {
    case "page_click": {
      const probe = await backend.probeClick(args, tab);
      const preflight: PreflightResult = { clickExpect: probe };
      if (!isHighRiskClick(probe)) return preflight;
      // The confirmation gate can be disabled in policy. This is dangerous
      // (ADR-0006) but offered as an explicit opt-in.
      if (policy.confirmHighRiskClick === false) return preflight;
      const actionDesc = describeAction(probe, "click");
      const key = `${tab.id}:${originOf(tab.url)}:${actionDesc}`;
      const graceMs = policy.confirmGraceMs;
      if (graceMs > 0 && lastConfirmed.key === key && Date.now() < lastConfirmed.until) {
        return preflight; // within the grace window
      }
      const approved = await confirmWithUser({
        kind: "click",
        origin: originOf(tab.url),
        tabTitle: tab.title || "",
        detail: `${actionDesc}: ${describeTarget(probe)}`,
        timeoutMs: policy.clickToastTimeoutMs,
        presenceRouting: false,
        panicEpoch,
      });
      if (!approved) throw new Error(`user denied: ${actionDesc}`);
      lastConfirmed = { key, until: Date.now() + graceMs };
      return preflight;
    }

    case "page_press": {
      // Confirmed on EVERY call: a keypress can submit or trigger. No grace
      // window is consulted or extended.
      const keys = (args.keys || "").trim();
      if (!keys) throw new Error("page_press needs `keys`");
      const approved = await confirmWithUser({
        kind: "press",
        origin: originOf(tab.url),
        tabTitle: tab.title || "",
        detail: keys,
        timeoutMs: policy.clickToastTimeoutMs,
        presenceRouting: false,
        panicEpoch,
      });
      if (!approved) throw new Error(`user denied: press ${keys}`);
      return {};
    }

    case "page_select": {
      // Confirmed on EVERY call: changes form state.
      const value = args.value ?? "";
      const approved = await confirmWithUser({
        kind: "select",
        origin: originOf(tab.url),
        tabTitle: tab.title || "",
        detail: value,
        timeoutMs: policy.clickToastTimeoutMs,
        presenceRouting: false,
        panicEpoch,
      });
      if (!approved) throw new Error(`user denied: select ${value}`);
      return {};
    }

    case "page_eval": {
      const code = args.code;
      if (typeof code !== "string" || !code.trim()) {
        throw new Error("page_eval needs non-empty `code`");
      }
      // Kill switch first: refuse before any confirmation prompt. The gate
      // field comes from the shared TOOL_GATES map, the same entry the
      // options grid renders, so enforcement and UI cannot name different
      // fields.
      if (policy[TOOL_GATES.page_eval] === false) {
        throw new Error("page_eval disabled in settings");
      }
      // Confirm EVERY call, showing the full code, unless the eval
      // confirmation is off in policy (confirmPageEval=false). page_eval is
      // DELIBERATELY excluded from the grace window (ADR-0008): there is no
      // silent-eval window. NOTE: disabling confirmPageEval removes
      // ADR-0008's guardrail - arbitrary JS then runs with no prompt.
      if (policy.confirmPageEval === false) return {};
      const approved = await confirmWithUser({
        kind: "eval",
        origin: originOf(tab.url),
        tabTitle: tab.title || "",
        detail: code,
        timeoutMs: policy.evalToastTimeoutMs,
        // The hardware-routing verdict is part of THIS decision's snapshot
        // (ADR-0032 decision 4): computed here and carried in the request,
        // so a policy push landing while the confirmation waits in the
        // queue cannot re-route it at presentation time.
        presenceRouting: await presenceRoutingEnabled(policy),
        panicEpoch,
      });
      if (!approved) throw new Error("user denied page_eval");
      return {};
    }

    default:
      return {}; // no gate for this op
  }
}
