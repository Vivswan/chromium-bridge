// The backend-independent pre-flight for page ops: settings gates, risk
// classification, and the user confirmation - run BEFORE the backend acts.
// Confirmations are policy, not DOM work, so they live here once instead of
// being hand-mirrored between the content-script and CDP backends. The only
// backend involvement is the click probe (a DOM read).

import type { Browser } from "wxt/browser";
import type { ClickProbe } from "../../dom/page-api";
import type { PageOp } from "../../shared/page-ops";
import { getSetting } from "../../shared/settings";
import type { OpArgs } from "../../shared/types";
import type { PageBackend } from "../page-backend";
import { describeAction, describeTarget, isHighRiskClick } from "./risk";
import { confirmWithUser } from "./service";

/** What the preflight authorized, for the backend to hold the act to. */
export interface PageOpGuard {
  /** The origin the allowlist check and any confirmation were based on.
   * Enforced IN THE PAGE, atomically with the act (the SW-side recheck can
   * always be raced by one more navigation; location.origin inside the page
   * cannot). Set by dispatch for every page op. */
  expectOrigin?: string;
  /** For page_click: the probe the risk decision (and the user, when a
   * confirmation was shown) was based on. The page API re-probes and refuses
   * the click if the target no longer matches this descriptor. */
  clickExpect?: ClickProbe;
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
 * - a settings gate is off (page_eval disabled).
 * Ops with no gate return an empty guard immediately.
 */
export async function preflightPageOp(
  op: PageOp,
  args: OpArgs,
  tab: Browser.tabs.Tab,
  backend: PageBackend,
): Promise<PageOpGuard> {
  switch (op) {
    case "page_click": {
      const probe = await backend.probeClick(args, tab);
      const guard: PageOpGuard = { clickExpect: probe };
      if (!isHighRiskClick(probe)) return guard;
      // The confirmation gate can be disabled by the user in settings. This
      // is dangerous (ADR-0006) but offered as an explicit opt-in.
      if ((await getSetting("confirmHighRiskClick")) === false) return guard;
      const actionDesc = describeAction(probe, "click");
      const key = `${tab.id}:${originOf(tab.url)}:${actionDesc}`;
      const graceMs = await getSetting("confirmGraceMs");
      if (graceMs > 0 && lastConfirmed.key === key && Date.now() < lastConfirmed.until) {
        return guard; // within the grace window
      }
      const approved = await confirmWithUser({
        kind: "click",
        origin: originOf(tab.url),
        tabTitle: tab.title || "",
        detail: `${actionDesc}: ${describeTarget(probe)}`,
        timeoutMs: await getSetting("clickToastTimeoutMs"),
      });
      if (!approved) throw new Error(`user denied: ${actionDesc}`);
      lastConfirmed = { key, until: Date.now() + graceMs };
      return guard;
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
        timeoutMs: await getSetting("clickToastTimeoutMs"),
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
        timeoutMs: await getSetting("clickToastTimeoutMs"),
      });
      if (!approved) throw new Error(`user denied: select ${value}`);
      return {};
    }

    case "page_eval": {
      const code = args.code;
      if (typeof code !== "string" || !code.trim()) {
        throw new Error("page_eval needs non-empty `code`");
      }
      // Kill switch first: refuse before any confirmation prompt.
      if ((await getSetting("pageEvalEnabled")) === false) {
        throw new Error("page_eval disabled in settings");
      }
      // Confirm EVERY call, showing the full code, unless the user turned the
      // eval confirmation off (confirmPageEval=false). page_eval is
      // DELIBERATELY excluded from the grace window (ADR-0008): there is no
      // silent-eval window. NOTE: disabling confirmPageEval removes
      // ADR-0008's guardrail - arbitrary JS then runs with no prompt.
      if ((await getSetting("confirmPageEval")) === false) return {};
      const approved = await confirmWithUser({
        kind: "eval",
        origin: originOf(tab.url),
        tabTitle: tab.title || "",
        detail: code,
        timeoutMs: await getSetting("evalToastTimeoutMs"),
      });
      if (!approved) throw new Error("user denied page_eval");
      return {};
    }

    default:
      return {}; // no gate for this op
  }
}
