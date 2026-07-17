// CdpBackend — the page backend used when cdpMode is on (ADR-0017). Every
// page-level op runs through a persistent CdpSession (chrome.debugger) in the
// page's MAIN world via Runtime.evaluate, which bypasses page CSP. The DOM work
// is the portable functions in cdp/page-fns.ts; confirmations, settings gates,
// masking and the same-origin grace window are handled here in the SW so they
// match the content-script path.

import type { OpArgs } from "../../shared/types";
import type { PageBackend } from "../page-backend";
import { getSetting } from "../../shared/settings";
import { maskSensitive, maskString } from "../../shared/masking";
import { truncate } from "../../content/util";
import { ensureAllowed } from "../allowlist-store";
import { isDebuggable, type CdpSession, type EvaluateResponse } from "../cdp/session";
import { cdpRegistry } from "../cdp/registry";
import {
  REF_ATTR,
  pageSnapshot,
  pageText,
  pageScroll,
  pageWaitFor,
  readStorage,
  probeClickTarget,
  doClick,
  doFill,
  doPress,
  doHover,
  doSelect,
  confirmToast,
  evalToast,
} from "../cdp/page-fns";
import {
  isHighRiskClick,
  describeAction,
  describeForToast,
  type ClickTarget,
} from "../cdp/click-risk";

// Same-origin confirmation grace window, mirroring content/toast.ts. Lives in
// the SW (not the page) so it survives across CDP evaluate calls. Reset if the
// SW is recycled — acceptable, same as a re-injected content script.
let lastConfirmed: { key: string | null; until: number } = { key: null, until: 0 };

function originOf(url: string | undefined): string {
  if (!url) return "";
  try {
    return new URL(url).origin;
  } catch {
    return url;
  }
}

export class CdpBackend implements PageBackend {
  async run(op: string, args: OpArgs, tab: chrome.tabs.Tab): Promise<unknown> {
    // Preserve dispatch's ordering: allowlist check, then do the work.
    await ensureAllowed(tab.url);
    if (!isDebuggable(tab.url)) {
      throw new Error(
        `CDP mode cannot control this page (URL scheme not allowed): ${(tab.url || "").slice(0, 80)}`
      );
    }
    const session = await cdpRegistry.get(tab.id!);

    switch (op) {
      case "page_snapshot":
        return await session.evaluate(pageSnapshot, [REF_ATTR]);

      case "page_text":
        return await session.evaluate(pageText, []);

      case "page_scroll":
        return await session.evaluate(pageScroll, [
          { direction: args.direction, pixels: args.pixels },
        ]);

      case "page_wait_for":
        try {
          return await session.evaluate(
            pageWaitFor,
            [
              {
                nav: args.nav,
                selector: args.selector,
                text: args.text,
                timeoutMs: args.timeoutMs,
              },
            ],
            { awaitPromise: true }
          );
        } catch (e) {
          // A successful navigation destroys the MAIN-world execution context,
          // which rejects the pending Runtime.evaluate. For a nav wait that IS
          // the success signal, so report it as matched (mirrors the content
          // path's { matched: true, nav: true }) instead of surfacing an error.
          const msg = String((e as Error)?.message || e);
          if (
            args.nav &&
            /context was destroyed|Cannot find context|Execution context/i.test(msg)
          ) {
            return { matched: true, nav: true };
          }
          throw e;
        }

      case "page_screenshot":
        return await session.screenshot();

      case "storage_get":
        return await this.storageGet(session, args);

      case "page_fill":
        return await session.evaluate(doFill, [
          REF_ATTR,
          { ref: args.ref, selector: args.selector, value: args.value },
        ]);

      case "page_click":
        return await this.click(session, args, tab);

      case "page_press":
        return await this.press(session, args);

      case "page_hover":
        return await session.evaluate(doHover, [
          REF_ATTR,
          { ref: args.ref, selector: args.selector },
        ]);

      case "page_select":
        return await this.select(session, args);

      case "page_eval":
        return await this.pageEval(session, args, tab);

      default:
        throw new Error(`CDP backend: unsupported op ${op}`);
    }
  }

  // storage_get: read raw values in the page, mask in the SW (always-on).
  private async storageGet(session: CdpSession, args: OpArgs): Promise<unknown> {
    const raw = (await session.evaluate(readStorage, [{ type: args.type, key: args.key }])) as
      | { key: string; found: false }
      | { key: string; found: true; value: string }
      | {
          type: string;
          entries: Record<string, string>;
          count: number;
          truncated: boolean;
          totalKeys: number;
        };
    if ("entries" in raw) {
      const masked: Record<string, string> = {};
      for (const k of Object.keys(raw.entries)) masked[k] = maskString(raw.entries[k]);
      return { ...raw, entries: masked };
    }
    if (raw.found) return { ...raw, value: maskString(raw.value) };
    return raw;
  }

  // page_click with the same high-risk confirmation as the content path.
  private async click(session: CdpSession, args: OpArgs, tab: chrome.tabs.Tab): Promise<unknown> {
    const target = (await session.evaluate(probeClickTarget, [
      REF_ATTR,
      { ref: args.ref, selector: args.selector },
    ])) as ClickTarget;

    if (isHighRiskClick(target)) {
      const confirmEnabled = await getSetting("confirmHighRiskClick");
      if (confirmEnabled !== false) {
        const actionDesc = describeAction(target, "click");
        await this.confirmWithToast(
          session,
          `Click "${describeForToast(target)}"?`,
          // Key the grace window per-tab (not just per-origin) so approving on
          // one tab never silently suppresses the confirm on another same-origin
          // tab — matching the content path, where lastConfirmed is per-tab.
          `${tab.id}:${originOf(tab.url)}:${actionDesc}`,
          actionDesc,
          await getSetting("clickToastTimeoutMs")
        );
      }
    }

    return await session.evaluate(doClick, [REF_ATTR, { ref: args.ref, selector: args.selector }]);
  }

  // page_press with a confirm-every-press toast (a keypress can submit/trigger).
  private async press(session: CdpSession, args: OpArgs): Promise<unknown> {
    const keys = (args.keys || "").trim();
    if (!keys) throw new Error("page_press needs `keys`");
    await this.confirmAlways(
      session,
      `Press "${keys}"?`,
      `press ${keys}`,
      await getSetting("clickToastTimeoutMs")
    );
    return await session.evaluate(doPress, [{ keys }]);
  }

  // page_select with a confirm-every-call toast (form state change).
  private async select(session: CdpSession, args: OpArgs): Promise<unknown> {
    const value = args.value ?? "";
    await this.confirmAlways(
      session,
      `Select "${value}"?`,
      `select ${value}`,
      await getSetting("clickToastTimeoutMs")
    );
    return await session.evaluate(doSelect, [
      REF_ATTR,
      { ref: args.ref, selector: args.selector, value },
    ]);
  }

  // Confirm with NO grace window: every call prompts. Mirrors content/toast.ts
  // confirmAlways — page_press / page_select promise a confirmation on every
  // call, so unlike confirmWithToast this never consults lastConfirmed.
  private async confirmAlways(
    session: CdpSession,
    question: string,
    actionDesc: string,
    timeoutMs: number
  ): Promise<void> {
    const approved = await session.evaluate(confirmToast, [question, timeoutMs], {
      awaitPromise: true,
    });
    if (!approved) throw new Error(`user denied: ${actionDesc}`);
  }

  // Show the click confirmation toast in the page (honoring the grace window).
  private async confirmWithToast(
    session: CdpSession,
    question: string,
    key: string,
    actionDesc: string,
    timeoutMs: number
  ): Promise<void> {
    const graceMs = await getSetting("confirmGraceMs");
    if (graceMs > 0 && lastConfirmed.key === key && Date.now() < lastConfirmed.until) {
      return; // within the grace window
    }
    const approved = await session.evaluate(confirmToast, [question, timeoutMs], {
      awaitPromise: true,
    });
    if (!approved) throw new Error(`user denied: ${actionDesc}`);
    lastConfirmed = { key, until: Date.now() + graceMs };
  }

  // page_eval: settings gate + enlarged confirm toast + run in MAIN world.
  private async pageEval(
    session: CdpSession,
    args: OpArgs,
    tab: chrome.tabs.Tab
  ): Promise<unknown> {
    const code = args.code;
    if (typeof code !== "string" || !code.trim()) {
      throw new Error("page_eval needs non-empty `code`");
    }
    if ((await getSetting("pageEvalEnabled")) === false) {
      throw new Error("page_eval disabled in settings");
    }

    // Confirm every call, unless the user turned the eval confirmation off
    // (confirmPageEval=false). page_eval is DELIBERATELY excluded from the
    // same-origin grace window (ADR-0008 update 2026-07-16): there is no
    // silent-eval window, so every eval reconfirms. This mirrors the content
    // path in content/toast.ts. NOTE: disabling confirmPageEval removes
    // ADR-0008's guardrail - arbitrary JS then runs with no prompt.
    if ((await getSetting("confirmPageEval")) !== false) {
      const approved = await session.evaluate(
        evalToast,
        [code, tab.url || "", tab.title || "", await getSetting("evalToastTimeoutMs")],
        { awaitPromise: true }
      );
      if (!approved) throw new Error("user denied page_eval");
    }

    // Run the code as an async IIFE in the MAIN world. Unlike the content path
    // this does NOT use `new Function` (blocked by strict CSP) — CDP evaluates
    // it directly, which is the whole point of CDP mode.
    const expression = `(async () => {\n${code}\n})()`;
    const res: EvaluateResponse = await session.rawEvaluate(expression, { awaitPromise: true });
    return evalResponseToPayload(res, (await getSetting("evalMask")) !== false);
  }
}

// Format a raw Runtime.evaluate response for page_eval egress. EVERY egress
// path — the success value and the exception name/message/stack — passes the
// same mask gate: exceptions used to bypass it, so a page could carry a secret
// out by throwing it (`throw new Error(localStorage.authToken)`). Exported for
// tests.
export function evalResponseToPayload(res: EvaluateResponse, mask: boolean): unknown {
  let payload: unknown;
  if (res.exceptionDetails) {
    const ex = res.exceptionDetails.exception;
    const description = ex?.description || res.exceptionDetails.text || "Error";
    payload = {
      __evalError: true,
      name: ex?.className || "Error",
      message: description.split("\n")[0],
      stack: truncate(description, 2000),
    };
  } else {
    payload = res.result?.value;
  }
  return mask ? maskSensitive(payload) : payload;
}
