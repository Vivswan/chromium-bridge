// CdpBackend - the page backend used when cdpMode is on (ADR-0017). Every
// page-level op runs through a persistent CdpSession (browser.debugger) in
// the page's MAIN world via Runtime.evaluate, which bypasses page CSP. The
// DOM work is the SAME shared page API the content script uses
// (lib/dom/page-api.ts): the self-contained factory is stringified and
// applied in the page, so the two backends cannot drift. Allowlist,
// confirmation, and masking policy run in dispatch.ts around this backend.

import { unreachable } from "@chromium-bridge/shared";
import type { Browser } from "wxt/browser";
import type { ClickProbe, PageApi } from "../../dom/page-api";
import { createPageApi, REF_ATTR } from "../../dom/page-api";
import type { PageOp } from "../../shared/page-ops";
import type { OpArgs } from "../../shared/types";
import { cdpRegistry } from "../cdp/registry";
import { type CdpSession, type EvaluateResponse, isDebuggable } from "../cdp/session";
import type { PageOpGuard } from "../confirm/gate";
import type { PageBackend } from "../page-backend";

// `(createPageApi)(REF_ATTR).method(...args)` as a MAIN-world expression.
// The factory is self-contained (enforced by test), so its source evaluates
// cleanly outside module scope; args are JSON, never string-spliced user
// code. The method name comes from the typed PageApi key set only.
// `expectOrigin` (when set) is asserted against location.origin INSIDE the
// same evaluation, atomically with the act: a navigation that raced the
// SW-side checks makes the expression throw instead of acting.
export function pageApiExpression(
  method: keyof PageApi,
  args: readonly unknown[],
  expectOrigin?: string,
): string {
  const argList = args.map((a) => JSON.stringify(a)).join(", ");
  const call = `(${createPageApi.toString()})(${JSON.stringify(REF_ATTR)}).${method}(${argList})`;
  if (expectOrigin === undefined) return call;
  return (
    `(() => { if (location.origin !== ${JSON.stringify(expectOrigin)}) ` +
    `throw new Error("the page origin changed while the request was in flight - re-issue the call"); ` +
    `return ${call}; })()`
  );
}

export class CdpBackend implements PageBackend {
  async probeClick(args: OpArgs, tab: Browser.tabs.Tab): Promise<ClickProbe> {
    const session = await this.session(tab);
    return (await session.evaluate(
      pageApiExpression("probeClick", [{ ref: args.ref, selector: args.selector }]),
    )) as ClickProbe;
  }

  private async session(tab: Browser.tabs.Tab): Promise<CdpSession> {
    if (!isDebuggable(tab.url)) {
      throw new Error(
        `CDP mode cannot control this page (URL scheme not allowed): ${(tab.url || "").slice(0, 80)}`,
      );
    }
    if (tab.id == null) throw new Error("target tab has no id");
    return await cdpRegistry.get(tab.id);
  }

  async run(op: PageOp, args: OpArgs, tab: Browser.tabs.Tab, guard: PageOpGuard): Promise<unknown> {
    const session = await this.session(tab);
    const expr = (method: keyof PageApi, callArgs: readonly unknown[]) =>
      pageApiExpression(method, callArgs, guard.expectOrigin);

    switch (op) {
      case "page_snapshot":
        return await session.evaluate(expr("snapshot", []));

      case "page_text":
        return await session.evaluate(expr("text", []));

      case "page_scroll":
        return await session.evaluate(
          expr("scroll", [{ direction: args.direction, pixels: args.pixels }]),
        );

      case "page_wait_for":
        try {
          return await session.evaluate(
            expr("waitFor", [
              {
                nav: args.nav,
                selector: args.selector,
                text: args.text,
                timeoutMs: args.timeoutMs,
              },
            ]),
            [],
            { awaitPromise: true },
          );
        } catch (e) {
          // A successful navigation destroys the MAIN-world execution
          // context, which rejects the pending Runtime.evaluate. For a nav
          // wait that IS the success signal, so report it as matched
          // (mirrors the content path's { matched: true, nav: true }).
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
        // RAW values here; dispatch masks them via egress.ts (always-on).
        return await session.evaluate(expr("readStorage", [{ type: args.type, key: args.key }]));

      case "page_click":
        // guard.clickExpect binds the click to the descriptor the preflight
        // authorized; the page API refuses if the target changed.
        return await session.evaluate(
          expr("click", [{ ref: args.ref, selector: args.selector, expect: guard.clickExpect }]),
        );

      case "page_fill":
        return await session.evaluate(
          expr("fill", [{ ref: args.ref, selector: args.selector, value: args.value }]),
        );

      case "page_press":
        return await session.evaluate(expr("press", [{ keys: args.keys }]));

      case "page_hover":
        return await session.evaluate(expr("hover", [{ ref: args.ref, selector: args.selector }]));

      case "page_select":
        return await session.evaluate(
          expr("select", [{ ref: args.ref, selector: args.selector, value: args.value }]),
        );

      case "page_eval":
        return await this.pageEval(session, args, guard);

      default:
        // Exhaustiveness backstop: adding an op to PAGE_OPS without a case
        // here fails to compile.
        return unreachable(op);
    }
  }

  // page_eval: the settings gate and the confirmation already ran in
  // confirm/gate.ts; here the code just runs as an async IIFE in the MAIN
  // world. Unlike the content path this does NOT use `new Function` (blocked
  // by strict CSP) - CDP evaluates it directly, which is the point of CDP
  // mode. The raw response (value or exception) is normalized here and
  // masked by dispatch via egress.ts.
  private async pageEval(session: CdpSession, args: OpArgs, guard: PageOpGuard): Promise<unknown> {
    const code = args.code;
    if (typeof code !== "string" || !code.trim()) {
      throw new Error("page_eval needs non-empty `code`");
    }
    // The origin assertion runs INSIDE the same evaluation, atomically with
    // the eval itself: approved code can only ever run on the approved origin.
    const originCheck =
      guard.expectOrigin === undefined
        ? ""
        : `if (location.origin !== ${JSON.stringify(guard.expectOrigin)}) ` +
          `throw new Error("the page origin changed while the request was in flight - re-issue the call");\n`;
    const expression = `(async () => {\n${originCheck}${code}\n})()`;
    const res: EvaluateResponse = await session.rawEvaluate(expression, { awaitPromise: true });
    return evalResponseToPayload(res);
  }
}

// Format a raw Runtime.evaluate response for page_eval: the success value, or
// the exception as structured data the model can react to. Masking of EVERY
// field happens downstream in egress.ts - exceptions used to bypass the mask,
// so a page could carry a secret out by throwing it. Exported for tests.
export function evalResponseToPayload(res: EvaluateResponse): unknown {
  if (res.exceptionDetails) {
    const ex = res.exceptionDetails.exception;
    const description = ex?.description || res.exceptionDetails.text || "Error";
    const stack = description.length > 2000 ? `${description.slice(0, 2000)}...` : description;
    return {
      __evalError: true,
      name: ex?.className || "Error",
      message: description.split("\n")[0],
      stack,
    };
  }
  return res.result?.value;
}
