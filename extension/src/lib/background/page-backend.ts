// Strategy interface for running page-level ops, plus the selector that picks
// the backend based on the cdpMode setting (ADR-0017).
//
//   - cdpMode OFF (default) -> ContentScriptBackend: inject the content
//     script and message it.
//   - cdpMode ON            -> CdpBackend: run every op via browser.debugger
//     (CDP) in the page's MAIN world, bypassing page CSP.
//
// Both backends run THE SAME page-side implementation (lib/dom/page-api.ts) -
// the content script holds a live instance, the CDP backend ships the factory
// through Runtime.evaluate - so page behavior cannot drift between them.
// Policy (allowlist, confirmations, egress masking) lives ABOVE the backend
// in dispatch.ts + confirm/gate.ts + egress.ts; a backend only probes and
// acts.

import type { Browser } from "wxt/browser";
import type { ClickProbe } from "../dom/page-api";
import type { PageOp } from "../shared/page-ops";
import type { OpArgs } from "../shared/types";
import { CdpBackend } from "./backends/cdp";
import { ContentScriptBackend } from "./backends/content-script";
import type { PageOpGuard } from "./confirm/gate";

export interface PageBackend {
  /** DOM-read the click target so confirm/gate.ts can classify its risk. */
  probeClick(args: OpArgs, tab: Browser.tabs.Tab): Promise<ClickProbe>;
  /** Act. `guard` carries what the preflight authorized (e.g. the approved
   * click descriptor); the page API holds the act to it. */
  run(op: PageOp, args: OpArgs, tab: Browser.tabs.Tab, guard: PageOpGuard): Promise<unknown>;
}

const contentScriptBackend = new ContentScriptBackend();
const cdpBackend = new CdpBackend();

export function selectBackend(cdpMode: boolean): PageBackend {
  return cdpMode ? cdpBackend : contentScriptBackend;
}
