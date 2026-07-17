// The page-op roster: the catalogue ops that run inside the page, via one of
// the two page backends (content script or CDP). Everything else in the
// catalogue is either handled directly in the service worker (dispatch.ts's
// SW_OPS) or answered by the MCP server (scope "server") and never reaches
// the extension.
//
// This is the single roster both page backends must cover: content/handle.ts
// and backends/cdp.ts each switch over PageOp with an exhaustiveness
// backstop, and the roster drift test asserts SW_OPS + PAGE_OPS + the
// server-scope ops partition the generated OP_NAMES exactly.

import type { OpName } from "@chromium-bridge/shared";

export const PAGE_OPS = [
  "page_snapshot",
  "page_click",
  "page_fill",
  "page_text",
  "page_screenshot",
  "page_scroll",
  "page_wait_for",
  "page_eval",
  "storage_get",
  "page_press",
  "page_hover",
  "page_select",
] as const satisfies readonly OpName[];

export type PageOp = (typeof PAGE_OPS)[number];

const PAGE_OP_SET: ReadonlySet<string> = new Set(PAGE_OPS);

export function isPageOp(op: string): op is PageOp {
  return PAGE_OP_SET.has(op);
}
