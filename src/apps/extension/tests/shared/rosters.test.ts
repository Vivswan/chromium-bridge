// Roster drift guards (the cloud-speech roster-sync pattern): every entry in
// the generated catalogue must be owned by exactly one handling surface, and
// every Chrome permission the catalogue needs must be granted by the
// manifest. A tool added to the Rust catalogue (src/packages/core/src/tools/catalogue.rs) without a home in the
// extension - or a home that quietly stops matching the catalogue - fails
// here instead of surfacing as a runtime "unknown op".

import { ContentMsgSchema, OP_NAMES, TOOL_META } from "@chromium-bridge/shared";
import { describe, expect, test } from "vitest";
import { SW_OPS } from "@/lib/background/dispatch";
import { MANIFEST_PERMISSIONS } from "@/lib/shared/manifest-permissions";
import { PAGE_OPS } from "@/lib/shared/page-ops";

// Ops answered by the MCP server itself (scope "server"): they never reach
// the extension, so no extension surface may claim them.
const SERVER_OPS = OP_NAMES.filter((op) => TOOL_META[op].scope === "server");

describe("op rosters partition the catalogue", () => {
  test("SW_OPS, PAGE_OPS, and the server ops cover every op exactly once", () => {
    const claimed = [...SW_OPS, ...PAGE_OPS, ...SERVER_OPS];
    expect(claimed.sort()).toEqual([...OP_NAMES].sort());
    expect(new Set(claimed).size).toBe(claimed.length);
  });

  test("no roster claims a server-answered op", () => {
    for (const op of SERVER_OPS) {
      expect(SW_OPS).not.toContain(op);
      expect(PAGE_OPS).not.toContain(op);
    }
  });
});

describe("the content-message contract covers the page roster", () => {
  // The SW <-> content-script schema (ContentMsgSchema) must stay in lockstep
  // with PAGE_OPS: every page op except page_screenshot (captured in the SW)
  // is accepted ONLY with a guard. An op added to PAGE_OPS without a schema
  // branch would fail closed at runtime - this test surfaces the drift here
  // instead.
  const CONTENT_OPS = PAGE_OPS.filter((op) => op !== "page_screenshot");

  test("every content-reaching page op requires its guard", () => {
    for (const op of CONTENT_OPS) {
      const guardless = ContentMsgSchema.safeParse({ op, args: {} });
      expect(guardless.success ? `guardless ${op} accepted` : op).toBe(op);
      const guard =
        op === "page_click"
          ? {
              expectOrigin: "https://example.com",
              clickExpect: { tagName: "A", role: "link", type: "", hasHref: true, name: "x" },
            }
          : { expectOrigin: "https://example.com" };
      const guarded = ContentMsgSchema.safeParse({ op, args: {}, guard });
      expect(guarded.success ? op : `guarded ${op} refused`).toBe(op);
    }
  });

  test("page_screenshot has no content-script branch (SW-captured)", () => {
    expect(
      ContentMsgSchema.safeParse({
        op: "page_screenshot",
        args: {},
        guard: { expectOrigin: "https://example.com" },
      }).success,
    ).toBe(false);
  });
});

describe("manifest permissions cover the catalogue", () => {
  test("every tool's Chrome permission is granted by the generated manifest", () => {
    // MANIFEST_PERMISSIONS is the exact list wxt.config.ts emits into the
    // generated manifest, so checking it checks the manifest.
    const granted = new Set<string>(MANIFEST_PERMISSIONS);
    const needed = [...new Set(OP_NAMES.map((op) => TOOL_META[op].permission))].sort();
    for (const permission of needed) {
      expect(granted.has(permission) ? permission : `missing: ${permission}`).toBe(permission);
    }
  });
});
