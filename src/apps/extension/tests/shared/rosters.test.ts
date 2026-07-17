// Roster drift guards (the cloud-speech roster-sync pattern): every entry in
// the generated catalogue must be owned by exactly one handling surface, and
// every Chrome permission the catalogue needs must be granted by the
// manifest. A tool added to the Rust catalogue (src/packages/core/src/tools/catalogue.rs) without a home in the
// extension - or a home that quietly stops matching the catalogue - fails
// here instead of surfacing as a runtime "unknown op".

import { OP_NAMES, TOOL_META } from "@chromium-bridge/shared";
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
