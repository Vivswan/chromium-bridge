// Roster drift guards (the cloud-speech roster-sync pattern): every entry in
// the generated catalogue must be owned by exactly one handling surface, and
// every Chrome permission the catalogue needs must be granted by the
// manifest. A tool added to contracts/tools.json without a home in the
// extension - or a home that quietly stops matching the catalogue - fails
// here instead of surfacing as a runtime "unknown op".

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { OP_NAMES, TOOL_META } from "@chromium-bridge/shared";
import { SW_OPS } from "../background/dispatch";
import { PAGE_OPS } from "./page-ops";

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
  test("every tool's Chrome permission is granted in manifest.json", () => {
    const manifest = JSON.parse(
      readFileSync(resolve(import.meta.dir, "../../manifest.json"), "utf8"),
    ) as { permissions?: string[] };
    const granted = new Set(manifest.permissions ?? []);
    const needed = [...new Set(OP_NAMES.map((op) => TOOL_META[op].permission))].sort();
    for (const permission of needed) {
      expect(granted.has(permission) ? permission : `missing: ${permission}`).toBe(permission);
    }
  });
});
