// The capabilities parity gate: contracts/capabilities.json groups tools for
// connection-time negotiation and is derived conceptually from tools.json
// (permission + scope). Its groupings and prose are hand-authored, so it is
// VERIFIED against tools.json here rather than generated - any tool added,
// removed, or re-permissioned without a matching capabilities update fails CI.

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const CONTRACTS = resolve(import.meta.dir, "../../../../contracts");

interface Capability {
  id: string;
  description: string;
  permissions: string[];
  tools: string[];
}

const { capabilities } = JSON.parse(
  readFileSync(resolve(CONTRACTS, "capabilities.json"), "utf8"),
) as { capabilities: Capability[] };

const { tools } = JSON.parse(readFileSync(resolve(CONTRACTS, "tools.json"), "utf8")) as {
  tools: { name: string; permission: string; scope: string }[];
};

// list_browsers is answered by the MCP server from its own connection
// registry; it needs nothing from the browser, so it has no capability.
const SERVER_SCOPE_TOOLS = new Set(tools.filter((t) => t.scope === "server").map((t) => t.name));

describe("capabilities.json parity with tools.json", () => {
  test("capability ids are unique and described", () => {
    const ids = capabilities.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const c of capabilities) {
      expect(c.id.length).toBeGreaterThan(0);
      expect(c.description.length).toBeGreaterThan(0);
      expect(c.tools.length).toBeGreaterThan(0);
    }
  });

  test("every bridge-routed tool is covered by exactly one capability", () => {
    const covered = new Map<string, string>();
    for (const c of capabilities) {
      for (const tool of c.tools) {
        expect(covered.has(tool) ? `${tool} in ${covered.get(tool)} and ${c.id}` : "").toBe("");
        covered.set(tool, c.id);
      }
    }
    const expected = tools
      .map((t) => t.name)
      .filter((name) => !SERVER_SCOPE_TOOLS.has(name))
      .sort();
    expect([...covered.keys()].sort()).toEqual(expected);
  });

  test("each capability's permissions are the union of its tools' permissions", () => {
    const permissionOf = new Map(tools.map((t) => [t.name, t.permission]));
    for (const c of capabilities) {
      const fromTools = [...new Set(c.tools.map((tool) => permissionOf.get(tool)))].sort();
      // Every listed tool must exist in tools.json (a dangling name would
      // surface here as an undefined permission).
      expect(fromTools).not.toContain(undefined);
      expect([...c.permissions].sort()).toEqual(fromTools as string[]);
    }
  });
});
