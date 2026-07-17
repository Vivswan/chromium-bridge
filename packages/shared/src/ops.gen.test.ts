// Parity between the generated catalogue (ops.gen.ts) and its source
// (contracts/tools.json), plus the per-op validator equivalence: each tool's
// OP_ARG_SCHEMAS entry must carry exactly the contract's properties and
// required set. tools/catalogue.rs is checked against the same contract in
// `cargo test`, so all sides stay aligned or CI fails.

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { z } from "zod";
import type { BridgeCommand, OpName, ToolMeta } from "./ops.gen";
import { OP_ARG_SCHEMAS, OP_NAMES, OpArgsSchema, TOOL_META, TOOLS } from "./ops.gen";

interface ContractTool {
  name: string;
  uiLabel: string;
  risk: string;
  scope: string;
  permission: string;
  confirmation: string;
  inputSchema: {
    properties?: Record<string, { type: string }>;
    required?: string[];
  };
}

const contract = JSON.parse(
  readFileSync(resolve(import.meta.dir, "../../../contracts/tools.json"), "utf8"),
) as { tools: ContractTool[] };

// `browser` is the server-side routing argument: the MCP server resolves it
// against its connection registry and never forwards it inside args, so the
// generator excludes it from the extension-facing shapes.
const ROUTING_ARGS = new Set(["browser"]);

describe("ops catalogue", () => {
  test("op names are unique", () => {
    expect(new Set(OP_NAMES).size).toBe(OP_NAMES.length);
  });

  test("every tool has an op and a description", () => {
    for (const t of TOOLS) {
      expect(t.op.length).toBeGreaterThan(0);
      expect(t.desc.length).toBeGreaterThan(0);
    }
  });

  test("matches contracts/tools.json (the source)", () => {
    const names = contract.tools.map((t) => t.name);
    const labels = Object.fromEntries(contract.tools.map((t) => [t.name, t.uiLabel]));
    expect([...OP_NAMES] as string[]).toEqual(names);
    for (const t of TOOLS) expect(t.desc).toBe(labels[t.op] as string);
  });

  test("TOOL_META matches contracts/tools.json (the source)", () => {
    // Same set of ops, no extras on either side.
    expect(Object.keys(TOOL_META).sort()).toEqual(contract.tools.map((t) => t.name).sort());

    for (const t of contract.tools) {
      expect(TOOL_META[t.name as OpName]).toEqual({
        risk: t.risk,
        scope: t.scope,
        permission: t.permission,
        confirmation: t.confirmation,
      } as ToolMeta);
    }
  });

  // The generated per-op validators are the runtime form of each tool's
  // inputSchema. Compare via z.toJSONSchema(): the contract's property set
  // (minus the routing arg), the required set, and the primitive types. That
  // is the WHOLE vocabulary the contract uses today; the generator refuses
  // any other inputSchema keyword (enum, bounds, pattern, ...) outright, so a
  // richer contract fails generation instead of quietly producing a weaker
  // validator than this test can see. The validators are also deliberately
  // STRICTER than the MCP inputSchema in one way - unknown keys are rejected
  // (fail closed at the extension boundary) - so additionalProperties is
  // asserted false rather than compared.
  test("OP_ARG_SCHEMAS carry each tool's inputSchema props/required/types (minus `browser`)", () => {
    for (const t of contract.tools) {
      const schema = OP_ARG_SCHEMAS[t.name as OpName];
      expect(schema).toBeDefined();
      const emitted = z.toJSONSchema(schema) as {
        properties?: Record<string, { type?: string }>;
        required?: string[];
        additionalProperties?: unknown;
      };

      const expectedProps = Object.entries(t.inputSchema.properties ?? {}).filter(
        ([k]) => !ROUTING_ARGS.has(k),
      );
      expect(Object.keys(emitted.properties ?? {}).sort()).toEqual(
        expectedProps.map(([k]) => k).sort(),
      );
      for (const [key, prop] of expectedProps) {
        const emittedType = emitted.properties?.[key]?.type;
        expect(`${t.name}.${key}:${emittedType}`).toBe(`${t.name}.${key}:${prop.type}`);
      }
      const required = (t.inputSchema.required ?? []).filter((k) => !ROUTING_ARGS.has(k));
      expect([...(emitted.required ?? [])].sort()).toEqual([...required].sort());
      expect(emitted.additionalProperties).toBe(false);
    }
  });

  // The envelope-level OpArgs union must be exactly the union of every
  // tool's props (minus the routing arg) - the same set the contract's
  // $defs/OpArgs declares (that side is enforced by the equivalence test).
  test("OpArgsSchema is the union of every tool's inputSchema props", () => {
    const expected = new Set<string>();
    for (const t of contract.tools) {
      for (const key of Object.keys(t.inputSchema.properties ?? {})) {
        if (!ROUTING_ARGS.has(key)) expected.add(key);
      }
    }
    expect(Object.keys(OpArgsSchema.shape).sort()).toEqual([...expected].sort());
  });

  // Compile-time coverage: these assignments only type-check if BridgeCommand
  // (inferred from the validators) narrows on `op` and enforces each tool's
  // args. `tsc --noEmit` is the gate; the runtime body is a smoke assertion.
  test("BridgeCommand narrows args per op (compile-time)", () => {
    const list: BridgeCommand = { op: "tab_list", args: {} };
    const focus: BridgeCommand = { op: "tab_focus", args: { tabId: 3 } };
    const fill: BridgeCommand = { op: "page_fill", args: { value: "hi", ref: "e1" } };
    const evalCmd: BridgeCommand = { op: "page_eval", args: { code: "1+1" } };

    // @ts-expect-error tab_focus requires args.tabId
    const missing: BridgeCommand = { op: "tab_focus", args: {} };
    // @ts-expect-error tab_focus.args has no `code` field
    const wrongField: BridgeCommand = { op: "tab_focus", args: { tabId: 1, code: "x" } };
    // @ts-expect-error tab_focus.args.tabId is a number, not a string
    const wrongType: BridgeCommand = { op: "tab_focus", args: { tabId: "3" } };

    void missing;
    void wrongField;
    void wrongType;
    expect([list.op, focus.op, fill.op, evalCmd.op]).toEqual([
      "tab_list",
      "tab_focus",
      "page_fill",
      "page_eval",
    ]);
  });

  // Runtime teeth for the same contract: the validators reject what the types
  // reject.
  test("OP_ARG_SCHEMAS reject missing/mistyped/unknown args at runtime", () => {
    expect(OP_ARG_SCHEMAS.tab_focus.safeParse({ tabId: 3 }).success).toBe(true);
    expect(OP_ARG_SCHEMAS.tab_focus.safeParse({}).success).toBe(false);
    expect(OP_ARG_SCHEMAS.tab_focus.safeParse({ tabId: "3" }).success).toBe(false);
    expect(OP_ARG_SCHEMAS.tab_focus.safeParse({ tabId: 3, code: "x" }).success).toBe(false);
    expect(OP_ARG_SCHEMAS.tab_focus.safeParse({ tabId: 3.5 }).success).toBe(false);
    expect(OP_ARG_SCHEMAS.page_eval.safeParse({ code: "1+1" }).success).toBe(true);
    expect(OP_ARG_SCHEMAS.page_eval.safeParse({}).success).toBe(false);
    expect(OP_ARG_SCHEMAS.tab_list.safeParse({}).success).toBe(true);
    expect(OP_ARG_SCHEMAS.tab_list.safeParse({ anything: 1 }).success).toBe(false);
  });
});
