// Internal consistency of the generated catalogue (ops.gen.ts): the per-op
// validators, the envelope-level OpArgs union, and the inferred BridgeCommand
// types must all agree with each other. The catalogue's SOURCE is the Rust
// core (src/packages/core/src/tools/catalogue.rs); faithful generation is enforced
// by CI regenerating and diffing the checked-in files (`just gen`
// idempotency), so these tests own the semantics, not the provenance.

import { describe, expect, test } from "bun:test";
import { z } from "zod";
import type { BridgeCommand } from "../src/ops.gen";
import { isOpName, OP_ARG_SCHEMAS, OP_NAMES, OpArgsSchema, TOOL_META } from "../src/ops.gen";

describe("ops catalogue", () => {
  test("op names are unique and recognized by isOpName", () => {
    expect(new Set(OP_NAMES).size).toBe(OP_NAMES.length);
    for (const op of OP_NAMES) expect(isOpName(op)).toBe(true);
    expect(isOpName("not_a_tool")).toBe(false);
  });

  test("every op has policy metadata and an arg validator", () => {
    expect(Object.keys(TOOL_META).sort()).toEqual([...OP_NAMES].sort());
    expect(Object.keys(OP_ARG_SCHEMAS).sort()).toEqual([...OP_NAMES].sort());
  });

  // The envelope-level OpArgs bag must be exactly the union of every per-op
  // validator's properties, each with a matching type and none required
  // (per-op required-ness is the per-op validators' job). This pins the
  // generator's two derivations of the same source against each other.
  test("OpArgsSchema is the union of the per-op validators' props", () => {
    const unionProps = z.toJSONSchema(OpArgsSchema) as {
      properties?: Record<string, { type?: string }>;
      required?: string[];
      additionalProperties?: unknown;
    };
    expect(unionProps.required ?? []).toEqual([]);
    expect(unionProps.additionalProperties).toBe(false);

    const expected = new Map<string, string | undefined>();
    for (const op of OP_NAMES) {
      const emitted = z.toJSONSchema(OP_ARG_SCHEMAS[op]) as {
        properties?: Record<string, { type?: string }>;
        additionalProperties?: unknown;
      };
      // Every per-op validator is strict: unknown keys are rejected (fail
      // closed at the extension boundary).
      expect(emitted.additionalProperties).toBe(false);
      for (const [key, prop] of Object.entries(emitted.properties ?? {})) {
        const prior = expected.get(key);
        if (prior !== undefined) expect(`${key}:${prop.type}`).toBe(`${key}:${prior}`);
        expected.set(key, prop.type);
      }
    }
    expect(Object.keys(unionProps.properties ?? {}).sort()).toEqual([...expected.keys()].sort());
    for (const [key, type] of expected) {
      expect(`${key}:${unionProps.properties?.[key]?.type}`).toBe(`${key}:${type}`);
    }
  });

  // The server-side `browser` routing argument is consumed by the MCP server
  // and never forwarded inside args; the generator must keep it out of every
  // extension-facing shape.
  test("no validator carries the server-consumed `browser` routing arg", () => {
    expect(
      Object.keys((z.toJSONSchema(OpArgsSchema) as { properties?: object }).properties ?? {}),
    ).not.toContain("browser");
    for (const op of OP_NAMES) {
      const emitted = z.toJSONSchema(OP_ARG_SCHEMAS[op]) as { properties?: object };
      expect(Object.keys(emitted.properties ?? {})).not.toContain("browser");
    }
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
