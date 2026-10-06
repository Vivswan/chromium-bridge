// Internal consistency of the generated catalogue (ops.gen.ts): the per-op
// validators, the envelope-level OpArgs union, and the inferred BridgeCommand
// types must all agree with each other. The catalogue's SOURCE is the Rust
// core (src/packages/core/src/tools/catalogue.rs); faithful generation is enforced
// by CI regenerating and diffing the checked-in files (`moon run gen`
// idempotency), so these tests own the semantics, not the provenance.

import { describe, expect, test } from "bun:test";
import { z } from "zod";
import type { BridgeCommand, OpName } from "../src/ops.gen";
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
});

// One representative args object per op, the per-op validator run against it and its hostile variants: a missing
// required arg, an unknown arg, and type confusion on every arg (a string where an integer belongs, a fraction
// where an integer belongs, ...). The census at the end holds the table to OP_NAMES, so a tool the catalogue adds
// is under this proof or fails here.
const ARGS_CASES: ReadonlyArray<{
  op: string;
  valid: Record<string, unknown>;
  required: readonly string[];
}> = [
  { op: "list_browsers", valid: {}, required: [] },
  { op: "tab_list", valid: {}, required: [] },
  { op: "tab_focus", valid: { tabId: 3 }, required: ["tabId"] },
  { op: "tab_open", valid: { url: "https://example.test/" }, required: ["url"] },
  { op: "tab_close", valid: { tabId: 3 }, required: ["tabId"] },
  { op: "page_snapshot", valid: {}, required: [] },
  { op: "page_click", valid: { ref: "e1", selector: "#go" }, required: [] },
  { op: "page_fill", valid: { ref: "e1", selector: "#name", value: "hi" }, required: ["value"] },
  { op: "page_text", valid: {}, required: [] },
  { op: "page_screenshot", valid: {}, required: [] },
  { op: "page_scroll", valid: { direction: "down", pixels: 400 }, required: [] },
  {
    op: "page_wait_for",
    valid: { nav: true, selector: "#done", text: "Done", timeoutMs: 5000 },
    required: [],
  },
  { op: "page_eval", valid: { code: "1+1" }, required: ["code"] },
  { op: "page_snapshot_precise", valid: { frameId: "f1" }, required: [] },
  {
    op: "cookie_get",
    valid: { domain: "example.test", name: "sid", url: "https://example.test/" },
    required: [],
  },
  { op: "storage_get", valid: { key: "k", type: "local" }, required: [] },
  { op: "page_navigate", valid: { url: "https://example.test/" }, required: ["url"] },
  { op: "page_back", valid: {}, required: [] },
  { op: "page_forward", valid: {}, required: [] },
  { op: "page_reload", valid: {}, required: [] },
  { op: "page_press", valid: { keys: "Enter" }, required: ["keys"] },
  { op: "page_hover", valid: { ref: "e1", selector: "#go" }, required: [] },
  { op: "page_select", valid: { ref: "e1", selector: "#pick", value: "b" }, required: ["value"] },
  { op: "console_get", valid: { limit: 50 }, required: [] },
  { op: "page_handle_dialog", valid: { action: "accept", promptText: "ok" }, required: ["action"] },
  {
    op: "page_upload",
    valid: { path: "/tmp/f.txt", selector: "input[type=file]" },
    required: ["path", "selector"],
  },
];

/** Every arg some other op accepts and this one does not, with a value its own op admits. */
function foreignArgs(own: Record<string, unknown>): [string, unknown][] {
  const foreign = new Map<string, unknown>();
  for (const { valid } of ARGS_CASES) {
    for (const [key, value] of Object.entries(valid)) {
      if (!(key in own)) foreign.set(key, value);
    }
  }
  return [...foreign];
}

function confusions(value: unknown): unknown[] {
  switch (typeof value) {
    case "string":
      return [7, true, { hostile: true }, null];
    case "number":
      return ["7", true, { hostile: true }, 1.5, null];
    case "boolean":
      return ["true", 0, { hostile: true }, null];
    default:
      return [42, "hostile", true, null];
  }
}

describe("every per-op validator fails closed on its own args", () => {
  for (const { op, valid, required } of ARGS_CASES) {
    const schema = OP_ARG_SCHEMAS[op as OpName];
    describe(op, () => {
      test("accepts the representative args and the required-only subset", () => {
        expect(schema.safeParse(valid).success).toBe(true);
        const requiredOnly = Object.fromEntries(
          Object.entries(valid).filter(([key]) => required.includes(key)),
        );
        expect(schema.safeParse(requiredOnly).success).toBe(true);
      });
      test("rejects an unknown arg, another op's arg, and non-objects", () => {
        expect(schema.safeParse({ ...valid, hostile: 1 }).success).toBe(false);
        // The table's valid args carry every arg the op accepts, so every other op's arg is foreign here.
        for (const [key, value] of foreignArgs(valid)) {
          expect(schema.safeParse({ ...valid, [key]: value }).success).toBe(false);
        }
        for (const bad of [null, undefined, 7, "args", [valid], true]) {
          expect(schema.safeParse(bad).success).toBe(false);
        }
      });
      for (const key of required) {
        test(`rejects the args without required ${key}`, () => {
          const { [key]: _dropped, ...rest } = valid;
          expect(schema.safeParse(rest).success).toBe(false);
        });
      }
      for (const [key, value] of Object.entries(valid)) {
        test(`rejects a type-confused ${key}`, () => {
          for (const hostile of confusions(value)) {
            expect(schema.safeParse({ ...valid, [key]: hostile }).success).toBe(false);
          }
        });
        if (typeof value === "number") {
          // The Rust side reads a JS-safe signed integer: both ends of that range are admitted, nothing past.
          test(`${key} spans exactly the JS-safe signed integers`, () => {
            for (const n of [-1, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]) {
              expect(schema.safeParse({ ...valid, [key]: n }).success).toBe(true);
            }
            for (const n of [2 ** 53, -(2 ** 53)]) {
              expect(schema.safeParse({ ...valid, [key]: n }).success).toBe(false);
            }
          });
        }
      }
    });
  }

  test("the table covers exactly the catalogue", () => {
    expect(ARGS_CASES.map((c) => c.op).sort()).toEqual([...OP_NAMES].sort());
  });
});
