// The rules scripts/gen-schema.ts holds every emitted validator to (R1-R4), each shown firing on the schema
// it exists to refuse; the external facts the emission leans on (which keywords zod's fromJSONSchema reads,
// what json-schema-to-typescript makes of the node shapes the generators produce, how change-case names a
// type after an op); and the equality A2 holds an inlined schema and its owner module to. The library's
// reading is the artifact under test, so every case goes
// through the real library, never a hand-built reading, except R3, which guards the library itself.

import { describe, expect, test } from "bun:test";
import { pascalCase } from "change-case";
import { z } from "zod";
import { OP_NAMES } from "../../src/packages/shared/src/ops.gen";
import {
  assertReadingRules,
  assertSchemaRules,
  libraryReading,
  opArgsSchema,
  readsEqual,
  typeSource,
} from "../gen-schema";

const strict = (properties: Record<string, unknown>, required: string[] = []) => ({
  type: "object",
  additionalProperties: false,
  properties,
  required,
});

describe("the reading rules refuse what they exist to refuse", () => {
  test("R1: an object the library reads as open fails unless the schema is a loose reader", () => {
    const open = { type: "object", properties: { a: { type: "string" } } };
    expect(() => assertSchemaRules("X", open, false)).toThrow(
      /\$ is an object read as \{\}, not strict \(R1\)/,
    );
    expect(() => assertSchemaRules("X", open, true)).not.toThrow();
    // Nested: the loose allowance covers every object of a loose reader, a strict one covers none.
    const nestedOpen = strict({ inner: { type: "object", properties: {} } }, ["inner"]);
    expect(() => assertSchemaRules("X", nestedOpen, false)).toThrow(
      /\$\.properties\.inner .*\(R1\)/,
    );
    // A oneOf's branches are walked too (prepare rewrites a discriminated oneOf to anyOf, but the walk owes
    // nothing to that).
    const oneOfOpen = {
      oneOf: [
        {
          type: "object",
          properties: { kind: { type: "string", const: "a" } },
          required: ["kind"],
        },
        {
          type: "object",
          properties: { kind: { type: "string", const: "b" } },
          required: ["kind"],
        },
      ],
    };
    expect(() => assertSchemaRules("X", oneOfOpen, false)).toThrow(/oneOf\[0\] .*\(R1\)/);
    // An additionalProperties SCHEMA is neither strict nor the loose form.
    const typedExtras = {
      type: "object",
      properties: {},
      additionalProperties: { type: "string" },
    };
    expect(() => assertSchemaRules("X", typedExtras, true)).toThrow(/\(R1\)/);
  });

  test("R2: a default anywhere fails", () => {
    expect(() =>
      assertSchemaRules("X", strict({ a: { type: "integer", default: 0 } }), false),
    ).toThrow(/\$\.properties\.a carries a default \(R2\)/);
  });

  test("R3: an integer the library reads without JS-safe bounds fails (a hand-built reading; the library adds the bounds itself)", () => {
    expect(() => assertReadingRules("X", { type: "integer" }, false)).toThrow(/\(R3\)/);
    expect(() =>
      assertReadingRules("X", { type: "integer", minimum: 0, maximum: 2 ** 53 }, false),
    ).toThrow(/\(R3\)/);
    expect(() =>
      assertReadingRules("X", libraryReading({ type: "integer", minimum: 0 }), false),
    ).not.toThrow();
  });

  test("R4: a union of objects without a shared required const fails; a discriminated one and a nullable object pass", () => {
    const plain = {
      anyOf: [strict({ a: { type: "string" } }, ["a"]), strict({ b: { type: "string" } }, ["b"])],
    };
    expect(() => assertSchemaRules("X", plain, false)).toThrow(
      /no discriminating required const \(R4\)/,
    );
    const optionalTag = {
      anyOf: [
        strict({ kind: { type: "string", const: "a" }, value: { type: "string" } }, ["value"]),
        strict({ kind: { type: "string", const: "b" }, value: { type: "string" } }, ["value"]),
      ],
    };
    expect(() => assertSchemaRules("X", optionalTag, false)).toThrow(/\(R4\)/);
    const discriminated = {
      anyOf: [
        strict({ ok: { type: "boolean", const: true }, value: { type: "string" } }, [
          "ok",
          "value",
        ]),
        strict({ ok: { type: "boolean", const: false }, error: { type: "string" } }, [
          "ok",
          "error",
        ]),
      ],
    };
    expect(() => assertSchemaRules("X", discriminated, false)).not.toThrow();
    expect(() =>
      assertSchemaRules("X", { anyOf: [strict({}), { type: "null" }] }, false),
    ).not.toThrow();
    // A null arm beside two overlapping objects does not excuse them.
    expect(() =>
      assertSchemaRules("X", { anyOf: [...plain.anyOf, { type: "null" }] }, false),
    ).toThrow(/\(R4\)/);
    // Nor does nesting one of them inside an inner union, nor spelling the union as oneOf (which zod reads as
    // exclusive while the type reader emits a plain union; only discrimination makes the two agree).
    const [first, second] = plain.anyOf;
    expect(() =>
      assertSchemaRules("X", { anyOf: [{ anyOf: [first, { type: "null" }] }, second] }, false),
    ).toThrow(/\(R4\)/);
    expect(() => assertSchemaRules("X", { oneOf: plain.anyOf }, false)).toThrow(/\(R4\)/);
  });
});

// The keyword lists the generators admit: prepare's allowlist (scripts/gen-envelope.ts) and the asymmetry
// table's changes. Each must change the library's reading when present, or the Rust parser would enforce a
// constraint the extension silently dropped.
describe("every keyword the generators admit is read by the library", () => {
  const read = (schema: unknown) => JSON.stringify(libraryReading(schema));
  test.each<[string, unknown, unknown]>([
    ["required", strict({ a: { type: "string" } }, ["a"]), strict({ a: { type: "string" } })],
    ["additionalProperties: false", strict({}), { type: "object", properties: {} }],
    ["items", { type: "array", items: { type: "string" } }, { type: "array" }],
    ["const", { type: "string", const: "x" }, { type: "string" }],
    ["enum", { type: "string", enum: ["a", "b"] }, { type: "string" }],
    ["minimum", { type: "integer", minimum: 0 }, { type: "integer" }],
    ["maximum", { type: "integer", maximum: 10 }, { type: "integer" }],
    ["minLength", { type: "string", minLength: 1 }, { type: "string" }],
    ["maxLength", { type: "string", maxLength: 32 }, { type: "string" }],
    ["pattern", { type: "string", pattern: "^[a-z]+$" }, { type: "string" }],
    [
      "maxItems",
      { type: "array", items: { type: "string" }, maxItems: 3 },
      { type: "array", items: { type: "string" } },
    ],
    ["a null type arm", { type: ["string", "null"] }, { type: "string" }],
    ["a false property schema", strict({ e: false }), strict({})],
  ])("%s", (_keyword, withKeyword, without) => {
    expect(read(withKeyword)).not.toBe(read(without));
  });

  test("and a keyword the library ignores reads the same with or without it (why prepare's allowlist exists)", () => {
    expect(read({ type: "array", items: { type: "string" }, uniqueItems: true })).toBe(
      read({ type: "array", items: { type: "string" } }),
    );
    expect(read({ type: "integer", format: "uint64", minimum: 0 })).toBe(
      read({ type: "integer", minimum: 0 }),
    );
  });
});

// The keyword census above compares standalone null arms; this is the required-property case. A converter that
// made every required string nullable passes every census case and R1-R4 and fails only here.
test("a property without a null arm refuses null; the null arm admits it", () => {
  const reader = z.fromJSONSchema(
    strict({ a: { type: "string" }, b: { type: ["string", "null"] } }, ["a", "b"]) as never,
  );
  expect(reader.safeParse({ a: "x", b: null }).success).toBe(true);
  expect(reader.safeParse({ a: null, b: null }).success).toBe(false);
  expect(reader.safeParse({ b: null }).success).toBe(false);
});

// The per-op arg types are named by change-case; a library that split snake_case differently (a kept
// underscore, a lowercased second word) would rename 26 exported types.
test("every op's args type is its snake_case name in PascalCase plus Args", () => {
  const expected: Record<string, string> = {
    list_browsers: "ListBrowsersArgs",
    tab_list: "TabListArgs",
    tab_focus: "TabFocusArgs",
    tab_open: "TabOpenArgs",
    tab_close: "TabCloseArgs",
    page_snapshot: "PageSnapshotArgs",
    page_click: "PageClickArgs",
    page_fill: "PageFillArgs",
    page_text: "PageTextArgs",
    page_screenshot: "PageScreenshotArgs",
    page_scroll: "PageScrollArgs",
    page_wait_for: "PageWaitForArgs",
    page_eval: "PageEvalArgs",
    page_snapshot_precise: "PageSnapshotPreciseArgs",
    cookie_get: "CookieGetArgs",
    storage_get: "StorageGetArgs",
    page_navigate: "PageNavigateArgs",
    page_back: "PageBackArgs",
    page_forward: "PageForwardArgs",
    page_reload: "PageReloadArgs",
    page_press: "PagePressArgs",
    page_hover: "PageHoverArgs",
    page_select: "PageSelectArgs",
    console_get: "ConsoleGetArgs",
    page_handle_dialog: "PageHandleDialogArgs",
    page_upload: "PageUploadArgs",
  };
  expect(Object.fromEntries(OP_NAMES.map((op) => [op, `${pascalCase(op)}Args`]))).toEqual(expected);
});

describe("the emitted source", () => {
  // The type reader's choices the exported types depend on: an empty strict object is Record<string, never>
  // (never `{}`), a false property is `never`, the any-schema is `unknown`, a loose object carries the index
  // signature, a const is a literal, a nullable type keeps its null, and a bounded array stays an array.
  test("the type reader's shapes", async () => {
    expect(await typeSource("Empty", strict({}))).toBe("export type Empty = Record<string, never>");
    const frame = {
      type: "object",
      additionalProperties: true,
      properties: {
        ok: { type: "boolean", const: true },
        error: false,
        data: {},
        label: { type: ["string", "null"] },
        tags: { type: "array", items: { type: "string", minLength: 1 }, maxItems: 4 },
        inner: strict({}),
      },
      required: ["ok", "tags"],
    };
    expect(await typeSource("Frame", frame)).toBe(
      [
        "export interface Frame {",
        "ok: true",
        "error?: never",
        "data?: unknown",
        "label?: (string | null)",
        "/**",
        " * @maxItems 4",
        " */",
        "tags: string[]",
        "inner?: Record<string, never>",
        "[k: string]: unknown",
        "}",
      ].join("\n"),
    );
  });
});

describe("the OpArgs bag", () => {
  test("a prop two ops declare with different schemas is refused: the bag would otherwise pick one silently", () => {
    const argsByOp = new Map<string, Record<string, unknown>>([
      ["a", strict({ x: { type: "string" } }, ["x"])],
      ["b", strict({ x: { type: "integer" } })],
    ]);
    expect(() => opArgsSchema(argsByOp)).toThrow(/conflicting schemas for arg "x"/);
  });
});

describe("readsEqual, the equality an inlined schema and its owner module are held to", () => {
  const node = strict({ a: { type: "string", minLength: 1 }, n: { type: "integer", minimum: 0 } }, [
    "a",
  ]);
  test("a module's exported schema reads equal to the node inlined elsewhere; a lost bound or a lost field does not", () => {
    expect(readsEqual(node, z.fromJSONSchema(node as never))).toBe(true);
    expect(
      readsEqual(node, z.strictObject({ a: z.string().min(1), n: z.int().min(0).optional() })),
    ).toBe(true);
    expect(readsEqual(node, z.strictObject({ a: z.string(), n: z.int().min(0).optional() }))).toBe(
      false,
    );
    expect(readsEqual(node, z.strictObject({ a: z.string().min(1) }))).toBe(false);
    expect(
      readsEqual(node, z.looseObject({ a: z.string().min(1), n: z.int().min(0).optional() })),
    ).toBe(false);
  });
});
