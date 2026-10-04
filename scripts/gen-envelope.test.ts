// The fail-closed generation rules (G1-G5) of scripts/gen-envelope.ts,
// exercised against schemas that would otherwise turn into WEAKER Zod
// validators than the Rust contract: objects without an explicit type,
// unconstrained arrays, keywords the generator does not model, undiscriminated
// oneOf, unresolved $refs. Every one of these must abort generation, never
// emit. The happy paths mirror the real schemars output shapes, and the
// emitted source spellings are pinned so the generated file stays stable.

import { describe, expect, test } from "bun:test";
import { convert, prepare, splitFlattenedCommand } from "./gen-envelope";

const strictObject = (properties: Record<string, unknown>, required: string[]) => ({
  type: "object",
  additionalProperties: false,
  properties,
  required,
});

describe("prepare accepts the shapes schemars actually emits", () => {
  test("a strict object with primitive fields", () => {
    const schema = strictObject(
      { id: { type: "integer", format: "uint64", minimum: 0 }, op: { type: "string" } },
      ["id", "op"],
    );
    expect(prepare(schema, "$")).toEqual(schema);
  });

  test("annotations and defaults are stripped; a FIELD named like one is not", () => {
    const schema = {
      type: "object",
      additionalProperties: false,
      description: "doc comment",
      properties: {
        added: { type: "integer", minimum: 0, default: 0, description: "epoch" },
        // A wire field that HAPPENS to be called `default` must survive.
        default: { type: "string" },
      },
      required: ["default"],
    };
    expect(prepare(schema, "$")).toEqual(
      strictObject({ added: { type: "integer", minimum: 0 }, default: { type: "string" } }, [
        "default",
      ]),
    );
  });

  test("the any-schema stays free-form (true and {} canonicalize to {})", () => {
    expect(prepare(true, "$")).toEqual({});
    expect(prepare({ description: "free-form args" }, "$")).toEqual({});
  });

  test("a discriminated oneOf is rewritten to anyOf", () => {
    const branch = (tag: string) =>
      strictObject({ kind: { type: "string", const: tag }, value: { type: "string" } }, [
        "kind",
        "value",
      ]);
    const out = prepare({ oneOf: [branch("hash"), branch("team_id")] }, "$") as {
      oneOf?: unknown;
      anyOf?: unknown;
    };
    expect(out.oneOf).toBeUndefined();
    expect(out.anyOf).toEqual([branch("hash"), branch("team_id")]);
  });
});

describe("prepare aborts on anything that would convert weaker (G1/G3/G4/G5)", () => {
  test("G1: object-shaped keywords without type: object (the object claim must be explicit)", () => {
    expect(() =>
      prepare({ properties: { secret: { type: "string" } }, required: ["secret"] }, "$"),
    ).toThrow("G1");
    expect(() => prepare({ additionalProperties: false }, "$")).toThrow("G1");
    expect(() => prepare({ type: ["object", "null"], additionalProperties: false }, "$")).toThrow(
      "G1",
    );
  });

  test("G1: an object without deny_unknown_fields", () => {
    expect(() => prepare({ type: "object", properties: {} }, "$")).toThrow("G1");
    expect(() =>
      prepare({ type: "object", additionalProperties: { type: "string" }, properties: {} }, "$"),
    ).toThrow("G1");
  });

  test("G5: arrays without a single object items schema (z.array(z.any()) is weaker)", () => {
    expect(() => prepare({ type: "array" }, "$")).toThrow("G5");
    expect(() => prepare({ type: "array", items: false }, "$")).toThrow("G5");
    expect(() => prepare({ type: "array", items: true }, "$")).toThrow("G5");
    expect(() => prepare({ type: "array", items: [{ type: "string" }] }, "$")).toThrow("G5");
    expect(() => prepare({ items: { type: "string" } }, "$")).toThrow("G5");
    // The null arm is the only companion type items admits (Option<Vec<_>>);
    // anything else beside "array" would leave items unenforced on it.
    expect(() => prepare({ type: ["array", "string"], items: { type: "string" } }, "$")).toThrow(
      "G5",
    );
  });

  test("serde's Option<Vec<_>> null-arm beside an array is inert and allowed", () => {
    const optionVec = { type: ["array", "null"], items: { type: "string" } };
    expect(prepare(optionVec, "$")).toEqual(optionVec);
    expect(convert(prepare(optionVec, "$"), "t")).toBe("z.union([z.array(z.string()), z.null()])");
  });

  test("G5: keywords the generator does not model", () => {
    for (const extra of [
      { minProperties: 1 },
      { patternProperties: { "^x": { type: "string" } } },
      { contains: { type: "string" } },
      { not: { type: "string" } },
      { allOf: [{ type: "string" }] },
    ]) {
      expect(() => prepare({ type: "object", additionalProperties: false, ...extra }, "$")).toThrow(
        "G5",
      );
    }
  });

  test("G5: unknown types, non-string consts, boolean false schema", () => {
    expect(() => prepare({ type: "integer-ish" }, "$")).toThrow("G5");
    expect(() => prepare({ type: "string", const: 7 }, "$")).toThrow("G5");
    expect(() => prepare(false, "$")).toThrow("unsupported schema form");
  });

  test("G4: unresolved $ref", () => {
    expect(() => prepare({ $ref: "#/$defs/Anchor" }, "$")).toThrow("G4");
  });

  test("G3: an undiscriminated oneOf (z.union would erase its exclusivity claim)", () => {
    const branch = (tag: string) =>
      strictObject({ kind: { type: "string", const: tag } }, ["kind"]);
    expect(() => prepare({ oneOf: [branch("a"), branch("a")] }, "$")).toThrow("G3");
    expect(() =>
      prepare({ oneOf: [branch("a"), strictObject({ kind: { type: "string" } }, ["kind"])] }, "$"),
    ).toThrow("G3");
    expect(() => prepare({ oneOf: [{ type: "string" }, { type: "integer" }] }, "$")).toThrow("G3");
  });

  test("G5: degenerate unions (no single faithful Zod form)", () => {
    // An empty union claims nothing.
    expect(() => prepare({ anyOf: [] }, "$")).toThrow("G5");
    expect(() => prepare({ oneOf: [] }, "$")).toThrow("G5");
    // Sibling constraints beside a combinator would have to be dropped.
    expect(() =>
      prepare({ type: "number", minimum: 5, anyOf: [{ type: "number", maximum: 10 }] }, "$"),
    ).toThrow("G5");
    // Two combinators on one node: one of them wins, the other is lost.
    expect(() =>
      prepare({ anyOf: [{ type: "string" }], oneOf: [{ type: "integer" }] }, "$"),
    ).toThrow("G5");
  });

  test("G5: keywords in positions the emitter does not model", () => {
    // format and bounds constrain only numeric nodes; const only strings.
    expect(() => prepare({ type: "string", format: "uuid" }, "$")).toThrow("G5");
    // A string arm beside a numeric one would still give format a
    // string-format meaning the emitter does not model.
    expect(() => prepare({ type: ["string", "number"], format: "uuid" }, "$")).toThrow("G5");
    expect(() => prepare({ type: "string", minimum: 1 }, "$")).toThrow("G5");
    expect(() => prepare({ type: "integer", minimum: "0" }, "$")).toThrow("G5");
    expect(() => prepare({ type: "boolean", maximum: 1 }, "$")).toThrow("G5");
    expect(() => prepare({ type: "integer", const: "7" }, "$")).toThrow("G5");
    expect(() => prepare({ type: ["string", "null"], const: "x" }, "$")).toThrow("G5");
    expect(() => prepare({ type: [] }, "$")).toThrow("G5");
    // The Option null-arm beside a numeric type is inert and stays allowed.
    expect(prepare({ type: ["integer", "null"], format: "int64" }, "$")).toEqual({
      type: ["integer", "null"],
      format: "int64",
    });
  });

  test("required naming a field that does not exist", () => {
    expect(() => prepare(strictObject({ a: { type: "string" } }, ["a", "ghost"]), "$")).toThrow(
      "non-property",
    );
  });
});

describe("convert re-asserts strictness on the emitted source", () => {
  test("every z.object( carries .strict(), including nested ones", () => {
    const nested = strictObject({ inner: strictObject({ a: { type: "string" } }, ["a"]) }, [
      "inner",
    ]);
    const code = convert(prepare(nested, "$"), "nested");
    expect(code).toContain(".strict()");
    expect(code.split("z.object(").length).toBe(code.split(".strict()").length);
  });

  test("the emitted validator rejects unknown and missing fields at runtime", async () => {
    const code = convert(prepare(strictObject({ a: { type: "string" } }, ["a"]), "$"), "t");
    const { z } = await import("zod");
    // Test-only evaluation of our own just-generated source.
    const schema = new Function("z", `return ${code};`)(z);
    expect(schema.safeParse({ a: "x" }).success).toBe(true);
    expect(schema.safeParse({ a: "x", b: 1 }).success).toBe(false);
    expect(schema.safeParse({}).success).toBe(false);
    expect(schema.safeParse({ a: 7 }).success).toBe(false);
  });
});

describe("the emitted source spellings are pinned (keeps the generated file stable)", () => {
  test("objects: quoted keys, .optional() on non-required fields, .strict()", () => {
    const schema = strictObject(
      {
        id: { type: "integer", format: "uint64", minimum: 0 },
        error: { type: ["string", "null"] },
        kind: { type: "string", const: "hash" },
        ok: { type: "boolean" },
      },
      ["id", "kind"],
    );
    expect(convert(prepare(schema, "$"), "t")).toBe(
      'z.object({ "id": z.number().int().gte(0), "error": z.union([z.string(), z.null()]).optional(), ' +
        '"kind": z.literal("hash"), "ok": z.boolean().optional() }).strict()',
    );
  });

  test("arrays, unions, bounds, the empty object and the any-schema", () => {
    expect(convert(prepare({ type: "array", items: strictObject({}, []) }, "$"), "t")).toBe(
      "z.array(z.object({}).strict())",
    );
    // A one-branch union is the branch itself.
    expect(convert(prepare({ anyOf: [{ type: "string" }] }, "$"), "t")).toBe("z.string()");
    expect(convert(prepare({ anyOf: [{ type: "string" }, { type: "null" }] }, "$"), "t")).toBe(
      "z.union([z.string(), z.null()])",
    );
    expect(convert(prepare({ type: "number", format: "int64", maximum: 10 }, "$"), "t")).toBe(
      "z.number().int().lte(10)",
    );
    expect(convert(prepare({}, "$"), "t")).toBe("z.any()");
  });

  test("the override substitutes a named schema for the matched node", () => {
    const prepared = prepare(
      strictObject({ entry: strictObject({ b: { type: "string" } }, ["b"]) }, ["entry"]),
      "$",
    ) as { properties: Record<string, unknown> };
    const entry = prepared.properties.entry;
    expect(convert(prepared, "t", (node) => (node === entry ? "NamedSchema" : undefined))).toBe(
      'z.object({ "entry": NamedSchema }).strict()',
    );
  });
});

// G6: the request's flattened command. The fixture is the exact shape schemars emits for
// `#[serde(flatten)] command: BridgeCommand` (parent properties, a oneOf of adjacently tagged
// branches, unevaluatedProperties: false); serde's other enum shapes must not be read as one.
describe("splitFlattenedCommand (G6)", () => {
  const branch = (op: string, args: Record<string, unknown>) => ({
    description: "variant doc",
    type: "object",
    properties: { args, op: { type: "string", const: op } },
    required: ["op", "args"],
  });
  const tabFocusArgs = {
    type: "object",
    additionalProperties: false,
    properties: { tabId: { type: "integer", format: "int64" } },
    required: ["tabId"],
  };
  const noArgs = { type: "object", additionalProperties: false };
  const request = {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    title: "BridgeReq",
    type: "object",
    properties: {
      browser: { type: ["string", "null"] },
      id: { type: "integer", format: "uint64", minimum: 0 },
    },
    oneOf: [branch("tab_list", noArgs), branch("tab_focus", tabFocusArgs)],
    required: ["id"],
    unevaluatedProperties: false,
  };

  test("gives back the pre-typed envelope and one args schema per op", () => {
    const { envelope, commands } = splitFlattenedCommand(request, "$");
    expect(envelope).toEqual({
      $schema: "https://json-schema.org/draft/2020-12/schema",
      title: "BridgeReq",
      type: "object",
      properties: {
        args: {},
        browser: { type: ["string", "null"] },
        id: { type: "integer", format: "uint64", minimum: 0 },
        op: { type: "string" },
      },
      required: ["id", "args", "op"],
      additionalProperties: false,
    });
    expect([...commands.keys()]).toEqual(["tab_list", "tab_focus"]);
    expect(commands.get("tab_focus")).toEqual(tabFocusArgs);
    // The envelope then converts exactly as the untyped request always did.
    expect(convert(prepare(envelope, "$"), "BridgeReqWireSchema")).toBe(
      'z.object({ "args": z.any(), "browser": z.union([z.string(), z.null()]).optional(), ' +
        '"id": z.number().int().gte(0), "op": z.string() }).strict()',
    );
  });

  test("refuses a request that is not a flattened tagged union", () => {
    // The strictness carrier is unevaluatedProperties: without it an unknown envelope field would pass.
    const { unevaluatedProperties: _dropped, ...loose } = request;
    expect(() => splitFlattenedCommand(loose, "$")).toThrow("G6");
    // A plain strict object (the pre-typed request) is not a command carrier either.
    expect(() =>
      splitFlattenedCommand({ ...loose, additionalProperties: false, oneOf: undefined }, "$"),
    ).toThrow("G6");
    // The envelope declaring op or args itself would shadow the command's.
    expect(() =>
      splitFlattenedCommand(
        { ...request, properties: { ...request.properties, op: { type: "string" } } },
        "$",
      ),
    ).toThrow("declares op");
  });

  test("refuses branches outside serde's adjacently tagged shape", () => {
    const withBranch = (b: unknown) => ({ ...request, oneOf: [request.oneOf[0], b] });
    // A third member: an internally tagged variant would carry its fields here.
    expect(() =>
      splitFlattenedCommand(
        withBranch({
          type: "object",
          properties: { op: { type: "string", const: "x" }, args: noArgs, extra: {} },
          required: ["op", "args"],
        }),
        "$",
      ),
    ).toThrow("exactly {op, args}");
    // args optional: a frame without args would be accepted.
    expect(() =>
      splitFlattenedCommand(withBranch({ ...branch("x", noArgs), required: ["op"] }), "$"),
    ).toThrow("exactly {op, args}");
    // No op const: an untagged branch cannot be keyed.
    expect(() =>
      splitFlattenedCommand(
        withBranch({
          type: "object",
          properties: { op: { type: "string" }, args: noArgs },
          required: ["op", "args"],
        }),
        "$",
      ),
    ).toThrow("no string op const");
    // A branch-level constraint beside the members would be dropped silently.
    expect(() =>
      splitFlattenedCommand(
        withBranch({ ...branch("x", noArgs), additionalProperties: false }),
        "$",
      ),
    ).toThrow("beside the command members");
    expect(() => splitFlattenedCommand(withBranch(branch("tab_list", noArgs)), "$")).toThrow(
      "repeats op",
    );
  });
});
