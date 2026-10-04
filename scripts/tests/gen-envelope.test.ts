// The fail-closed generation rules (G1-G7, A1-A2) of scripts/gen-envelope.ts,
// exercised against inputs that would otherwise turn into WEAKER Zod
// validators than the Rust contract: objects without an explicit type,
// unconstrained arrays, keywords the generator does not model, undiscriminated
// oneOf, unresolved $refs, an unplanned Rust frame, an asymmetry entry on a
// node it cannot apply to. Every one of these must abort generation, never
// emit. The happy paths mirror the real schemars output shapes, and the
// emitted source spellings are pinned so the generated file stays stable.

import { describe, expect, test } from "bun:test";
import { z } from "zod";
import {
  applyAsymmetries,
  assertFramePlan,
  assertGeneratedMatches,
  convert,
  prepare,
  splitFlattenedCommand,
  splitTaggedUnionSchema,
} from "../gen-envelope";

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

  test("arrays, unions, bounds, the empty object and the any-schema (unknown, so consumers narrow)", () => {
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
    expect(convert(prepare({}, "$"), "t")).toBe("z.unknown()");
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
      'z.object({ "args": z.unknown(), "browser": z.union([z.string(), z.null()]).optional(), ' +
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

describe("prepare models string enums (G5 placement)", () => {
  test("a string enum survives and emits z.enum; anything else is refused", () => {
    const kind = { type: "string", enum: ["hash", "team_id"] };
    expect(prepare(kind, "$")).toEqual(kind);
    expect(convert(prepare(kind, "$"), "t")).toBe('z.enum(["hash", "team_id"])');
    for (const bad of [
      { type: "string", enum: [] },
      { type: "string", enum: ["a", "a"] },
      { type: "string", enum: ["a", 1] },
      { type: "integer", enum: ["a"] },
      { type: "string", enum: ["a"], const: "a" },
    ]) {
      expect(() => prepare(bad, "$")).toThrow("G5");
    }
  });
});

// The asymmetry pass: the table's changes applied at their paths, the reader rules everywhere, and every way
// an entry can fail to apply (A1). The fixtures are the prepared shapes the Rust readers have today.
describe("applyAsymmetries", () => {
  const reader = strictObject(
    {
      id: { type: "integer", format: "uint64", minimum: 0 },
      error: { type: ["string", "null"] },
      label: { type: "string" },
      anchor: {
        anyOf: [
          strictObject({ kind: { type: "string", const: "hash" }, value: { type: "string" } }, [
            "kind",
            "value",
          ]),
          strictObject({ kind: { type: "string", const: "team_id" }, value: { type: "string" } }, [
            "kind",
            "value",
          ]),
        ],
      },
      overlay: {
        anyOf: [strictObject({ cdpMode: { type: ["boolean", "null"] } }, []), { type: "null" }],
      },
    },
    ["id", "anchor"],
  );
  const entry = (changes: unknown) =>
    ({ direction: "narrow", reason: "r", changes, probes: {} }) as Parameters<
      typeof applyAsymmetries
    >[2][string];

  test("the reader rules: null arms dropped everywhere, objects loose on a control frame only", () => {
    const loose = applyAsymmetries(reader, "t", {}, true).schema;
    expect(convert(loose, "t")).toBe(
      'z.object({ "id": z.number().int().gte(0), "error": z.string().optional(), "label": z.string().optional(), ' +
        '"anchor": z.union([z.object({ "kind": z.literal("hash"), "value": z.string() }).catchall(z.unknown()), ' +
        'z.object({ "kind": z.literal("team_id"), "value": z.string() }).catchall(z.unknown())]), ' +
        '"overlay": z.object({ "cdpMode": z.boolean().optional() }).catchall(z.unknown()).optional() }).catchall(z.unknown())',
    );
    const strict = applyAsymmetries(reader, "t", {}, false).schema;
    expect(convert(strict, "t")).toContain('"error": z.string().optional()');
    expect(convert(strict, "t")).not.toContain("catchall");
  });

  test("the changes, each at its path, and the emitted spellings", () => {
    const { schema, replacements } = applyAsymmetries(
      reader,
      "t",
      {
        "$.properties.id": entry([{ change: "string-arm" }]),
        "$.properties.label": entry([
          { change: "string", minLength: 1, maxLength: 32, pattern: "^[a-z/]+$" },
        ]),
        "$.properties.anchor": entry([{ change: "tag-union-as-enum-object" }]),
        "$.properties.anchor.properties.value": entry([{ change: "string", minLength: 1 }]),
        "$.properties.overlay": entry([
          { change: "generated-schema", symbol: "OverlaySchema", from: "./policy.gen" },
        ]),
      },
      true,
    );
    expect(convert(schema, "t")).toBe(
      'z.object({ "id": z.union([z.number().int().gte(0), z.string()]), "error": z.string().optional(), ' +
        '"label": z.string().min(1).max(32).regex(/^[a-z\\/]+$/).optional(), ' +
        '"anchor": z.object({ "kind": z.enum(["hash", "team_id"]), "value": z.string().min(1) }).catchall(z.unknown()), ' +
        '"overlay": OverlaySchema.optional() }).catchall(z.unknown())',
    );
    // The replacement keeps the Rust node (post null-arm drop) for the A2 cross-check.
    expect(replacements).toEqual([
      {
        path: "$.properties.overlay",
        symbol: "OverlaySchema",
        from: "./policy.gen",
        rust: strictObject({ cdpMode: { type: ["boolean", "null"] } }, []),
      },
    ]);
  });

  // A1: every way an entry fails to apply aborts generation, naming the path.
  const refused: readonly [string, Record<string, unknown>, string][] = [
    [
      "a path the schema lacks",
      { "$.properties.ghost": entry([{ change: "string" }]) },
      "does not have",
    ],
    [
      "a string change on a non-string node",
      { "$.properties.id": entry([{ change: "string" }]) },
      "A1",
    ],
    [
      "a string-arm on a non-numeric node",
      { "$.properties.label": entry([{ change: "string-arm" }]) },
      "A1",
    ],
    [
      "a tag-union flatten on a plain node",
      { "$.properties.label": entry([{ change: "tag-union-as-enum-object" }]) },
      "A1",
    ],
    [
      "a second change on a generated-schema replacement",
      {
        "$.properties.overlay": entry([
          { change: "generated-schema", symbol: "S", from: "./x" },
          { change: "string" },
        ]),
      },
      "already a generated-schema replacement",
    ],
  ];
  test.each(refused)("%s is refused", (_, entries, message) => {
    expect(() =>
      applyAsymmetries(reader, "t", entries as Parameters<typeof applyAsymmetries>[2], true),
    ).toThrow(message);
  });

  test("a tag union whose variants disagree on the content field is refused", () => {
    const mismatched = strictObject(
      {
        anchor: {
          anyOf: [
            strictObject({ kind: { type: "string", const: "a" }, value: { type: "string" } }, [
              "kind",
              "value",
            ]),
            strictObject({ kind: { type: "string", const: "b" }, value: { type: "integer" } }, [
              "kind",
              "value",
            ]),
          ],
        },
      },
      ["anchor"],
    );
    expect(() =>
      applyAsymmetries(
        mismatched,
        "t",
        { "$.properties.anchor": entry([{ change: "tag-union-as-enum-object" }]) },
        true,
      ),
    ).toThrow("one content field with one schema");
  });
  test("a required nullable property and nullable array items keep null; only an optional property drops it", () => {
    const reader = {
      type: "object",
      additionalProperties: false,
      properties: {
        values: { type: "array", items: { type: ["string", "null"] } },
        label: { type: ["string", "null"] },
        note: { type: ["string", "null"] },
      },
      required: ["values", "label"],
    };
    expect(convert(applyAsymmetries(reader, "t", {}, false).schema, "t")).toBe(
      'z.object({ "values": z.array(z.union([z.string(), z.null()])), "label": z.union([z.string(), z.null()]), ' +
        '"note": z.string().optional() }).strict()',
    );
  });
});

describe("assertFramePlan (G7)", () => {
  const variant = (tag: string, extra: Record<string, unknown> = {}) => ({
    type: "object",
    properties: { type: { type: "string", const: tag }, ...extra },
  });
  test("an unplanned Rust frame, a planned frame the enum lost, and a bare tag with fields are refused", () => {
    const planned = new Map(
      [
        "enclave_challenge",
        "enclave_proof",
        "enclave_error",
        "enclave_revoke",
        "enclave_revoked",
        "presence_challenge",
        "presence_proof",
        "presence_error",
      ].map((tag) => [tag, variant(tag)]),
    );
    expect(() => assertFramePlan("enclave", planned)).not.toThrow();
    expect(() =>
      assertFramePlan("enclave", new Map([...planned, ["enclave_new", variant("enclave_new")]])),
    ).toThrow("unplanned frame enclave_new");
    const lost = new Map(planned);
    lost.delete("enclave_error");
    expect(() => assertFramePlan("enclave", lost)).toThrow("has no such frame");
    const grown = new Map([
      ...planned,
      ["enclave_revoked", variant("enclave_revoked", { reason: { type: "string" } })],
    ]);
    expect(() => assertFramePlan("enclave", grown)).toThrow(
      "bare tag enclave_revoked carries fields reason",
    );
  });
});

describe("assertGeneratedMatches (A2)", () => {
  const replacement = (rust: unknown) => ({
    path: "$.properties.overlay",
    symbol: "S",
    from: "./x",
    rust,
  });
  const rustOverlay = {
    type: "object",
    additionalProperties: false,
    properties: {
      cdpMode: { type: ["boolean", "null"] },
      confirmGraceMs: { type: ["integer", "null"], minimum: 0 },
    },
  };
  test("same fields and base types pass; a missing field or a changed type is refused", () => {
    const matching = z.strictObject({
      cdpMode: z.boolean().optional(),
      confirmGraceMs: z.int().nonnegative().optional(),
    });
    expect(() => assertGeneratedMatches(replacement(rustOverlay), matching)).not.toThrow();
    const missing = z.strictObject({ cdpMode: z.boolean().optional() });
    expect(() => assertGeneratedMatches(replacement(rustOverlay), missing)).toThrow(
      "has fields [cdpMode]",
    );
    const retyped = z.strictObject({
      cdpMode: z.boolean().optional(),
      confirmGraceMs: z.string().optional(),
    });
    expect(() => assertGeneratedMatches(replacement(rustOverlay), retyped)).toThrow(
      "says string but the Rust node says integer",
    );
    // The any-schema has nothing to hold the generated schema to.
    expect(() => assertGeneratedMatches(replacement({}), missing)).not.toThrow();
  });
  test("a loose replacement of a strict Rust node is refused", () => {
    const rust = {
      type: "object",
      additionalProperties: false,
      properties: { cdpMode: { type: ["boolean", "null"] } },
    };
    const replacement = { path: "$.properties.overlay", symbol: "S", from: "./x", rust };
    expect(() =>
      assertGeneratedMatches(replacement, z.strictObject({ cdpMode: z.boolean().optional() })),
    ).not.toThrow();
    expect(() =>
      assertGeneratedMatches(replacement, z.looseObject({ cdpMode: z.boolean().optional() })),
    ).toThrow("admits unknown fields where the Rust node refuses them");
  });
});

describe("splitTaggedUnionSchema", () => {
  const variantA = {
    type: "object",
    properties: { type: { type: "string", const: "a" }, x: { $ref: "#/$defs/X" } },
    required: ["type"],
  };
  const variantB = {
    type: "object",
    properties: { type: { type: "string", const: "b" } },
    required: ["type"],
  };
  const defs = { X: { type: "string" } };
  const withX = (x: unknown) => ({
    oneOf: [{ ...variantA, properties: { ...variantA.properties, x } }, variantB],
    $defs: defs,
  });
  const partX = (schema: unknown) =>
    (splitTaggedUnionSchema(schema).get("a") as { properties: { x: unknown } }).properties.x;

  test("splits per tag and inlines $defs indirection (an annotation beside the $ref is dropped)", () => {
    const parts = splitTaggedUnionSchema({ oneOf: [variantA, variantB], $defs: defs });
    expect([...parts.keys()]).toEqual(["a", "b"]);
    expect(partX({ oneOf: [variantA, variantB], $defs: defs })).toEqual({ type: "string" });
    expect(partX(withX({ $ref: "#/$defs/X", description: "doc" }))).toEqual({ type: "string" });
  });

  test("refuses non-unions, tagless variants, duplicate tags, and a $ref with constraint siblings", () => {
    expect(() => splitTaggedUnionSchema({ type: "object" })).toThrow("oneOf");
    expect(() => splitTaggedUnionSchema({ oneOf: [{ type: "object", properties: {} }] })).toThrow(
      "type",
    );
    expect(() => splitTaggedUnionSchema({ oneOf: [variantB, variantB] })).toThrow("duplicate");
    expect(() => splitTaggedUnionSchema(withX({ $ref: "#/$defs/X", minLength: 1 }))).toThrow(
      "siblings",
    );
    expect(() => splitTaggedUnionSchema(withX({ $ref: "#/$defs/Missing" }))).toThrow(
      "unresolvable",
    );
  });
});
