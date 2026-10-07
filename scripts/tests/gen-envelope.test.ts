// The fail-closed generation rules (G1-G7, A1-A3) of scripts/gen-envelope.ts,
// exercised against inputs that would otherwise turn into WEAKER validators
// than the Rust contract: objects without an explicit type, unconstrained
// arrays, keywords the generator does not admit, undiscriminated oneOf,
// unresolved $refs, an unplanned Rust frame, an asymmetry entry on a node it
// cannot apply to. Every one of these must abort generation, never emit. The
// happy paths mirror the real schemars output shapes, and the prepared JSON
// Schema is pinned where prepare rewrites it.

import { describe, expect, test } from "bun:test";
import { z } from "zod";
import {
  applyAsymmetries,
  assertFramePlan,
  assertGeneratedMatches,
  prepare,
  splitFlattenedCommand,
  splitTaggedUnionSchema,
} from "../gen-envelope";
import { emittedValidator } from "../gen-schema";

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
    // schemars' integer-width format is stripped: inert beside the safe-integers rule, unread by zod.
    expect(prepare(schema, "$")).toEqual(
      strictObject({ id: { type: "integer", minimum: 0 }, op: { type: "string" } }, ["id", "op"]),
    );
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
    const out = prepare({ oneOf: [branch("hash"), branch("label")] }, "$") as {
      oneOf?: unknown;
      anyOf?: unknown;
    };
    expect(out.oneOf).toBeUndefined();
    expect(out.anyOf).toEqual([branch("hash"), branch("label")]);
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
    // format belongs to an integer node only (a string format, or an integer claim on a plain number, would go
    // unenforced); bounds constrain only numeric nodes; const only strings.
    expect(() => prepare({ type: "string", format: "uuid" }, "$")).toThrow("G5");
    expect(() => prepare({ type: "number", format: "int64" }, "$")).toThrow("G5");
    // A string arm beside the integer arm would give format a string-format meaning.
    expect(() => prepare({ type: ["integer", "string"], format: "uuid" }, "$")).toThrow("G5");
    expect(() => prepare({ type: ["string", "number"], format: "uuid" }, "$")).toThrow("G5");
    expect(() => prepare({ type: "string", minimum: 1 }, "$")).toThrow("G5");
    expect(() => prepare({ type: "integer", minimum: "0" }, "$")).toThrow("G5");
    expect(() => prepare({ type: "boolean", maximum: 1 }, "$")).toThrow("G5");
    // minItems is an array length floor and nothing else.
    expect(() => prepare({ type: "string", minItems: 1 }, "$")).toThrow("G5");
    expect(() => prepare({ type: "array", items: { type: "string" }, minItems: -1 }, "$")).toThrow(
      "G5",
    );
    expect(() => prepare({ type: "array", items: { type: "string" }, minItems: 1.5 }, "$")).toThrow(
      "G5",
    );
    expect(() => prepare({ type: "integer", const: "7" }, "$")).toThrow("G5");
    expect(() => prepare({ type: ["string", "null"], const: "x" }, "$")).toThrow("G5");
    expect(() => prepare({ type: [] }, "$")).toThrow("G5");
    // The Option null-arm beside a numeric type is inert and stays allowed.
    expect(prepare({ type: ["integer", "null"], format: "int64" }, "$")).toEqual({
      type: ["integer", "null"],
    });
  });

  test("required naming a field that does not exist", () => {
    expect(() => prepare(strictObject({ a: { type: "string" } }, ["a", "ghost"]), "$")).toThrow(
      "non-property",
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
    // The envelope then prepares exactly as the untyped request always did.
    expect(prepare(envelope, "$")).toEqual({
      type: "object",
      properties: {
        args: {},
        browser: { type: ["string", "null"] },
        id: { type: "integer", minimum: 0 },
        op: { type: "string" },
      },
      required: ["id", "args", "op"],
      additionalProperties: false,
    });
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
  test("a string enum survives; anything else is refused", () => {
    const kind = { type: "string", enum: ["hash", "label"] };
    expect(prepare(kind, "$")).toEqual(kind);
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
  // A control frame as prepare leaves it: a required integer, two Option strings, a tagged union, and an
  // Option object (serde's Option<Struct>: an anyOf with a null branch).
  const reader = strictObject(
    {
      id: { type: "integer", minimum: 0 },
      error: { type: ["string", "null"] },
      label: { type: ["string", "null"] },
      anchor: {
        anyOf: [
          strictObject({ kind: { type: "string", const: "hash" }, value: { type: "string" } }, [
            "kind",
            "value",
          ]),
          strictObject({ kind: { type: "string", const: "label" }, value: { type: "string" } }, [
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
  const loose = (properties: Record<string, unknown>, required: string[]) => ({
    ...strictObject(properties, required),
    additionalProperties: true,
  });
  const reads = (schema: unknown) => emittedValidator(schema);

  test("the reader rules: null arms dropped on every Option, objects loose on a control frame only", () => {
    const control = applyAsymmetries(reader, "t", {}, true).schema;
    expect(control).toEqual(
      loose(
        {
          id: { type: "integer", minimum: 0 },
          error: { type: "string" },
          label: { type: "string" },
          anchor: {
            anyOf: [
              loose({ kind: { type: "string", const: "hash" }, value: { type: "string" } }, [
                "kind",
                "value",
              ]),
              loose({ kind: { type: "string", const: "label" }, value: { type: "string" } }, [
                "kind",
                "value",
              ]),
            ],
          },
          overlay: loose({ cdpMode: { type: "boolean" } }, []),
        },
        ["id", "anchor"],
      ),
    );
    const envelope = applyAsymmetries(reader, "t", {}, false).schema as {
      properties: Record<string, unknown>;
      additionalProperties: unknown;
    };
    expect(envelope.additionalProperties).toBe(false);
    expect(envelope.properties.error).toEqual({ type: "string" });
    expect(JSON.stringify(envelope)).not.toContain('"additionalProperties":true');
  });

  test("the changes, each at its path, as plain JSON Schema; the owner's schema is inlined whole", () => {
    const overlaySchema = strictObject({ cdpMode: { type: "boolean" } }, []);
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
      new Map([["OverlaySchema", overlaySchema]]),
    );
    expect(schema).toEqual(
      loose(
        {
          id: { anyOf: [{ type: "integer", minimum: 0 }, { type: "string" }] },
          error: { type: "string" },
          label: { type: "string", minLength: 1, maxLength: 32, pattern: "^[a-z/]+$" },
          anchor: loose(
            {
              kind: { type: "string", enum: ["hash", "label"] },
              value: { type: "string", minLength: 1 },
            },
            ["kind", "value"],
          ),
          // Inlined as the owner wrote it: strict, and outside the loose-frames rule.
          overlay: overlaySchema,
        },
        ["id", "anchor"],
      ),
    );
    // The replacement keeps the Rust node (post null-arm drop) and the inlined schema for the A2 cross-checks.
    expect(replacements).toEqual([
      {
        path: "$.properties.overlay",
        symbol: "OverlaySchema",
        from: "./policy.gen",
        rust: strictObject({ cdpMode: { type: ["boolean", "null"] } }, []),
        inlined: overlaySchema,
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
      "a generated-schema entry naming a schema nothing builds",
      {
        "$.properties.overlay": entry([
          { change: "generated-schema", symbol: "Ghost", from: "./x" },
        ]),
      },
      "no schema named Ghost",
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
      applyAsymmetries(
        reader,
        "t",
        entries as Parameters<typeof applyAsymmetries>[2],
        true,
        new Map([["S", strictObject({}, [])]]),
      ),
    ).toThrow(message);
  });

  test("an ok-split is a union whose arms require and refuse exactly the declared fields (A3)", () => {
    // The field-level change (min 1 on label) is applied before the split, so both arms inherit it.
    const verdict = strictObject(
      {
        ok: { type: "boolean" },
        label: { type: ["string", "null"] },
        error: { type: ["string", "null"] },
      },
      ["ok"],
    );
    const split = (arms: unknown) => entry([{ change: "ok-split", discriminant: "ok", arms }]);
    const { schema } = applyAsymmetries(
      verdict,
      "t",
      {
        $: split([
          { when: true, required: ["label"], forbidden: ["error"] },
          { when: false, required: ["error"], forbidden: ["label"] },
        ]),
        "$.properties.label": entry([{ change: "string", minLength: 1 }]),
      },
      true,
    );
    expect(schema).toEqual({
      anyOf: [
        loose(
          {
            ok: { type: "boolean", const: true },
            label: { type: "string", minLength: 1 },
            error: false,
          },
          ["ok", "label"],
        ),
        loose({ ok: { type: "boolean", const: false }, label: false, error: { type: "string" } }, [
          "ok",
          "error",
        ]),
      ],
    });
    // The library reads a forbidden field as "absent or nothing": a present value, null included, fails the arm.
    const reading = reads(schema);
    expect(reading.safeParse({ ok: true, label: "x" }).success).toBe(true);
    expect(reading.safeParse({ ok: false, error: "e", extra: 1 }).success).toBe(true);
    expect(reading.safeParse({ ok: true }).success).toBe(false);
    expect(reading.safeParse({ ok: true, label: "x", error: "e" }).success).toBe(false);
    expect(reading.safeParse({ ok: false, error: "e", label: null }).success).toBe(false);
    for (const [why, arms] of [
      ["one arm only", [{ when: true, required: [], forbidden: [] }]],
      [
        "a field the frame lacks",
        [
          { when: true, required: ["missing"], forbidden: [] },
          { when: false, required: [], forbidden: [] },
        ],
      ],
      [
        "a field both required and forbidden",
        [
          { when: true, required: ["label"], forbidden: ["label"] },
          { when: false, required: [], forbidden: [] },
        ],
      ],
    ] as const) {
      expect(() => applyAsymmetries(verdict, "t", { $: split(arms) }, true), why).toThrow("(A3)");
    }
    // Paired with a generated-schema replacement the frame has no arms to split, and the replacement's early
    // return would otherwise skip the split and every refusal above.
    expect(() =>
      applyAsymmetries(
        verdict,
        "t",
        {
          $: entry([
            { change: "generated-schema", symbol: "VerdictSchema", from: "./verdict.gen" },
            {
              change: "ok-split",
              discriminant: "ok",
              arms: [{ when: true, required: ["missing"], forbidden: ["missing"] }],
            },
          ]),
        },
        true,
        new Map([["VerdictSchema", verdict]]),
      ),
    ).toThrow("(A3)");
    // The discriminant must be a required boolean: a string `ok`, or an optional one, is refused.
    const stringOk = strictObject({ ok: { type: "string" } }, ["ok"]);
    expect(() =>
      applyAsymmetries(
        stringOk,
        "t",
        {
          $: split([
            { when: true, required: [], forbidden: [] },
            { when: false, required: [], forbidden: [] },
          ]),
        },
        true,
      ),
    ).toThrow("(A3)");
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
    const reader = strictObject(
      {
        values: { type: "array", items: { type: ["string", "null"] } },
        label: { type: ["string", "null"] },
        note: { type: ["string", "null"] },
      },
      ["values", "label"],
    );
    expect(applyAsymmetries(reader, "t", {}, false).schema).toEqual(
      strictObject(
        {
          values: { type: "array", items: { type: ["string", "null"] } },
          label: { type: ["string", "null"] },
          note: { type: "string" },
        },
        ["values", "label"],
      ),
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
    inlined: {},
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
    expect(() =>
      assertGeneratedMatches(
        replacement(rust),
        z.strictObject({ cdpMode: z.boolean().optional() }),
      ),
    ).not.toThrow();
    expect(() =>
      assertGeneratedMatches(replacement(rust), z.looseObject({ cdpMode: z.boolean().optional() })),
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
  const partX = async (schema: unknown) =>
    ((await splitTaggedUnionSchema(schema)).get("a") as { properties: { x: unknown } }).properties
      .x;

  test("splits per tag and dereferences the $defs indirection; a sibling beside the $ref is merged into the target, the sibling winning a collision", async () => {
    const parts = await splitTaggedUnionSchema({ oneOf: [variantA, variantB], $defs: defs });
    expect([...parts.keys()]).toEqual(["a", "b"]);
    expect(await partX({ oneOf: [variantA, variantB], $defs: defs })).toEqual({ type: "string" });
    expect(await partX(withX({ $ref: "#/$defs/X", description: "doc" }))).toEqual({
      description: "doc",
      type: "string",
    });
    expect(await partX(withX({ $ref: "#/$defs/X", minLength: 1 }))).toEqual({
      minLength: 1,
      type: "string",
    });
    expect(await partX(withX({ $ref: "#/$defs/X", type: "integer" }))).toEqual({
      type: "integer",
    });
  });

  test("refuses non-unions, tagless variants, duplicate tags, and an unresolvable $ref; an external $ref stays for prepare to refuse", async () => {
    await expect(splitTaggedUnionSchema({ type: "object" })).rejects.toThrow("oneOf");
    await expect(
      splitTaggedUnionSchema({ oneOf: [{ type: "object", properties: {} }] }),
    ).rejects.toThrow("type");
    await expect(splitTaggedUnionSchema({ oneOf: [variantB, variantB] })).rejects.toThrow(
      "duplicate",
    );
    await expect(splitTaggedUnionSchema(withX({ $ref: "#/$defs/Missing" }))).rejects.toThrow(
      "Missing",
    );
    const external = await partX(withX({ $ref: "other.json#/X" }));
    expect(external).toEqual({ $ref: "other.json#/X" });
    expect(() => prepare(external, "$")).toThrow("G4");
  });
});
