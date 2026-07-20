// The fail-closed generation rules (G1-G5) of scripts/gen-envelope.ts,
// exercised against schemas that would otherwise convert to WEAKER Zod
// validators than the Rust contract: objects without an explicit type,
// unconstrained arrays, keywords the generator does not model, undiscriminated
// oneOf, unresolved $refs. Every one of these must abort generation, never
// emit. The happy paths mirror the real schemars output shapes.

import { describe, expect, test } from "bun:test";
import { convert, prepare } from "./gen-envelope";

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
  test("G1: object-shaped keywords without type: object (converter would emit z.any())", () => {
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

  test("G5: arrays without a single object items schema (z.array(z.any()))", () => {
    expect(() => prepare({ type: "array" }, "$")).toThrow("G5");
    expect(() => prepare({ type: "array", items: false }, "$")).toThrow("G5");
    expect(() => prepare({ type: "array", items: true }, "$")).toThrow("G5");
    expect(() => prepare({ type: "array", items: [{ type: "string" }] }, "$")).toThrow("G5");
    expect(() => prepare({ items: { type: "string" } }, "$")).toThrow("G5");
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

  test("G3: an undiscriminated oneOf (converter would emit type-erased superRefine)", () => {
    const branch = (tag: string) =>
      strictObject({ kind: { type: "string", const: tag } }, ["kind"]);
    expect(() => prepare({ oneOf: [branch("a"), branch("a")] }, "$")).toThrow("G3");
    expect(() =>
      prepare({ oneOf: [branch("a"), strictObject({ kind: { type: "string" } }, ["kind"])] }, "$"),
    ).toThrow("G3");
    expect(() => prepare({ oneOf: [{ type: "string" }, { type: "integer" }] }, "$")).toThrow("G3");
  });

  test("G5: degenerate unions (converter would drop constraints or emit z.any())", () => {
    // Empty unions convert to z.any().
    expect(() => prepare({ anyOf: [] }, "$")).toThrow("G5");
    expect(() => prepare({ oneOf: [] }, "$")).toThrow("G5");
    // Sibling constraints beside a combinator are silently discarded.
    expect(() =>
      prepare({ type: "number", minimum: 5, anyOf: [{ type: "number", maximum: 10 }] }, "$"),
    ).toThrow("G5");
    // Two combinators on one node: one of them wins, the other is lost.
    expect(() =>
      prepare({ anyOf: [{ type: "string" }], oneOf: [{ type: "integer" }] }, "$"),
    ).toThrow("G5");
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
