// The normalizer is what stands between the equivalence tests and a false
// "equivalent" verdict, so its own behavior is pinned here: it may erase
// representation (annotations, $ref indirection, required order) and nothing
// else. Constraints must survive normalization verbatim.

import { describe, expect, test } from "bun:test";
import { diffSchemas, normalizeJsonSchema } from "./json-schema-normalize";

describe("normalizeJsonSchema", () => {
  test("strips annotations only", () => {
    const a = normalizeJsonSchema({
      $schema: "https://json-schema.org/draft/2020-12/schema",
      $id: "https://example.test/x.json",
      $comment: "noise",
      title: "X",
      description: "noise",
      type: "object",
      properties: { a: { type: "string", description: "noise" } },
    });
    const b = normalizeJsonSchema({
      type: "object",
      properties: { a: { type: "string" } },
    });
    expect(diffSchemas(a, b)).toEqual([]);
  });

  test("constraints survive verbatim (bounds, pattern, minLength, additionalProperties)", () => {
    const constrained = {
      type: "object",
      additionalProperties: false,
      properties: {
        n: { type: "integer", minimum: -9007199254740991, maximum: 9007199254740991 },
        s: { type: "string", minLength: 1, maxLength: 32, pattern: "^[a-z]+$" },
      },
    };
    expect(normalizeJsonSchema(constrained)).toEqual(constrained);
    // Dropping a single bound is a real difference, not representation.
    const loosened = {
      ...constrained,
      properties: {
        ...constrained.properties,
        n: { type: "integer", minimum: -9007199254740991 },
      },
    };
    expect(
      diffSchemas(normalizeJsonSchema(constrained), normalizeJsonSchema(loosened)),
    ).not.toEqual([]);
  });

  test("inlines $defs/$ref indirection", () => {
    const withRef = normalizeJsonSchema({
      type: "object",
      properties: { args: { $ref: "#/$defs/Args" } },
      $defs: { Args: { type: "object", properties: { a: { type: "string" } } } },
    });
    const inline = normalizeJsonSchema({
      type: "object",
      properties: { args: { type: "object", properties: { a: { type: "string" } } } },
    });
    expect(diffSchemas(withRef, inline)).toEqual([]);
  });

  test("refuses an unresolvable $ref", () => {
    expect(() =>
      normalizeJsonSchema({ type: "object", properties: { x: { $ref: "#/$defs/Missing" } } }),
    ).toThrow("unresolvable");
    expect(() =>
      normalizeJsonSchema({ properties: { x: { $ref: "https://elsewhere.test/schema.json" } } }),
    ).toThrow("unresolvable");
  });

  test("refuses a $ref with sibling keys rather than silently merging", () => {
    expect(() =>
      normalizeJsonSchema({
        properties: { x: { $ref: "#/$defs/Args", minLength: 1 } },
        $defs: { Args: { type: "string" } },
      }),
    ).toThrow("siblings");
  });

  test("required order does not matter; required content does", () => {
    const a = normalizeJsonSchema({ type: "object", required: ["b", "a"] });
    const b = normalizeJsonSchema({ type: "object", required: ["a", "b"] });
    expect(diffSchemas(a, b)).toEqual([]);
    const c = normalizeJsonSchema({ type: "object", required: ["a"] });
    expect(diffSchemas(a, c)).not.toEqual([]);
  });

  test("union shape is compared verbatim (anyOf is not collapsed)", () => {
    const anyOf = normalizeJsonSchema({ anyOf: [{ type: "integer" }, { type: "string" }] });
    const typeArray = normalizeJsonSchema({ type: ["integer", "string"] });
    expect(diffSchemas(anyOf, typeArray)).not.toEqual([]);
  });
});
