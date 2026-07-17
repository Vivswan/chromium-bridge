// The normalizer is what stands between the envelope double-derivation gate
// (scripts/check-envelope-parity.ts) and a false "equivalent" verdict, so
// its behavior is pinned here: it may erase representation and exactly the
// documented rules R1-R4 (see the module doc). At the reconciled paths each
// side must equal its own origin's approved form and is refused loudly
// otherwise - a drifted parser can never be compared away, not even by
// converging on the canonical form. Structure everywhere else must survive
// normalization verbatim. The fixtures below are the real shapes each
// derivation emits today; the mutation cases prove drift is CAUGHT.

import { describe, expect, test } from "bun:test";
import { diffSchemas, normalizeEnvelopeSchema } from "../src/json-schema-normalize";

const JS_SAFE = Number.MAX_SAFE_INTEGER;

// What schemars emits for the field today (Rust side)...
const RUST = {
  id: { type: "integer", format: "uint64", minimum: 0 },
  tabId: { type: ["integer", "null"], format: "int64" },
  op: { type: "string" },
  browser: { type: ["string", "null"] },
  error: { type: ["string", "null"] },
};
// ...and what z.toJSONSchema emits (Zod side).
const ZOD = {
  id: {
    anyOf: [{ type: "integer", minimum: -JS_SAFE, maximum: JS_SAFE }, { type: "string" }],
  },
  tabId: { type: "integer", minimum: -JS_SAFE, maximum: JS_SAFE },
  op: { type: "string", minLength: 1 },
  browser: { type: "string", minLength: 1, maxLength: 32, pattern: "^[A-Za-z0-9._-]+$" },
  error: { type: "string" },
};

function rustReq(properties: Record<string, unknown>): unknown {
  return normalizeEnvelopeSchema({ type: "object", properties }, "request", "rust");
}
function zodReq(properties: Record<string, unknown>): unknown {
  return normalizeEnvelopeSchema({ type: "object", properties }, "request", "zod");
}
function rustResp(properties: Record<string, unknown>): unknown {
  return normalizeEnvelopeSchema({ type: "object", properties }, "response", "rust");
}
function zodResp(properties: Record<string, unknown>): unknown {
  return normalizeEnvelopeSchema({ type: "object", properties }, "response", "zod");
}

describe("normalizeEnvelopeSchema", () => {
  test("R1: strips pure annotations, but format is contract material", () => {
    const annotated = normalizeEnvelopeSchema(
      {
        $schema: "https://json-schema.org/draft/2020-12/schema",
        $id: "https://example.test/x.json",
        $comment: "noise",
        title: "X",
        description: "noise",
        type: "object",
        properties: { op: { type: "string", description: "noise" } },
      },
      "request",
      "rust",
    );
    expect(diffSchemas(annotated, rustReq({ op: { type: "string" } }))).toEqual([]);
    // `format` claims an integer width (or a string dialect) and is only
    // erased through an exact R4 form - never as an annotation.
    expect(
      diffSchemas(
        rustResp({ ok: { type: "boolean", format: "x" } }),
        zodResp({ ok: { type: "boolean" } }),
      ),
    ).not.toEqual([]);
  });

  test("R2: the boolean schema `true` means any, like {}", () => {
    expect(diffSchemas(rustResp({ data: true }), zodResp({ data: {} }))).toEqual([]);
  });

  test("R3: rust args must be the any-schema, zod args an object schema", () => {
    const zodArgs = {
      type: "object",
      properties: { url: { type: "string" } },
      additionalProperties: false,
    };
    expect(diffSchemas(zodReq({ args: zodArgs }), rustReq({ args: true }))).toEqual([]);
    // Rust narrowing args away from "anything" is refused, not erased.
    expect(() => rustReq({ args: zodArgs })).toThrow("no longer free-form");
    // So is the zod side losing its OpArgs narrowing: a widened zod args
    // would otherwise equal the canonical any-schema.
    expect(() => zodReq({ args: true })).toThrow("narrowing");
    expect(() => zodReq({ args: { type: "string" } })).toThrow("narrowing");
    expect(() => zodReq({ args: { anyOf: [zodArgs] } })).toThrow("narrowing");
    // Response schemas get no args rule.
    expect(diffSchemas(zodResp({ args: zodArgs }), rustResp({ args: true }))).not.toEqual([]);
  });

  test("R4: today's real derivations reconcile field by field", () => {
    expect(
      diffSchemas(
        rustReq({ id: RUST.id, tabId: RUST.tabId, op: RUST.op, browser: RUST.browser }),
        zodReq({ id: ZOD.id, tabId: ZOD.tabId, op: ZOD.op, browser: ZOD.browser }),
      ),
    ).toEqual([]);
    expect(
      diffSchemas(
        rustResp({ id: RUST.id, error: RUST.error }),
        zodResp({ id: ZOD.id, error: ZOD.error }),
      ),
    ).toEqual([]);
  });

  test("R4 mutation: a side adopting the OTHER side's approved form is refused", () => {
    // Zod's browser validator degrading to the Rust null-arm shape (its
    // grammar gone) must not match under the zod origin.
    expect(() => zodReq({ browser: RUST.browser })).toThrow("approved zod form");
    // Zod's op losing minLength by adopting the plain Rust form - which is
    // also the canonical form, so only the refusal can catch it.
    expect(() => zodReq({ op: RUST.op })).toThrow("approved zod form");
    // Rust's id widening into Zod's integer-or-string union.
    expect(() => rustReq({ id: ZOD.id })).toThrow("approved rust form");
    // Rust's tabId dropping nullability for Zod's bounded integer.
    expect(() => rustReq({ tabId: ZOD.tabId })).toThrow("approved rust form");
  });

  test("R4 mutation: a changed integer width on id is refused", () => {
    // If BridgeReq::id became i64, schemars would emit int64 with no
    // minimum; that matches no approved form.
    expect(() => rustReq({ id: { type: "integer", format: "int64" } })).toThrow(
      "approved rust form",
    );
    // Likewise a u64 that lost its lower bound.
    expect(() => rustReq({ id: { type: "integer", format: "uint64" } })).toThrow(
      "approved rust form",
    );
  });

  test("R4 mutation: a constrained id string arm is refused", () => {
    const narrowedArm = {
      anyOf: [
        { type: "integer", minimum: -JS_SAFE, maximum: JS_SAFE },
        { type: "string", minLength: 1 },
      ],
    };
    expect(() => zodReq({ id: narrowedArm })).toThrow("approved zod form");
    // And a sibling constraint next to the anyOf.
    expect(() => zodReq({ id: { ...ZOD.id, multipleOf: 2 } })).toThrow("approved zod form");
  });

  test("R4 mutation: changed bounds and patterns are refused", () => {
    expect(() => rustReq({ tabId: { type: "integer", minimum: 0 } })).toThrow("approved rust form");
    expect(() => zodReq({ browser: { ...ZOD.browser, maxLength: 64 } })).toThrow(
      "approved zod form",
    );
  });

  test("outside the reconciled paths, differences survive to the diff", () => {
    // A null-arm on a field with no reconciliation entry is a real
    // difference (a newly nullable field must fail the gate).
    expect(
      diffSchemas(
        rustResp({ ok: { type: ["boolean", "null"] } }),
        zodResp({ ok: { type: "boolean" } }),
      ),
    ).not.toEqual([]);
    // Kind-scoped: tabId has no entry (and no refusal) on the response side.
    expect(diffSchemas(rustResp({ tabId: RUST.tabId }), zodResp({ tabId: ZOD.tabId }))).not.toEqual(
      [],
    );
    // A property present on one side only is always a difference.
    expect(
      diffSchemas(zodReq({ id: ZOD.id, extra: { type: "string" } }), zodReq({ id: ZOD.id })),
    ).not.toEqual([]);
  });

  test("required is order-insensitive but compared verbatim, args included", () => {
    const a = normalizeEnvelopeSchema(
      { type: "object", required: ["op", "id", "args"] },
      "request",
      "rust",
    );
    const b = normalizeEnvelopeSchema(
      { type: "object", required: ["args", "id", "op"] },
      "request",
      "zod",
    );
    expect(diffSchemas(a, b)).toEqual([]);
    // One side no longer requiring args is a contract change, not noise.
    const noArgs = normalizeEnvelopeSchema(
      { type: "object", required: ["id", "op"] },
      "request",
      "rust",
    );
    expect(diffSchemas(b, noArgs)).not.toEqual([]);
  });

  test("additionalProperties is compared verbatim", () => {
    const strict = normalizeEnvelopeSchema(
      { type: "object", additionalProperties: false },
      "request",
      "rust",
    );
    const loose = normalizeEnvelopeSchema({ type: "object" }, "request", "zod");
    expect(diffSchemas(strict, loose)).not.toEqual([]);
  });

  test("inlines $defs/$ref indirection", () => {
    const withRef = normalizeEnvelopeSchema(
      {
        type: "object",
        properties: { extra: { $ref: "#/$defs/Extra" } },
        $defs: { Extra: { type: "object", properties: { a: { type: "string" } } } },
      },
      "request",
      "rust",
    );
    const inline = rustReq({ extra: { type: "object", properties: { a: { type: "string" } } } });
    expect(diffSchemas(withRef, inline)).toEqual([]);
  });

  test("refuses an unresolvable $ref", () => {
    expect(() =>
      normalizeEnvelopeSchema(
        { type: "object", properties: { x: { $ref: "#/$defs/Missing" } } },
        "request",
        "rust",
      ),
    ).toThrow("unresolvable");
    expect(() =>
      normalizeEnvelopeSchema(
        { properties: { x: { $ref: "https://elsewhere.test/schema.json" } } },
        "request",
        "rust",
      ),
    ).toThrow("unresolvable");
  });

  test("refuses a $ref with sibling keys rather than silently merging", () => {
    expect(() =>
      normalizeEnvelopeSchema(
        {
          properties: { x: { $ref: "#/$defs/Extra", minLength: 1 } },
          $defs: { Extra: { type: "string" } },
        },
        "request",
        "rust",
      ),
    ).toThrow("siblings");
  });
});
