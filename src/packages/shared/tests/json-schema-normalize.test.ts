// The normalizer is what stands between the envelope double-derivation gate
// (scripts/check-envelope-parity.ts) and a false "equivalent" verdict, so
// its behavior is pinned here: it may erase representation and exactly the
// documented rules R1-R5 (see the module doc). At the reconciled paths each
// side must equal its own origin's approved form and is refused loudly
// otherwise - a drifted parser can never be compared away, not even by
// converging on the canonical form. Structure everywhere else must survive
// normalization verbatim. The fixtures below are the real shapes each
// derivation emits today; the mutation cases prove drift is CAUGHT.

import { describe, expect, test } from "bun:test";
import {
  diffSchemas,
  normalizeEnvelopeSchema,
  splitTaggedUnionSchema,
} from "../src/json-schema-normalize";

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

// The fixtures below often carry a single field on purpose; opt those out of
// the unconsumed-pin refusal (the gate's default), which its own tests
// exercise against full schemas.
const PARTIAL = { requireConsumedPins: false } as const;

function rustReq(properties: Record<string, unknown>): unknown {
  return normalizeEnvelopeSchema({ type: "object", properties }, "request", "rust", PARTIAL);
}
function zodReq(properties: Record<string, unknown>): unknown {
  return normalizeEnvelopeSchema({ type: "object", properties }, "request", "zod", PARTIAL);
}
function rustResp(properties: Record<string, unknown>): unknown {
  return normalizeEnvelopeSchema({ type: "object", properties }, "response", "rust", PARTIAL);
}
function zodResp(properties: Record<string, unknown>): unknown {
  return normalizeEnvelopeSchema({ type: "object", properties }, "response", "zod", PARTIAL);
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
      PARTIAL,
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

  test("a pin the walk never consumes is refused, not left inert", () => {
    // By default (the gate's mode) every RECONCILED_FIELDS pin for the kind
    // must be hit: a schema that lost a pinned field - or a pin whose path
    // no longer matches anything - fails loudly, naming the leftover.
    expect(() =>
      normalizeEnvelopeSchema({ type: "object", properties: { op: ZOD.op } }, "request", "zod"),
    ).toThrow(/RECONCILED_FIELDS \$\.properties\.id/);
    expect(() =>
      normalizeEnvelopeSchema({ type: "object", properties: { id: RUST.id } }, "response", "rust"),
    ).toThrow(/RECONCILED_FIELDS \$\.properties\.error/);
    // The full pin set consumed normalizes cleanly without the opt-out.
    expect(() =>
      normalizeEnvelopeSchema(
        { type: "object", properties: { id: RUST.id, error: RUST.error } },
        "response",
        "rust",
      ),
    ).not.toThrow();
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
      PARTIAL,
    );
    const b = normalizeEnvelopeSchema(
      { type: "object", required: ["args", "id", "op"] },
      "request",
      "zod",
      PARTIAL,
    );
    expect(diffSchemas(a, b)).toEqual([]);
    // One side no longer requiring args is a contract change, not noise.
    const noArgs = normalizeEnvelopeSchema(
      { type: "object", required: ["id", "op"] },
      "request",
      "rust",
      PARTIAL,
    );
    expect(diffSchemas(b, noArgs)).not.toEqual([]);
  });

  test("additionalProperties is compared verbatim", () => {
    const strict = normalizeEnvelopeSchema(
      { type: "object", additionalProperties: false },
      "request",
      "rust",
      PARTIAL,
    );
    const loose = normalizeEnvelopeSchema({ type: "object" }, "request", "zod", PARTIAL);
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
      PARTIAL,
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

  test("refuses a $ref with constraint siblings rather than silently merging", () => {
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
    // Annotation siblings constrain nothing: schemars puts a field's doc
    // comment next to the $ref (ClientEntry.anchor), and it is dropped like
    // R1 drops annotations everywhere else.
    const annotated = normalizeEnvelopeSchema(
      {
        type: "object",
        properties: { x: { $ref: "#/$defs/Extra", description: "noise" } },
        $defs: { Extra: { type: "string" } },
      },
      "request",
      "rust",
      PARTIAL,
    );
    expect(diffSchemas(annotated, rustReq({ x: { type: "string" } }))).toEqual([]);
    // $id and $schema are NOT harmless beside a $ref: they change how a
    // conforming validator resolves it (base URI / dialect), so they are
    // refused there even though R1 strips them elsewhere.
    for (const sibling of [
      { $id: "https://elsewhere.test/x.json" },
      { $schema: "https://json-schema.org/draft-07/schema" },
    ]) {
      expect(() =>
        normalizeEnvelopeSchema(
          {
            properties: { x: { $ref: "#/$defs/Extra", ...sibling } },
            $defs: { Extra: { type: "string" } },
          },
          "request",
          "rust",
        ),
      ).toThrow("siblings");
    }
  });
});

// ---- the control frames (EnclaveControl / AdminControl, R5 + new R4s) ---------

// The real shapes each derivation emits today for a signed-statement frame
// (enclave_proof / presence_proof share the field set)...
const RUST_PROOF = {
  type: "object",
  additionalProperties: false,
  properties: {
    type: { type: "string", const: "enclave_proof" },
    sig: { type: "string" },
    key_id: { type: "string" },
    pubkey: { type: "string" },
  },
  required: ["type", "sig", "key_id", "pubkey"],
};
const ZOD_PROOF = {
  type: "object",
  additionalProperties: {},
  properties: {
    type: { type: "string", const: "enclave_proof" },
    sig: { type: "string", minLength: 1 },
    key_id: { type: "string", minLength: 1 },
    pubkey: { type: "string", minLength: 1 },
  },
  required: ["type", "sig", "key_id", "pubkey"],
};

// ...and for the admin list result, ClientEntry (with the adjacently-tagged
// Anchor) embedded.
const RUST_ANCHOR = {
  oneOf: [
    {
      type: "object",
      additionalProperties: false,
      properties: { kind: { type: "string", const: "hash" }, value: { type: "string" } },
      required: ["kind", "value"],
    },
    {
      type: "object",
      additionalProperties: false,
      properties: { kind: { type: "string", const: "team_id" }, value: { type: "string" } },
      required: ["kind", "value"],
    },
  ],
};
const ZOD_ANCHOR = {
  type: "object",
  additionalProperties: {},
  properties: {
    kind: { type: "string", enum: ["hash", "team_id"] },
    value: { type: "string", minLength: 1 },
  },
  required: ["kind", "value"],
};
const RUST_CLIENT_LIST = {
  type: "object",
  additionalProperties: false,
  properties: {
    type: { type: "string", const: "client_list_result" },
    ok: { type: "boolean" },
    enrolled: { type: "boolean" },
    error: { type: ["string", "null"] },
    clients: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        properties: {
          name: { type: "string" },
          anchor: RUST_ANCHOR,
          added_unix: { type: "integer", format: "uint64", minimum: 0, default: 0 },
        },
        required: ["name", "anchor"],
      },
    },
  },
  required: ["type", "ok", "enrolled", "clients"],
};
const ZOD_CLIENT_LIST = {
  type: "object",
  additionalProperties: {},
  properties: {
    type: { type: "string", const: "client_list_result" },
    ok: { type: "boolean" },
    enrolled: { type: "boolean" },
    error: { type: "string" },
    clients: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: {},
        properties: {
          name: { type: "string", minLength: 1 },
          anchor: ZOD_ANCHOR,
          added_unix: { type: "integer", minimum: 0, maximum: JS_SAFE },
        },
        required: ["name", "anchor"],
      },
    },
  },
  required: ["type", "ok", "enrolled", "clients"],
};

describe("normalizeEnvelopeSchema on control frames", () => {
  test("R5 + R4: today's real proof-frame derivations are equivalent", () => {
    expect(
      diffSchemas(
        normalizeEnvelopeSchema(RUST_PROOF, "enclave_proof", "rust"),
        normalizeEnvelopeSchema(ZOD_PROOF, "enclave_proof", "zod"),
      ),
    ).toEqual([]);
  });

  test("R5 + R4: today's real client_list_result derivations are equivalent", () => {
    expect(
      diffSchemas(
        normalizeEnvelopeSchema(RUST_CLIENT_LIST, "client_list_result", "rust"),
        normalizeEnvelopeSchema(ZOD_CLIENT_LIST, "client_list_result", "zod"),
      ),
    ).toEqual([]);
  });

  test("R5 refusal: a Rust frame losing deny_unknown_fields is fail-open drift", () => {
    const loosened = { ...RUST_PROOF, additionalProperties: {} };
    expect(() => normalizeEnvelopeSchema(loosened, "enclave_proof", "rust")).toThrow(
      "deny_unknown_fields",
    );
    const dropped = { ...RUST_PROOF };
    delete (dropped as Record<string, unknown>).additionalProperties;
    expect(() => normalizeEnvelopeSchema(dropped, "enclave_proof", "rust")).toThrow(
      "deny_unknown_fields",
    );
  });

  test("R5 refusal: a Zod frame leaving the documented looseObject form", () => {
    // Going strict is a deliberate contract change, not something to erase.
    expect(() =>
      normalizeEnvelopeSchema(
        { ...ZOD_PROOF, additionalProperties: false },
        "enclave_proof",
        "zod",
      ),
    ).toThrow("looseObject");
    const dropped = { ...ZOD_PROOF };
    delete (dropped as Record<string, unknown>).additionalProperties;
    expect(() => normalizeEnvelopeSchema(dropped, "enclave_proof", "zod")).toThrow("looseObject");
  });

  test("R5 is scoped to control frames: nested objects are checked, envelopes are not", () => {
    // The nested ClientEntry object also carries the origin marker (checked
    // by the equivalence test above); a nested Rust object losing it fails.
    const nested = structuredClone(RUST_CLIENT_LIST) as typeof RUST_CLIENT_LIST;
    delete (nested.properties.clients.items as Record<string, unknown>).additionalProperties;
    expect(() => normalizeEnvelopeSchema(nested, "client_list_result", "rust")).toThrow(
      "deny_unknown_fields",
    );
    // Request/response keep the verbatim additionalProperties comparison
    // (see "additionalProperties is compared verbatim" above).
  });

  test("R5 also walks the extension->host frames, rust-side only", () => {
    // audit_event has no Zod reader, but its rust-side normalization must
    // still refuse a variant that stops rejecting unknown fields.
    const auditEvent = {
      type: "object",
      additionalProperties: false,
      properties: {
        type: { type: "string", const: "audit_event" },
        kind: { type: "string" },
        outcome: { type: ["string", "null"] },
      },
      required: ["type", "kind"],
    };
    expect(() => normalizeEnvelopeSchema(auditEvent, "audit_event", "rust")).not.toThrow();
    const loosened = { ...auditEvent };
    delete (loosened as Record<string, unknown>).additionalProperties;
    expect(() => normalizeEnvelopeSchema(loosened, "audit_event", "rust")).toThrow(
      "deny_unknown_fields",
    );
  });

  test("R4 mutation: proof material losing the Zod non-empty guard is refused", () => {
    const weakened = structuredClone(ZOD_PROOF) as typeof ZOD_PROOF;
    weakened.properties.sig = { type: "string" } as (typeof ZOD_PROOF)["properties"]["sig"];
    expect(() => normalizeEnvelopeSchema(weakened, "enclave_proof", "zod")).toThrow(
      "approved zod form",
    );
  });

  test("R4 mutation: kill_status_result.killed must keep each origin's form", () => {
    const rustKill = {
      type: "object",
      additionalProperties: false,
      properties: {
        type: { type: "string", const: "kill_status_result" },
        ok: { type: "boolean" },
        killed: { type: ["boolean", "null"] },
        error: { type: ["string", "null"] },
      },
      required: ["type", "ok"],
    };
    const zodKill = {
      type: "object",
      additionalProperties: {},
      properties: {
        type: { type: "string", const: "kill_status_result" },
        ok: { type: "boolean" },
        killed: { type: "boolean" },
        error: { type: "string" },
      },
      required: ["type", "ok"],
    };
    expect(
      diffSchemas(
        normalizeEnvelopeSchema(rustKill, "kill_status_result", "rust"),
        normalizeEnvelopeSchema(zodKill, "kill_status_result", "zod"),
      ),
    ).toEqual([]);
    // Rust dropping the Option null-arm (killed no longer optional in the
    // wire type) is refused, not erased.
    const changed = structuredClone(rustKill);
    (changed.properties as Record<string, unknown>).killed = { type: "boolean" };
    expect(() => normalizeEnvelopeSchema(changed, "kill_status_result", "rust")).toThrow(
      "approved rust form",
    );
  });

  test("R4 mutation: the anchor union and added_unix hardening are pinned", () => {
    // The Zod anchor losing a kind from its enum.
    const narrowed = structuredClone(ZOD_CLIENT_LIST) as typeof ZOD_CLIENT_LIST;
    narrowed.properties.clients.items.properties.anchor.properties.kind.enum = ["hash"];
    expect(() => normalizeEnvelopeSchema(narrowed, "client_list_result", "zod")).toThrow(
      "approved zod form",
    );
    // The Zod added_unix widening back to a bare number.
    const widened = structuredClone(ZOD_CLIENT_LIST) as typeof ZOD_CLIENT_LIST;
    widened.properties.clients.items.properties.added_unix = {
      type: "number",
    } as (typeof ZOD_CLIENT_LIST)["properties"]["clients"]["items"]["properties"]["added_unix"];
    expect(() => normalizeEnvelopeSchema(widened, "client_list_result", "zod")).toThrow(
      "approved zod form",
    );
  });

  test("frame kinds share no reconciliations with the envelopes", () => {
    // enclave_error has no reconciled paths: reason is required on both
    // sides, so an optional Zod reason surfaces as a required-list diff.
    const rust = {
      type: "object",
      additionalProperties: false,
      properties: {
        type: { type: "string", const: "enclave_error" },
        reason: { type: "string" },
      },
      required: ["type", "reason"],
    };
    const zodOptionalReason = {
      type: "object",
      additionalProperties: {},
      properties: {
        type: { type: "string", const: "enclave_error" },
        reason: { type: "string" },
      },
      required: ["type"],
    };
    expect(
      diffSchemas(
        normalizeEnvelopeSchema(rust, "enclave_error", "rust"),
        normalizeEnvelopeSchema(zodOptionalReason, "enclave_error", "zod"),
      ),
    ).not.toEqual([]);
  });
});

// ---- the PolicyControl frames (ADR-0032: R5 strict-nested exception + new R4s) --

// The real shapes each derivation emits today for the policy push. The
// overlay is Option<PolicyOverlay> on the Rust side (a null arm around the
// strict all-optional object, uint64 ms fields); the Zod side is the
// generated strict PolicyOverlaySchema (no null arm, JS-safe ms bounds, the
// disabledTools caps).
const OVERLAY_BOOLS = [
  "cdpMode",
  "fileUploadEnabled",
  "handleDialogEnabled",
  "pageEvalEnabled",
  "confirmHighRiskClick",
  "confirmPageEval",
  "touchIdConfirm",
  "confirmTabClose",
  "warnPreciseSnapshot",
  "evalMask",
] as const;
const OVERLAY_MS = [
  "hostReverifyMs",
  "confirmGraceMs",
  "clickToastTimeoutMs",
  "evalToastTimeoutMs",
] as const;

function rustOverlayObject() {
  const properties: Record<string, unknown> = {};
  for (const f of OVERLAY_BOOLS) properties[f] = { type: ["boolean", "null"] };
  for (const f of OVERLAY_MS)
    properties[f] = { type: ["integer", "null"], format: "uint64", minimum: 0 };
  properties.disabledTools = { type: ["array", "null"], items: { type: "string" } };
  return { type: "object", additionalProperties: false, properties };
}

function zodOverlayObject() {
  const properties: Record<string, unknown> = {};
  for (const f of OVERLAY_BOOLS) properties[f] = { type: "boolean" };
  for (const f of OVERLAY_MS) properties[f] = { type: "integer", minimum: 0, maximum: JS_SAFE };
  properties.disabledTools = {
    type: "array",
    items: { type: "string", minLength: 1, maxLength: 128 },
    maxItems: 256,
  };
  return { type: "object", additionalProperties: false, properties };
}

function rustPolicyCurrent() {
  return {
    type: "object",
    additionalProperties: false,
    properties: {
      type: { type: "string", const: "policy_current" },
      ok: { type: "boolean" },
      baseline: { type: ["string", "null"] },
      sig: { type: ["string", "null"] },
      overlay: { anyOf: [rustOverlayObject(), { type: "null" }] },
      error: { type: ["string", "null"] },
    },
    required: ["type", "ok"],
  };
}

function zodPolicyCurrent() {
  return {
    type: "object",
    additionalProperties: {},
    properties: {
      type: { type: "string", const: "policy_current" },
      ok: { type: "boolean" },
      baseline: { type: "string", minLength: 1 },
      sig: { type: "string", minLength: 1 },
      overlay: zodOverlayObject(),
      error: { type: "string" },
    },
    required: ["type", "ok"],
  };
}

const RUST_LANG_CURRENT = {
  type: "object",
  additionalProperties: false,
  properties: {
    type: { type: "string", const: "lang_current" },
    value: { type: "string" },
    seq: { type: "integer", format: "uint64", minimum: 0 },
  },
  required: ["type", "value", "seq"],
};
const ZOD_LANG_CURRENT = {
  type: "object",
  additionalProperties: {},
  properties: {
    type: { type: "string", const: "lang_current" },
    value: { type: "string" },
    seq: { type: "integer", minimum: 0, maximum: JS_SAFE },
  },
  required: ["type", "value", "seq"],
};

describe("normalizeEnvelopeSchema on the policy frames", () => {
  test("R4 + R5: today's real policy_current derivations are equivalent", () => {
    expect(
      diffSchemas(
        normalizeEnvelopeSchema(rustPolicyCurrent(), "policy_current", "rust"),
        normalizeEnvelopeSchema(zodPolicyCurrent(), "policy_current", "zod"),
      ),
    ).toEqual([]);
  });

  test("R4: today's real lang_current derivations are equivalent", () => {
    expect(
      diffSchemas(
        normalizeEnvelopeSchema(RUST_LANG_CURRENT, "lang_current", "rust"),
        normalizeEnvelopeSchema(ZOD_LANG_CURRENT, "lang_current", "zod"),
      ),
    ).toEqual([]);
  });

  test("an unconsumed STRICT_ZOD_NODES pin is refused, not left inert", () => {
    // The zod frame losing its overlay property entirely: the strict-nested
    // exception pin (and the overlay reconciliation) would sit inert, so
    // both are named as leftovers.
    const noOverlay = zodPolicyCurrent();
    delete (noOverlay.properties as Record<string, unknown>).overlay;
    expect(() => normalizeEnvelopeSchema(noOverlay, "policy_current", "zod")).toThrow(
      /STRICT_ZOD_NODES \$\.properties\.overlay/,
    );
    // The rust walk never consults STRICT_ZOD_NODES (it is a zod-side
    // exception), so only the reconciliation leftover is named there.
    const rustNoOverlay = rustPolicyCurrent();
    delete (rustNoOverlay.properties as Record<string, unknown>).overlay;
    expect(() => normalizeEnvelopeSchema(rustNoOverlay, "policy_current", "rust")).toThrow(
      /RECONCILED_FIELDS \$\.properties\.overlay/,
    );
  });

  test("R5 exception: the zod overlay leaving its pinned strictness is refused", () => {
    // Going loose would let an unowned policy claim ride the frame - the
    // exact fail-open the STRICT_ZOD_NODES pin exists to refuse.
    const loosened = zodPolicyCurrent();
    (loosened.properties.overlay as Record<string, unknown>).additionalProperties = {};
    expect(() => normalizeEnvelopeSchema(loosened, "policy_current", "zod")).toThrow(
      "strict nested document",
    );
    const dropped = zodPolicyCurrent();
    delete (dropped.properties.overlay as Record<string, unknown>).additionalProperties;
    expect(() => normalizeEnvelopeSchema(dropped, "policy_current", "zod")).toThrow(
      "strict nested document",
    );
    // The exception is scoped to the overlay: the frame top level must stay
    // the approved looseObject.
    const strictTop = { ...zodPolicyCurrent(), additionalProperties: false };
    expect(() => normalizeEnvelopeSchema(strictTop, "policy_current", "zod")).toThrow(
      "looseObject",
    );
  });

  test("R5: the rust overlay losing deny_unknown_fields is refused", () => {
    const loosened = rustPolicyCurrent();
    const overlayUnion = loosened.properties.overlay as { anyOf: Record<string, unknown>[] };
    delete overlayUnion.anyOf[0]?.additionalProperties;
    expect(() => normalizeEnvelopeSchema(loosened, "policy_current", "rust")).toThrow(
      "deny_unknown_fields",
    );
  });

  test("R4 mutation: overlay bounds and null arms must keep each origin's form", () => {
    // The zod disabledTools losing its caps.
    const uncapped = zodPolicyCurrent();
    uncapped.properties.overlay.properties.disabledTools = {
      type: "array",
      items: { type: "string" },
    };
    expect(() => normalizeEnvelopeSchema(uncapped, "policy_current", "zod")).toThrow(
      "approved zod form",
    );
    // The rust overlay dropping a field's Option null arm.
    const changed = rustPolicyCurrent();
    const rustOverlay = (changed.properties.overlay as { anyOf: Record<string, unknown>[] })
      .anyOf[0] as { properties: Record<string, unknown> };
    rustOverlay.properties.cdpMode = { type: "boolean" };
    expect(() => normalizeEnvelopeSchema(changed, "policy_current", "rust")).toThrow(
      "approved rust form",
    );
  });

  test("R4 mutation: baseline/sig and seq must keep each origin's form", () => {
    // The zod baseline losing its non-empty guard (which is also the
    // canonical form, so only the refusal can catch it).
    const weakened = zodPolicyCurrent();
    (weakened.properties as Record<string, unknown>).baseline = { type: "string" };
    expect(() => normalizeEnvelopeSchema(weakened, "policy_current", "zod")).toThrow(
      "approved zod form",
    );
    // The rust seq widening to i64 (the JS-safe agreement gone).
    const widened = structuredClone(RUST_LANG_CURRENT);
    (widened.properties as Record<string, unknown>).seq = { type: "integer", format: "int64" };
    expect(() => normalizeEnvelopeSchema(widened, "lang_current", "rust")).toThrow(
      "approved rust form",
    );
  });
});

describe("splitTaggedUnionSchema", () => {
  const union = {
    oneOf: [
      {
        type: "object",
        properties: { type: { type: "string", const: "a" }, x: { $ref: "#/$defs/X" } },
        required: ["type"],
      },
      { type: "object", properties: { type: { type: "string", const: "b" } }, required: ["type"] },
    ],
    $defs: { X: { type: "string" } },
  };

  test("splits per tag and inlines $defs indirection", () => {
    const parts = splitTaggedUnionSchema(union);
    expect([...parts.keys()]).toEqual(["a", "b"]);
    const a = parts.get("a") as { properties: { x: unknown } };
    expect(diffSchemas(a.properties.x, { type: "string" })).toEqual([]);
  });

  test("refuses non-unions, tagless variants, and duplicate tags", () => {
    expect(() => splitTaggedUnionSchema({ type: "object" })).toThrow("oneOf");
    expect(() => splitTaggedUnionSchema({ oneOf: [{ type: "object", properties: {} }] })).toThrow(
      "type",
    );
    expect(() => splitTaggedUnionSchema({ oneOf: [union.oneOf[1], union.oneOf[1]] })).toThrow(
      "duplicate",
    );
  });
});
