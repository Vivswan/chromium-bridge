// Semantics of the generated policy contract (policy.gen.ts): the deny
// baseline, the direction table, the salvage posture, and the strict
// document validator. The SOURCE is the Rust core
// (src/packages/core/src/policy/mod.rs); faithful generation is enforced by
// CI regenerating and diffing the checked-in file (`moon run gen`
// idempotency), so these tests own the semantics, not the provenance.

import { describe, expect, test } from "bun:test";
import { POLICY_GOLDEN_FIXTURE } from "../src/enclave-fixture.gen";
import {
  DISABLED_TOOL_NAME_MAX_BYTES,
  DISABLED_TOOLS_MAX_ENTRIES,
  isPolicyFieldName,
  POLICY_DEFAULTS,
  POLICY_DIRECTIONS,
  POLICY_DOC_VERSION,
  POLICY_DOMAIN,
  POLICY_FIELDS,
  POLICY_REVISION_MAX,
  PolicyDocSchema,
  PolicyOverlaySchema,
  PolicyValuesSchema,
  parseStoredPolicyValues,
  salvagePolicyValues,
} from "../src/policy.gen";

// A well-formed v1 document: the deny-baseline values under default scoping.
const wellFormedDoc = () => ({
  v: POLICY_DOC_VERSION,
  revision: 1,
  touched: ["pageEvalEnabled"],
  ...POLICY_DEFAULTS,
});

describe("POLICY_FIELDS", () => {
  test("names are unique and recognized by isPolicyFieldName", () => {
    expect(POLICY_FIELDS.length).toBe(15);
    expect(new Set(POLICY_FIELDS).size).toBe(POLICY_FIELDS.length);
    for (const field of POLICY_FIELDS) expect(isPolicyFieldName(field)).toBe(true);
    expect(isPolicyFieldName("requireEnrollment")).toBe(false);
    expect(isPolicyFieldName("uiLanguage")).toBe(false);
  });
});

describe("POLICY_DIRECTIONS", () => {
  test("every field has a direction and nothing else does", () => {
    expect(Object.keys(POLICY_DIRECTIONS).sort()).toEqual([...POLICY_FIELDS].sort());
  });

  test("hostReverifyMs keeps its custom zero-top order", () => {
    // The one a naive numeric comparator gets backwards: 0 = never
    // re-verify = MOST permissive, so it tops the scale.
    expect(POLICY_DIRECTIONS.hostReverifyMs).toBe("growsPermissiveZeroTop");
  });
});

describe("POLICY_DEFAULTS", () => {
  test("is the deny baseline: pageEvalEnabled off, unlike settings.ts", () => {
    // The deliberate divergence from the legacy settings.ts default of
    // true (ADR-0032 decision 4): with no applied policy, page_eval is off.
    expect(POLICY_DEFAULTS.pageEvalEnabled).toBe(false);
  });

  test("is deep-frozen, nested array included", () => {
    expect(Object.isFrozen(POLICY_DEFAULTS)).toBe(true);
    expect(Object.isFrozen(POLICY_DEFAULTS.disabledTools)).toBe(true);
  });
});

describe("salvagePolicyValues", () => {
  test("a non-object bag yields the defaults", () => {
    expect(salvagePolicyValues(null)).toEqual(POLICY_DEFAULTS);
    expect(salvagePolicyValues("junk")).toEqual(POLICY_DEFAULTS);
  });

  test("field-by-field: bad fields fall back, healthy fields survive", () => {
    const salvaged = salvagePolicyValues({
      ...POLICY_DEFAULTS,
      cdpMode: true,
      confirmGraceMs: "corrupted",
      disabledTools: ["page_upload"],
    });
    expect(salvaged.cdpMode).toBe(true);
    expect(salvaged.confirmGraceMs).toBe(POLICY_DEFAULTS.confirmGraceMs);
    expect(salvaged.disabledTools).toEqual(["page_upload"]);
  });

  test("an unknown key is dropped", () => {
    const salvaged = salvagePolicyValues({ ...POLICY_DEFAULTS, requireEnrollment: false });
    expect("requireEnrollment" in salvaged).toBe(false);
    expect(Object.keys(salvaged).sort()).toEqual([...POLICY_FIELDS].sort());
  });
});

describe("parseStoredPolicyValues", () => {
  test("returns the exact values on a valid bag", () => {
    const bag = { ...POLICY_DEFAULTS, cdpMode: true, disabledTools: ["page_upload"] };
    expect(parseStoredPolicyValues(bag)).toEqual(bag);
  });

  test("returns null on any failure, never a salvage", () => {
    // A per-field fallback here would move the corrupt field toward its
    // permissive pole - the ratchet anchor must be exact or absent.
    expect(parseStoredPolicyValues({ ...POLICY_DEFAULTS, confirmGraceMs: "corrupted" })).toBeNull();
    expect(parseStoredPolicyValues(null)).toBeNull();
    expect(parseStoredPolicyValues("junk")).toBeNull();
    expect(parseStoredPolicyValues({ ...POLICY_DEFAULTS, requireEnrollment: false })).toBeNull();
  });
});

describe("PolicyDocSchema", () => {
  test("accepts a well-formed document", () => {
    const parsed = PolicyDocSchema.parse(wellFormedDoc());
    expect(parsed.revision).toBe(1);
    expect(parsed.touched).toEqual(["pageEvalEnabled"]);
  });

  test("rejects an unknown field, fail-closed", () => {
    expect(PolicyDocSchema.safeParse({ ...wellFormedDoc(), surprise: true }).success).toBe(false);
  });

  test("rejects a revision beyond the JS-safe bound", () => {
    expect(POLICY_REVISION_MAX).toBe(Number.MAX_SAFE_INTEGER);
    expect(
      PolicyDocSchema.safeParse({ ...wellFormedDoc(), revision: POLICY_REVISION_MAX }).success,
    ).toBe(true);
    expect(
      PolicyDocSchema.safeParse({ ...wellFormedDoc(), revision: POLICY_REVISION_MAX + 1 }).success,
    ).toBe(false);
  });

  test("rejects a touched set naming the retired requireEnrollment", () => {
    expect(
      PolicyDocSchema.safeParse({ ...wellFormedDoc(), touched: ["requireEnrollment"] }).success,
    ).toBe(false);
  });

  test("rejects a foreign document version", () => {
    expect(PolicyDocSchema.safeParse({ ...wellFormedDoc(), v: 2 }).success).toBe(false);
    expect(PolicyDocSchema.safeParse({ ...wellFormedDoc(), v: 0 }).success).toBe(false);
  });

  test("rejects millisecond fields beyond the JS-safe bound (Rust parity)", () => {
    // The Rust parser bounds these to JS_SAFE_INT_MAX for exactly this
    // equivalence; a value only one side accepts would sign host-side and
    // brick the push extension-side.
    for (const field of [
      "hostReverifyMs",
      "confirmGraceMs",
      "clickToastTimeoutMs",
      "evalToastTimeoutMs",
    ]) {
      expect(
        PolicyDocSchema.safeParse({ ...wellFormedDoc(), [field]: Number.MAX_SAFE_INTEGER }).success,
      ).toBe(true);
      expect(
        PolicyDocSchema.safeParse({ ...wellFormedDoc(), [field]: Number.MAX_SAFE_INTEGER + 1 })
          .success,
      ).toBe(false);
    }
  });

  test("bounds disabledTools entries (Rust parity)", () => {
    const withTools = (disabledTools: string[]) => ({ ...wellFormedDoc(), disabledTools });
    const atCap = Array.from({ length: DISABLED_TOOLS_MAX_ENTRIES }, (_, i) => `tool_${i}`);
    expect(PolicyDocSchema.safeParse(withTools(atCap)).success).toBe(true);
    expect(PolicyDocSchema.safeParse(withTools([...atCap, "one_more"])).success).toBe(false);
    expect(
      PolicyValuesSchema.safeParse({
        ...POLICY_DEFAULTS,
        disabledTools: ["a".repeat(DISABLED_TOOL_NAME_MAX_BYTES)],
      }).success,
    ).toBe(true);
    expect(
      PolicyValuesSchema.safeParse({
        ...POLICY_DEFAULTS,
        disabledTools: ["a".repeat(DISABLED_TOOL_NAME_MAX_BYTES + 1)],
      }).success,
    ).toBe(false);
    expect(PolicyValuesSchema.safeParse({ ...POLICY_DEFAULTS, disabledTools: [""] }).success).toBe(
      false,
    );
  });
});

describe("PolicyOverlaySchema", () => {
  test("accepts the empty overlay and any all-owned subset", () => {
    expect(PolicyOverlaySchema.safeParse({}).success).toBe(true);
    expect(
      PolicyOverlaySchema.safeParse({
        pageEvalEnabled: false,
        confirmGraceMs: 0,
        disabledTools: ["page_eval"],
      }).success,
    ).toBe(true);
  });

  test("rejects a field the catalogue does not own, fail-closed", () => {
    expect(PolicyOverlaySchema.safeParse({ requireEnrollment: false }).success).toBe(false);
    expect(PolicyOverlaySchema.safeParse({ uiLanguage: "en" }).success).toBe(false);
  });

  test("bounds millisecond fields and disabledTools like the document (Rust parity)", () => {
    expect(PolicyOverlaySchema.safeParse({ confirmGraceMs: Number.MAX_SAFE_INTEGER }).success).toBe(
      true,
    );
    expect(
      PolicyOverlaySchema.safeParse({ confirmGraceMs: Number.MAX_SAFE_INTEGER + 1 }).success,
    ).toBe(false);
    expect(PolicyOverlaySchema.safeParse({ hostReverifyMs: -1 }).success).toBe(false);
    expect(PolicyOverlaySchema.safeParse({ disabledTools: [""] }).success).toBe(false);
    expect(
      PolicyOverlaySchema.safeParse({
        disabledTools: ["a".repeat(DISABLED_TOOL_NAME_MAX_BYTES + 1)],
      }).success,
    ).toBe(false);
  });

  test("never invents a value for an absent field", () => {
    expect(PolicyOverlaySchema.parse({})).toEqual({});
  });
});

// The POLICY_DOMAIN golden vectors (enclave-fixture.gen.ts): the byte-level
// proof that the Rust signer and this side's verify-then-parse pipeline
// agree. Phase 3's extension golden test replays these through its own
// verifier; here the fixture's internal consistency and the document parse
// are pinned at the shared layer.
describe("POLICY_GOLDEN_FIXTURE", () => {
  const b64ToBytes = (b64: string) => Uint8Array.from(Buffer.from(b64, "base64"));
  const hexToBytes = (hex: string) => Uint8Array.from(Buffer.from(hex, "hex"));

  test("each message is POLICY_DOMAIN || 0x00 || the exact document bytes", () => {
    for (const vector of POLICY_GOLDEN_FIXTURE.vectors) {
      const domain = new TextEncoder().encode(POLICY_DOMAIN);
      const doc = b64ToBytes(vector.docB64);
      const expected = new Uint8Array([...domain, 0, ...doc]);
      expect(hexToBytes(vector.messageHex)).toEqual(expected);
    }
  });

  test("each document strict-parses under the generated PolicyDocSchema", () => {
    const revisions = POLICY_GOLDEN_FIXTURE.vectors.map((vector) => {
      const doc = PolicyDocSchema.parse(
        JSON.parse(new TextDecoder().decode(b64ToBytes(vector.docB64))),
      );
      expect(doc.v).toBe(POLICY_DOC_VERSION);
      for (const field of doc.touched) expect(isPolicyFieldName(field)).toBe(true);
      return doc.revision;
    });
    // The fixture carries distinct revisions, so replay-ordering tests have
    // a lower and a higher baseline to work with.
    expect(new Set(revisions).size).toBe(revisions.length);
  });

  test("each signature verifies over the message bytes (WebCrypto, P-256/SHA-256)", async () => {
    const key = await crypto.subtle.importKey(
      "raw",
      b64ToBytes(POLICY_GOLDEN_FIXTURE.pubkeyB64),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    for (const vector of POLICY_GOLDEN_FIXTURE.vectors) {
      const ok = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        key,
        b64ToBytes(vector.sigB64),
        hexToBytes(vector.messageHex),
      );
      expect(ok).toBe(true);
      // And a flipped byte in the document breaks it: the signature really
      // covers these exact bytes.
      const tampered = hexToBytes(vector.messageHex);
      const last = tampered.length - 1;
      tampered[last] = (tampered[last] ?? 0) ^ 1;
      expect(
        await crypto.subtle.verify(
          { name: "ECDSA", hash: "SHA-256" },
          key,
          b64ToBytes(vector.sigB64),
          tampered,
        ),
      ).toBe(false);
    }
  });
});
