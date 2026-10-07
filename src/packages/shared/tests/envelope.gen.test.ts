// The generated wire validators (envelope.gen.ts), exercised adversarially: hostile frames - unknown fields,
// missing required fields, type confusion, nested extras - must all be refused by the faithful base AND by the
// enforced validator the extension runs, and nothing may be silently defaulted. This is the runtime proof that
// the generated validators fail closed like the Rust serde parsers they are derived from; the per-entry
// differences between base and enforced are proved by the asymmetry gate (scripts/check-envelope.ts), not here.
// Every exported schema is under a case (the census at the end), so a reader or writer the generator adds or
// re-emits differently cannot sit outside this proof.

import { describe, expect, test } from "bun:test";
import { z } from "zod";
import * as generated from "../src/envelope.gen";
import { BROWSER_KEYS } from "../src/host.gen";

type Frame = Record<string, unknown>;

function schemaNamed(name: string): z.ZodType {
  const schema = (generated as Record<string, unknown>)[name];
  if (!(schema instanceof z.ZodType)) throw new Error(`envelope.gen.ts exports no schema ${name}`);
  return schema;
}

const entry: Frame = {
  name: "example-client",
  anchor: { kind: "hash", value: "abc123" },
  added_unix: 1700000000,
};

const row: Frame = {
  browser: "chrome",
  detected: true,
  state: { kind: "stale", detail: "launch path missing" },
  location: "/home/user/.config/google-chrome/NativeMessagingHosts/host.json",
};

const record: Frame = {
  entry: "record",
  ts_ms: 3000,
  kind: "pair_client",
  fields: "surface=cli outcome=ok",
};

const check = { value: "present", details: ["pid: 4242"] };
const report: Frame = {
  version: "1.2.3",
  platform: "linux/x86_64",
  lock_file: check,
  mcp_server: check,
  kill_switch: check,
  policy_baseline: check,
  host_key: "present (the OS credential store)",
  summary: "OK",
  healthy: true,
};

// One representative valid frame per reader pair (the faithful base and the enforced validator the extension
// runs); the harness below derives the hostile variants. The enforced validator runs too: a generator change
// that silently coerces (z.preprocess) is invisible to the asymmetry gate's structural view and is caught only
// here, behaviorally.
//   freeForm          -> fields the CONTRACT leaves unconstrained on the base (BridgeReq.args is validated
//                        per-op downstream, BridgeResp.data varies per op): any JSON is admitted there
//   enforcedFreeForm  -> the free-form fields the enforced validator leaves free too (not args: the asymmetry
//                        table narrows it to the OpArgs bag, proved by the gate)
//   enforcedStringOk  -> fields where a string is legal on the enforced side only (the id's forward-compat arm)
//   enforcedStrict    -> enforced validators that must ALSO refuse unknown fields (the envelopes and the signal
//                        frames; the control frames read loose under the asymmetry table's loose-frames rule)
//   enforcedRequired  -> fields the enforced side requires beyond the base (an ok-split's ok:true arm); the
//                        minimal-frame probe keeps them and proves dropping each fails only there
//   tag               -> the discriminant field when it is not `type` (an embedded item's own tag)
const WIRE_CASES: ReadonlyArray<{
  name: string;
  enforced: string;
  valid: Frame;
  required: readonly string[];
  freeForm?: readonly string[];
  enforcedFreeForm?: readonly string[];
  enforcedStringOk?: readonly string[];
  enforcedStrict?: boolean;
  enforcedRequired?: readonly string[];
  tag?: string;
}> = [
  {
    name: "BridgeReqWireSchema",
    enforced: "BridgeReqSchema",
    valid: { id: 1, op: "tab_list", browser: "brave", args: {} },
    required: ["id", "op", "args"],
    freeForm: ["args"],
    enforcedStringOk: ["id"],
    enforcedStrict: true,
  },
  {
    name: "BridgeRespWireSchema",
    enforced: "BridgeRespSchema",
    valid: { id: 1, ok: true, data: { any: "thing" }, error: "reason" },
    required: ["id", "ok"],
    freeForm: ["data"],
    enforcedFreeForm: ["data"],
    enforcedStringOk: ["id"],
    enforcedStrict: true,
  },
  {
    name: "BridgeCancelWireSchema",
    enforced: "BridgeCancelSchema",
    valid: { type: "cancel", id: 1 },
    required: ["type", "id"],
    enforcedStringOk: ["id"],
    enforcedStrict: true,
  },
  {
    name: "ClientEntryWireSchema",
    enforced: "TrustedClientSchema",
    valid: entry,
    required: ["name", "anchor", "added_unix"],
  },
  {
    name: "RegistrationRowWireSchema",
    enforced: "RegistrationRowSchema",
    valid: row,
    required: ["browser", "detected", "state", "location"],
  },
  {
    name: "AuditTrailEntryWireSchema",
    enforced: "AuditTrailEntrySchema",
    valid: record,
    required: ["entry", "ts_ms", "kind", "fields"],
    tag: "entry",
  },
  {
    name: "AuditTrailEntryWireSchema",
    enforced: "AuditTrailEntrySchema",
    valid: { entry: "unrecognized", text: "UNRECOGNIZED RECORD" },
    required: ["entry", "text"],
    tag: "entry",
  },
  {
    name: "HealthReportWireSchema",
    enforced: "HealthReportSchema",
    valid: report,
    required: Object.keys(report),
  },
  {
    name: "EnclaveProofWireSchema",
    enforced: "EnclaveProofFrameSchema",
    valid: { type: "enclave_proof", sig: "s", key_id: "k", pubkey: "p" },
    required: ["type", "sig", "key_id", "pubkey"],
  },
  {
    name: "EnclaveErrorWireSchema",
    enforced: "EnclaveErrorFrameSchema",
    valid: { type: "enclave_error", reason: "denied" },
    required: ["type", "reason"],
  },
  {
    name: "ClientListResultWireSchema",
    enforced: "ClientListResultSchema",
    valid: { type: "client_list_result", ok: true, enrolled: true, clients: [entry], error: "e" },
    required: ["type", "ok", "enrolled", "clients"],
  },
  {
    name: "ClientRevokeResultWireSchema",
    enforced: "ClientRevokeResultSchema",
    valid: { type: "client_revoke_result", ok: true, error: "e" },
    required: ["type", "ok"],
  },
  {
    name: "KillStatusResultWireSchema",
    enforced: "KillStatusResultSchema",
    valid: { type: "kill_status_result", ok: true, killed: false, error: "e" },
    // `killed` is an Option: `ok: false` deliberately carries no claim.
    required: ["type", "ok"],
  },
  {
    name: "RegistrationStatusResultWireSchema",
    enforced: "RegistrationStatusResultSchema",
    valid: { type: "registration_status_result", ok: true, browsers: [row] },
    required: ["type", "ok"],
    enforcedRequired: ["browsers"],
  },
  {
    name: "AuditReadResultWireSchema",
    enforced: "AuditReadResultSchema",
    valid: {
      type: "audit_read_result",
      ok: true,
      entries: [record],
      older: 1,
      path: "/tmp/audit.log",
    },
    required: ["type", "ok"],
    enforcedRequired: ["entries", "older", "path"],
  },
  {
    name: "DoctorReportResultWireSchema",
    enforced: "DoctorReportResultSchema",
    valid: { type: "doctor_report_result", ok: true, report },
    required: ["type", "ok"],
    enforcedRequired: ["report"],
  },
  {
    name: "BrowserRevokeResultWireSchema",
    enforced: "BrowserRevokeResultFrameSchema",
    valid: { type: "browser_revoke_result", ok: true },
    required: ["type", "ok"],
  },
  {
    name: "PolicyCurrentWireSchema",
    enforced: "PolicyCurrentFrameSchema",
    // The ok:true arm of the ok-split: baseline required, sig/overlay optional. error rides the ok:false arm
    // exclusively (the generated union refuses the mixtures); its coverage is the dedicated tests below.
    valid: {
      type: "policy_current",
      ok: true,
      baseline: "YmFzZQ==",
      sig: "c2ln",
      overlay: { pageEvalEnabled: false, confirmGraceMs: 1000, disabledTools: ["page_eval"] },
    },
    required: ["type", "ok"],
    enforcedRequired: ["baseline"],
  },
  {
    name: "PolicyRestrictResultWireSchema",
    enforced: "PolicyRestrictResultSchema",
    valid: { type: "policy_restrict_result", ok: true },
    required: ["type", "ok"],
  },
  {
    name: "LangCurrentWireSchema",
    enforced: "LangCurrentFrameSchema",
    valid: { type: "lang_current", value: "en", seq: 3 },
    required: ["type", "value", "seq"],
  },
  {
    name: "EnrollOptionsWireSchema",
    enforced: "EnrollOptionsFrameSchema",
    valid: {
      type: "enroll_options",
      challenge: "Y2hhbGxlbmdl",
      nonce: "nonce-0001",
      user_id: "dXNlci1pZA",
      user_name: "brave",
      exclude_credential_ids: ["Y3JlZC1h"],
    },
    required: ["type", "challenge", "nonce", "user_id", "user_name", "exclude_credential_ids"],
  },
  {
    name: "EnrollResultWireSchema",
    enforced: "EnrollResultFrameSchema",
    valid: { type: "enroll_result", ok: true, credential_id: "Y3JlZC1h" },
    required: ["type", "ok"],
    enforcedRequired: ["credential_id"],
  },
  {
    name: "PresenceRequestWireSchema",
    enforced: "PresenceRequestFrameSchema",
    valid: {
      type: "presence_request",
      challenge: "cHJlc2VuY2U",
      nonce: "nonce-0002",
      action: "pair_client:codex",
      allowed_credential_ids: ["Y3JlZC1h"],
    },
    required: ["type", "challenge", "nonce", "action", "allowed_credential_ids"],
  },
  {
    name: "PresenceResultWireSchema",
    enforced: "PresenceResultFrameSchema",
    valid: { type: "presence_result", ok: true },
    required: ["type", "ok"],
  },
];

// Values that violate whatever type the field had - including the SAME base family (a number where a string
// belongs, and vice versa; a bare element where an array belongs; a wrong-typed element inside the array; a
// fraction or a negative where the Rust side has a u64), so a validator that silently coerces or wraps
// (z.preprocess, z.coerce) or loses a bound fails here even though its derived JSON Schema still looks right.
function confusions(value: unknown): unknown[] {
  if (Array.isArray(value)) return [42, "hostile", true, ...value.slice(0, 1), [7], [null]];
  switch (typeof value) {
    case "string":
      return [7, true, { hostile: true }];
    case "number":
      return ["7", true, { hostile: true }, 1.5, -1];
    case "boolean":
      return ["true", 0, { hostile: true }];
    default:
      return [42, "hostile", true];
  }
}

/** Every type-confused variant of `frame`: each top-level field, and each field of a nested object one level
 * down (a writer's overlay, so a lost bound inside it is caught too). Keys in `skip` are left alone, and so
 * is a null (a written Option arm has no type to confuse). */
function confusedFrames(frame: Frame, skip: readonly string[] = []): [string, Frame][] {
  const out: [string, Frame][] = [];
  for (const [key, value] of Object.entries(frame)) {
    if (skip.includes(key)) continue;
    for (const hostile of confusions(value)) out.push([key, { ...frame, [key]: hostile }]);
    if (typeof value === "object" && value !== null && !Array.isArray(value)) {
      for (const [inner, innerValue] of Object.entries(value)) {
        if (innerValue === null) continue;
        for (const hostile of confusions(innerValue)) {
          out.push([`${key}.${inner}`, { ...frame, [key]: { ...value, [inner]: hostile } }]);
        }
      }
    }
  }
  return out;
}

/** Every integer field of `frame` at the top level and one nested level down, as the frames that set it to
 * `value`. The envelopes' integers are Rust u64s read as JS-safe integers: 0 and MAX_SAFE_INTEGER are in
 * range, 2^53 is not. */
function integerFrames(frame: Frame, value: number): Frame[] {
  const out: Frame[] = [];
  for (const [key, field] of Object.entries(frame)) {
    if (typeof field === "number") out.push({ ...frame, [key]: value });
    if (typeof field === "object" && field !== null && !Array.isArray(field)) {
      for (const [inner, innerValue] of Object.entries(field)) {
        if (typeof innerValue === "number")
          out.push({ ...frame, [key]: { ...field, [inner]: value } });
      }
    }
  }
  return out;
}

/** Every nested object of `frame` grown by an unknown field: the strict (deny_unknown_fields) claim must hold
 * one level down too, not only on the frame itself. Keys in `skip` (the free-form fields) are left alone. */
function nestedGrownFrames(frame: Frame, skip: readonly string[] = []): Frame[] {
  return Object.entries(frame)
    .filter(
      ([key, field]) =>
        !skip.includes(key) && typeof field === "object" && field !== null && !Array.isArray(field),
    )
    .map(([key, field]) => ({ ...frame, [key]: { ...(field as Frame), hostAdded: "field" } }));
}

/** Arbitrary JSON, for a field the contract leaves free-form. */
const ANY_JSON: readonly unknown[] = [
  7,
  "text",
  true,
  null,
  [],
  [1, "a"],
  {},
  { nested: { deep: [1] } },
];

describe("generated wire schemas and their enforced validators fail closed", () => {
  for (const {
    name,
    enforced: enforcedName,
    valid,
    required,
    freeForm,
    enforcedFreeForm,
    enforcedStringOk,
    enforcedStrict,
    enforcedRequired,
    tag = "type",
  } of WIRE_CASES) {
    const schema = schemaNamed(name);
    const enforced = schemaNamed(enforcedName);
    describe(name, () => {
      test("accepts the representative frame", () => {
        expect(schema.safeParse(valid).success).toBe(true);
        expect(enforced.safeParse(valid).success).toBe(true);
      });

      test("accepts the frame with optional fields omitted", () => {
        const keep = (keys: readonly string[]) =>
          Object.fromEntries(Object.entries(valid).filter(([key]) => keys.includes(key)));
        const enforcedKeys = [...required, ...(enforcedRequired ?? [])];
        expect(schema.safeParse(keep(required)).success).toBe(true);
        expect(enforced.safeParse(keep(enforcedKeys)).success).toBe(true);
        // Each enforced-required field: the base accepts its absence, the enforced side refuses it (the
        // ok-split's arm).
        for (const key of enforcedRequired ?? []) {
          const without = keep(enforcedKeys.filter((k) => k !== key));
          expect(schema.safeParse(without).success).toBe(true);
          expect(enforced.safeParse(without).success).toBe(false);
        }
      });

      test("rejects an unknown field (the loose control frames are proved by the gate)", () => {
        expect(schema.safeParse({ ...valid, extra: 1 }).success).toBe(false);
        if (enforcedStrict) {
          expect(enforced.safeParse({ ...valid, extra: 1 }).success).toBe(false);
        }
      });

      test("rejects non-objects", () => {
        for (const bad of [null, undefined, 7, "frame", [valid], true]) {
          expect(schema.safeParse(bad).success).toBe(false);
          expect(enforced.safeParse(bad).success).toBe(false);
        }
      });

      if (tag in valid) {
        test("the tag is load-bearing: a retagged frame is refused", () => {
          expect(schema.safeParse({ ...valid, [tag]: "evil" }).success).toBe(false);
          expect(enforced.safeParse({ ...valid, [tag]: "evil" }).success).toBe(false);
        });
      }

      for (const key of required) {
        test(`rejects the frame without required ${key}, and with it null`, () => {
          const { [key]: _dropped, ...rest } = valid;
          expect(schema.safeParse(rest).success).toBe(false);
          expect(enforced.safeParse(rest).success).toBe(false);
          // A required field is never an Option, so null is refused like any other wrong type (a free-form
          // field admits any JSON on the base, null included).
          if (!freeForm?.includes(key)) {
            expect(schema.safeParse({ ...valid, [key]: null }).success).toBe(false);
          }
          expect(enforced.safeParse({ ...valid, [key]: null }).success).toBe(false);
        });
      }

      // Every optional field is a serde Option: the faithful base keeps its null arm, the enforced validator
      // drops it (the asymmetry table's optional-only rule, which the gate proves from the base's inventory;
      // this pin holds the inventory itself).
      for (const key of Object.keys(valid)) {
        if (required.includes(key) || freeForm?.includes(key)) continue;
        test(`${key} is an Option: null admitted by the base, refused by the enforced validator`, () => {
          expect(schema.safeParse({ ...valid, [key]: null }).success).toBe(true);
          expect(enforced.safeParse({ ...valid, [key]: null }).success).toBe(false);
        });
      }

      if (integerFrames(valid, 0).length > 0) {
        test("every integer spans exactly the JS-safe non-negative integers", () => {
          for (const value of [0, Number.MAX_SAFE_INTEGER]) {
            for (const frame of integerFrames(valid, value)) {
              expect(schema.safeParse(frame).success).toBe(true);
              expect(enforced.safeParse(frame).success).toBe(true);
            }
          }
          for (const frame of integerFrames(valid, 2 ** 53)) {
            expect(schema.safeParse(frame).success).toBe(false);
            expect(enforced.safeParse(frame).success).toBe(false);
          }
        });
      }

      if (nestedGrownFrames(valid, freeForm).length > 0) {
        test("the base refuses an unknown field inside a nested object too", () => {
          for (const frame of nestedGrownFrames(valid, freeForm)) {
            expect(schema.safeParse(frame).success).toBe(false);
          }
        });
      }

      for (const key of freeForm ?? []) {
        test(`admits any JSON at the free-form ${key}`, () => {
          for (const value of ANY_JSON) {
            expect(schema.safeParse({ ...valid, [key]: value }).success).toBe(true);
            if (enforcedFreeForm?.includes(key)) {
              expect(enforced.safeParse({ ...valid, [key]: value }).success).toBe(true);
            }
          }
        });
      }

      test("rejects a type-confused field, at the top level and inside a nested object", () => {
        for (const [key, hostileFrame] of confusedFrames(valid, freeForm)) {
          expect(schema.safeParse(hostileFrame).success).toBe(false);
          if (typeof hostileFrame[key] === "string" && enforcedStringOk?.includes(key)) continue;
          expect(enforced.safeParse(hostileFrame).success).toBe(false);
        }
      });
    });
  }

  // The ok:true representative frames above cannot carry the ok:false arm's field, so each ok-split reader
  // gets its own confusion probe on that arm: both sides refuse a non-string there.
  test.each([
    ["PolicyCurrentWireSchema", "PolicyCurrentFrameSchema", "policy_current", "error"],
    [
      "RegistrationStatusResultWireSchema",
      "RegistrationStatusResultSchema",
      "registration_status_result",
      "error",
    ],
    [
      "PolicyRestrictResultWireSchema",
      "PolicyRestrictResultSchema",
      "policy_restrict_result",
      "error",
    ],
    ["EnrollResultWireSchema", "EnrollResultFrameSchema", "enroll_result", "reason"],
    ["PresenceResultWireSchema", "PresenceResultFrameSchema", "presence_result", "reason"],
    ["AuditReadResultWireSchema", "AuditReadResultSchema", "audit_read_result", "error"],
    ["DoctorReportResultWireSchema", "DoctorReportResultSchema", "doctor_report_result", "error"],
    [
      "BrowserRevokeResultWireSchema",
      "BrowserRevokeResultFrameSchema",
      "browser_revoke_result",
      "reason",
    ],
  ])(
    "%s: type confusion on the ok:false arm is refused on both sides",
    (base, enforced, type, field) => {
      const frame = { type, ok: false, [field]: "e" };
      expect(schemaNamed(enforced).safeParse(frame).success).toBe(true);
      for (const hostile of [7, true, { hostile: true }]) {
        expect(schemaNamed(base).safeParse({ ...frame, [field]: hostile }).success).toBe(false);
        expect(schemaNamed(enforced).safeParse({ ...frame, [field]: hostile }).success).toBe(false);
      }
    },
  );

  test("rejects nested extras (client entry, anchor, registration row) on the base", () => {
    const withEntryExtra = {
      type: "client_list_result",
      ok: true,
      enrolled: true,
      clients: [{ ...entry, extra: 1 }],
    };
    expect(generated.ClientListResultWireSchema.safeParse(withEntryExtra).success).toBe(false);
    const withAnchorExtra = { ...entry, anchor: { kind: "hash", value: "abc123", extra: 1 } };
    expect(generated.ClientEntryWireSchema.safeParse(withAnchorExtra).success).toBe(false);
    const withRowExtra = {
      type: "registration_status_result",
      ok: true,
      browsers: [{ ...row, extra: 1 }],
    };
    expect(generated.RegistrationStatusResultWireSchema.safeParse(withRowExtra).success).toBe(
      false,
    );
  });

  // The adjacently tagged enums embedded in the admin frames: every variant is admitted on both sides; a tag
  // outside the variants (content or not), a variant missing its content, or the content without its tag is
  // refused on both sides. (A variant carrying a field it does not declare is the loose-frames rule's business:
  // the base refuses it, the enforced reader admits it.)
  test.each<[string, string, string, unknown[], unknown[]]>([
    [
      "anchor",
      "ClientEntryWireSchema",
      "TrustedClientSchema",
      [
        { kind: "hash", value: "abc123" },
        { kind: "signer", value: "signer-key" },
      ],
      [{ kind: "root", value: "x" }, { kind: "hash" }, { value: "x" }, "hash:x"],
    ],
    [
      "state",
      "RegistrationRowWireSchema",
      "RegistrationRowSchema",
      [
        { kind: "missing" },
        { kind: "ok" },
        { kind: "stale", detail: "launch path missing" },
        { kind: "foreign", detail: "another host owns the manifest" },
        { kind: "unreadable", detail: "not JSON" },
      ],
      [
        { kind: "lost" },
        { kind: "lost", detail: "x" },
        { kind: "stale" },
        { kind: "foreign" },
        { kind: "unreadable" },
        { detail: "x" },
        "ok",
      ],
    ],
  ])(
    "the %s variants are admitted and anything else refused by %s and %s",
    (field, base, enforced, variants, hostile) => {
      const frame = field === "anchor" ? entry : row;
      for (const value of variants) {
        expect(schemaNamed(base).safeParse({ ...frame, [field]: value }).success).toBe(true);
        expect(schemaNamed(enforced).safeParse({ ...frame, [field]: value }).success).toBe(true);
      }
      for (const value of hostile) {
        expect(schemaNamed(base).safeParse({ ...frame, [field]: value }).success).toBe(false);
        expect(schemaNamed(enforced).safeParse({ ...frame, [field]: value }).success).toBe(false);
      }
    },
  );
});

// The generated WRITER schemas (extension->host; the Rust serde parser is the enforcing reader). The extension
// only uses their inferred types (constructor-site `satisfies`), but the schemas are the faithful Rust contract,
// so parsing the exact frames the extension constructs proves those constructor shapes are frames the host
// actually admits - and that the schemas kept deny_unknown_fields, so the `satisfies` claim is against a strict
// shape, not a lax one.
//   required      -> the fields the host's parser demands; the rest are Options
//   nullable      -> the Option fields, which the host's serializer may write as null (a writer keeps the null arm)
//   integerRange  -> the admitted range of the frame's integer fields when the host bounds it below the JS-safe
//                    non-negative integers (both ends admitted, one past each end refused)
const WRITER_CASES: ReadonlyArray<{
  name: string;
  valid: Frame;
  required: readonly string[];
  nullable?: readonly string[];
  integerRange?: readonly [number, number];
}> = [
  {
    name: "EnclaveChallengeWireSchema",
    valid: { type: "enclave_challenge", nonce: "n", context: "ext:id:pair" },
    required: ["type", "nonce"],
    nullable: ["context"],
  },
  { name: "EnclaveRevokeWireSchema", valid: { type: "enclave_revoke" }, required: ["type"] },
  { name: "ClientListWireSchema", valid: { type: "client_list" }, required: ["type"] },
  {
    name: "ClientRevokeWireSchema",
    valid: { type: "client_revoke", name: "example-client" },
    required: ["type", "name"],
  },
  { name: "KillStatusWireSchema", valid: { type: "kill_status" }, required: ["type"] },
  { name: "KillEngageWireSchema", valid: { type: "kill_engage" }, required: ["type"] },
  { name: "KillReleaseWireSchema", valid: { type: "kill_release" }, required: ["type"] },
  {
    name: "AuditEventWireSchema",
    valid: {
      type: "audit_event",
      kind: "confirm_denied",
      tool: "page_eval",
      cid: "c-1",
      name: "example-client",
      outcome: "denied",
      detail: "the user declined",
    },
    required: ["type", "kind"],
    nullable: ["tool", "cid", "name", "outcome", "detail"],
  },
  {
    name: "RegistrationStatusWireSchema",
    valid: { type: "registration_status" },
    required: ["type"],
  },
  {
    name: "RegistrationRepairWireSchema",
    valid: { type: "registration_repair", browsers: ["chrome", "brave"] },
    required: ["type"],
    nullable: ["browsers"],
  },
  {
    name: "AuditReadWireSchema",
    valid: { type: "audit_read", limit: 100 },
    required: ["type"],
    nullable: ["limit"],
    integerRange: [1, 1000],
  },
  { name: "DoctorReportWireSchema", valid: { type: "doctor_report" }, required: ["type"] },
  { name: "BrowserRevokeWireSchema", valid: { type: "browser_revoke" }, required: ["type"] },
  { name: "PolicyGetWireSchema", valid: { type: "policy_get" }, required: ["type"] },
  {
    name: "PolicyRestrictWireSchema",
    // The overlay's own Options carry their null arm too (the host reads them as serde Options).
    valid: {
      type: "policy_restrict",
      overlay: { pageEvalEnabled: false, confirmGraceMs: 1000, disabledTools: null, cdpMode: null },
    },
    required: ["type", "overlay"],
  },
  { name: "LangGetWireSchema", valid: { type: "lang_get" }, required: ["type"] },
  {
    name: "LangSetWireSchema",
    valid: { type: "lang_set", value: "zh_CN" },
    required: ["type", "value"],
  },
  { name: "EnrollBeginWireSchema", valid: { type: "enroll_begin" }, required: ["type"] },
  {
    name: "EnrollFinishWireSchema",
    valid: { type: "enroll_finish", attestation_object: "YXR0", client_data_json: "Y2Rq" },
    required: ["type", "attestation_object", "client_data_json"],
  },
  {
    name: "PresenceAssertWireSchema",
    valid: {
      type: "presence_assert",
      authenticator_data: "YXV0aA",
      client_data_json: "Y2Rq",
      credential_id: "Y3JlZC1h",
      signature: "c2ln",
    },
    required: ["type", "authenticator_data", "client_data_json", "credential_id", "signature"],
  },
  {
    name: "PresenceConfirmWireSchema",
    valid: { type: "presence_confirm", nonce: "nonce-0002" },
    required: ["type", "nonce"],
  },
  {
    name: "PresenceBeginWireSchema",
    valid: {
      type: "presence_begin",
      action: "pair_client:codex",
      origin: "chrome-extension://example",
    },
    required: ["type", "action", "origin"],
  },
];

describe("generated writer schemas admit exactly the frames the extension constructs", () => {
  for (const { name, valid, required, nullable, integerRange } of WRITER_CASES) {
    const schema = schemaNamed(name);
    const [min, max] = integerRange ?? [0, Number.MAX_SAFE_INTEGER];
    describe(String(valid.type), () => {
      test("accepts the constructed frame and its required-only subset", () => {
        expect(schema.safeParse(valid).success).toBe(true);
        const requiredOnly = Object.fromEntries(
          Object.entries(valid).filter(([key]) => required.includes(key)),
        );
        expect(schema.safeParse(requiredOnly).success).toBe(true);
      });
      test("stays strict: an unknown field is refused (deny_unknown_fields kept), nested objects included", () => {
        expect(schema.safeParse({ ...valid, extra: 1 }).success).toBe(false);
        for (const frame of nestedGrownFrames(valid)) {
          expect(schema.safeParse(frame).success).toBe(false);
        }
      });
      test("the tag is load-bearing: a retagged frame is refused", () => {
        expect(schema.safeParse({ ...valid, type: "evil" }).success).toBe(false);
      });
      if (integerFrames(valid, 0).length > 0) {
        test("every integer spans exactly its range", () => {
          for (const value of [min, max]) {
            for (const frame of integerFrames(valid, value)) {
              expect(schema.safeParse(frame).success).toBe(true);
            }
          }
          for (const value of [min - 1, max + 1]) {
            for (const frame of integerFrames(valid, value)) {
              expect(schema.safeParse(frame).success).toBe(false);
            }
          }
        });
      }
      for (const key of required) {
        test(`rejects the frame without required ${key}`, () => {
          const { [key]: _dropped, ...rest } = valid;
          expect(schema.safeParse(rest).success).toBe(false);
        });
      }
      test("rejects a type-confused field, at the top level and inside a nested object", () => {
        for (const [, hostileFrame] of confusedFrames(valid)) {
          expect(schema.safeParse(hostileFrame).success).toBe(false);
        }
      });
      test("null is admitted exactly on the Option fields", () => {
        for (const key of Object.keys(valid)) {
          expect(schema.safeParse({ ...valid, [key]: null }).success).toBe(
            nullable?.includes(key) ?? false,
          );
        }
      });
    });
  }
});

// The repair writer's browser list is the catalogue's own key set (browsers.rs Browser::ALL, emitted into
// host.gen.ts as BROWSER_KEYS) and never empty: a repair of no browser is not a request the host answers.
test("registration_repair admits every catalogue browser key and nothing else, never an empty list", () => {
  const schema = generated.RegistrationRepairWireSchema;
  const frame = (browsers: unknown) => ({ type: "registration_repair", browsers });
  for (const key of BROWSER_KEYS) expect(schema.safeParse(frame([key])).success).toBe(true);
  expect(schema.safeParse(frame([...BROWSER_KEYS])).success).toBe(true);
  expect(schema.safeParse(frame([])).success).toBe(false);
  expect(schema.safeParse(frame(["firefox"])).success).toBe(false);
  expect(schema.safeParse(frame(["chrome", "firefox"])).success).toBe(false);
});

test("every schema envelope.gen.ts exports is under a reader or writer case", () => {
  const exported = Object.entries(generated)
    .filter(([, value]) => value instanceof z.ZodType)
    .map(([name]) => name)
    .sort();
  const covered = [
    ...new Set([
      ...WIRE_CASES.flatMap((wire) => [wire.name, wire.enforced]),
      ...WRITER_CASES.map((writer) => writer.name),
    ]),
  ].sort();
  expect(exported).toEqual(covered);
});
