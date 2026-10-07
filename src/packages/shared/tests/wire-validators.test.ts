// The generated wire validators (generated/envelope.ts), exercised adversarially: hostile frames - unknown fields,
// missing required fields, type confusion, nested extras - must all be refused by the faithful base AND by the
// enforced validator the extension runs, and nothing may be silently defaulted. This is the runtime proof that
// the generated validators fail closed like the Rust serde parsers they are derived from; the per-entry
// differences between base and enforced are proved by the asymmetry gate (scripts/check-envelope.ts), not here.

import { describe, expect, test } from "bun:test";
import type { z } from "zod";
import {
  AuditEventWireSchema,
  BridgeReqSchema,
  BridgeReqWireSchema,
  BridgeRespSchema,
  BridgeRespWireSchema,
  ClientEntryWireSchema,
  ClientListResultSchema,
  ClientListResultWireSchema,
  ClientListWireSchema,
  ClientRevokeResultSchema,
  ClientRevokeResultWireSchema,
  ClientRevokeWireSchema,
  EnclaveChallengeWireSchema,
  EnclaveErrorFrameSchema,
  EnclaveErrorWireSchema,
  EnclaveProofFrameSchema,
  EnclaveProofWireSchema,
  EnclaveRevokeWireSchema,
  KillEngageWireSchema,
  KillReleaseWireSchema,
  KillStatusResultSchema,
  KillStatusResultWireSchema,
  KillStatusWireSchema,
  LangCurrentFrameSchema,
  LangCurrentWireSchema,
  LangGetWireSchema,
  LangSetWireSchema,
  PolicyCurrentFrameSchema,
  PolicyCurrentWireSchema,
  PolicyGetWireSchema,
  TrustedClientSchema,
} from "../generated/envelope";

type Frame = Record<string, unknown>;

const entry: Frame = {
  name: "example-client",
  anchor: { kind: "hash", value: "abc123" },
  added_unix: 1700000000,
};

// One representative valid frame per generated schema; the harness below derives the hostile variants. The
// enforced validator runs too: a generator change that silently coerces (z.preprocess) is invisible to the
// asymmetry gate's structural view and is caught only here, behaviorally.
//   freeForm          -> fields the CONTRACT leaves unconstrained (BridgeReq.args is validated per-op
//                        downstream, BridgeResp.data varies per op), so type confusion on them is legal here
//   enforced          -> the validator the extension actually runs
//   enforcedStringOk  -> fields where a string is legal on the enforced side only (the id's forward-compat arm)
//   enforcedStrict    -> enforced validators that must ALSO refuse unknown fields (the envelopes; the control
//                        frames read loose under the asymmetry table's loose-frames rule)
//   enforcedRequired  -> fields the enforced side requires beyond the base (policy_current's ok:true arm needs
//                        baseline); the minimal-frame probe keeps them and proves dropping each fails only there
const WIRE_CASES: ReadonlyArray<{
  name: string;
  schema: z.ZodType;
  enforced: z.ZodType;
  valid: Frame;
  required: readonly string[];
  freeForm?: readonly string[];
  enforcedStringOk?: readonly string[];
  enforcedStrict?: boolean;
  enforcedRequired?: readonly string[];
}> = [
  {
    name: "BridgeReqWireSchema",
    schema: BridgeReqWireSchema,
    enforced: BridgeReqSchema,
    valid: { id: 1, op: "tab_list", browser: "brave", args: {} },
    required: ["id", "op", "args"],
    freeForm: ["args"],
    enforcedStringOk: ["id"],
    enforcedStrict: true,
  },
  {
    name: "BridgeRespWireSchema",
    schema: BridgeRespWireSchema,
    enforced: BridgeRespSchema,
    valid: { id: 1, ok: true, data: { any: "thing" }, error: "reason" },
    required: ["id", "ok"],
    freeForm: ["data"],
    enforcedStringOk: ["id"],
    enforcedStrict: true,
  },
  {
    name: "ClientEntryWireSchema",
    schema: ClientEntryWireSchema,
    enforced: TrustedClientSchema,
    valid: entry,
    required: ["name", "anchor", "added_unix"],
  },
  {
    name: "EnclaveProofWireSchema",
    schema: EnclaveProofWireSchema,
    enforced: EnclaveProofFrameSchema,
    valid: { type: "enclave_proof", sig: "s", key_id: "k", pubkey: "p" },
    required: ["type", "sig", "key_id", "pubkey"],
  },
  {
    name: "EnclaveErrorWireSchema",
    schema: EnclaveErrorWireSchema,
    enforced: EnclaveErrorFrameSchema,
    valid: { type: "enclave_error", reason: "denied" },
    required: ["type", "reason"],
  },
  {
    name: "ClientListResultWireSchema",
    schema: ClientListResultWireSchema,
    enforced: ClientListResultSchema,
    valid: { type: "client_list_result", ok: true, enrolled: true, clients: [entry], error: "e" },
    required: ["type", "ok", "enrolled", "clients"],
  },
  {
    name: "ClientRevokeResultWireSchema",
    schema: ClientRevokeResultWireSchema,
    enforced: ClientRevokeResultSchema,
    valid: { type: "client_revoke_result", ok: true, error: "e" },
    required: ["type", "ok"],
  },
  {
    name: "KillStatusResultWireSchema",
    schema: KillStatusResultWireSchema,
    enforced: KillStatusResultSchema,
    valid: { type: "kill_status_result", ok: true, killed: false, error: "e" },
    // `killed` is an Option: `ok: false` deliberately carries no claim.
    required: ["type", "ok"],
  },
  {
    name: "PolicyCurrentWireSchema",
    schema: PolicyCurrentWireSchema,
    enforced: PolicyCurrentFrameSchema,
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
    name: "LangCurrentWireSchema",
    schema: LangCurrentWireSchema,
    enforced: LangCurrentFrameSchema,
    valid: { type: "lang_current", value: "en", seq: 3 },
    required: ["type", "value", "seq"],
  },
];

// Values that violate whatever type the field had - including the SAME base family (a number where a string
// belongs, and vice versa; a bare element where an array belongs), so a validator that silently coerces or
// wraps (z.preprocess, z.coerce) fails here even though its derived JSON Schema still looks right.
function confusions(value: unknown): unknown[] {
  if (Array.isArray(value)) return [42, "hostile", true, ...value.slice(0, 1)];
  switch (typeof value) {
    case "string":
      return [7, true, { hostile: true }];
    case "number":
      return ["7", true, { hostile: true }];
    case "boolean":
      return ["true", 0, { hostile: true }];
    default:
      return [42, "hostile", true];
  }
}

describe("generated wire schemas and their enforced validators fail closed", () => {
  for (const {
    name,
    schema,
    enforced,
    valid,
    required,
    freeForm,
    enforcedStringOk,
    enforcedStrict,
    enforcedRequired,
  } of WIRE_CASES) {
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
        // Each enforced-required field: the base accepts its absence, the enforced side refuses it (a pinned
        // refinement, e.g. the ok-split).
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

      for (const key of required) {
        test(`rejects the frame without required ${key}`, () => {
          const { [key]: _dropped, ...rest } = valid;
          expect(schema.safeParse(rest).success).toBe(false);
          expect(enforced.safeParse(rest).success).toBe(false);
        });
      }

      for (const [key, value] of Object.entries(valid)) {
        if (freeForm?.includes(key)) continue;
        test(`rejects a type-confused ${key}`, () => {
          for (const hostile of confusions(value)) {
            expect(schema.safeParse({ ...valid, [key]: hostile }).success).toBe(false);
            if (typeof hostile === "string" && enforcedStringOk?.includes(key)) continue;
            expect(enforced.safeParse({ ...valid, [key]: hostile }).success).toBe(false);
          }
        });
      }
    });
  }

  test("policy_current error: type confusion on the ok:false arm is refused on both sides", () => {
    // The ok:true representative frame above cannot carry `error`, so the ok:false arm gets its own confusion
    // probe: both sides refuse a non-string.
    const base = { type: "policy_current", ok: false, error: "e" };
    expect(PolicyCurrentFrameSchema.safeParse(base).success).toBe(true);
    for (const hostile of [7, true, { hostile: true }]) {
      expect(PolicyCurrentWireSchema.safeParse({ ...base, error: hostile }).success).toBe(false);
      expect(PolicyCurrentFrameSchema.safeParse({ ...base, error: hostile }).success).toBe(false);
    }
  });

  test("rejects nested extras (client entry, anchor) on the base", () => {
    const withEntryExtra = {
      type: "client_list_result",
      ok: true,
      enrolled: true,
      clients: [{ ...entry, extra: 1 }],
    };
    expect(ClientListResultWireSchema.safeParse(withEntryExtra).success).toBe(false);
    const withAnchorExtra = { ...entry, anchor: { kind: "hash", value: "abc123", extra: 1 } };
    expect(ClientEntryWireSchema.safeParse(withAnchorExtra).success).toBe(false);
  });

  test("rejects an anchor outside the two variants on both sides (type confusion on the tag)", () => {
    for (const anchor of [
      { kind: "root", value: "x" },
      { kind: "hash" },
      { value: "x" },
      "hash:x",
    ]) {
      expect(ClientEntryWireSchema.safeParse({ ...entry, anchor }).success).toBe(false);
      expect(TrustedClientSchema.safeParse({ ...entry, anchor }).success).toBe(false);
    }
  });
});

// The generated WRITER schemas (extension->host; the Rust serde parser is the enforcing reader). The extension
// only uses their inferred types (constructor-site `satisfies`), but the schemas are the faithful Rust contract,
// so parsing the exact frames the extension constructs proves those constructor shapes are frames the host
// actually admits - and that the schemas kept deny_unknown_fields, so the `satisfies` claim is against a strict
// shape, not a lax one.
describe("generated writer schemas admit exactly the frames the extension constructs", () => {
  const WRITER_CASES: ReadonlyArray<{ schema: z.ZodType; valid: Frame }> = [
    {
      schema: EnclaveChallengeWireSchema,
      valid: { type: "enclave_challenge", nonce: "n", context: "ext:id:pair" },
    },
    { schema: EnclaveRevokeWireSchema, valid: { type: "enclave_revoke" } },
    { schema: ClientListWireSchema, valid: { type: "client_list" } },
    { schema: ClientRevokeWireSchema, valid: { type: "client_revoke", name: "example-client" } },
    { schema: KillStatusWireSchema, valid: { type: "kill_status" } },
    { schema: KillEngageWireSchema, valid: { type: "kill_engage" } },
    { schema: KillReleaseWireSchema, valid: { type: "kill_release" } },
    {
      schema: AuditEventWireSchema,
      valid: { type: "audit_event", kind: "confirm_denied", tool: "page_eval", cid: "c-1" },
    },
    { schema: PolicyGetWireSchema, valid: { type: "policy_get" } },
    { schema: LangGetWireSchema, valid: { type: "lang_get" } },
    { schema: LangSetWireSchema, valid: { type: "lang_set", value: "zh_CN" } },
  ];

  for (const { schema, valid } of WRITER_CASES) {
    describe(String(valid.type), () => {
      test("accepts the constructed frame", () => {
        expect(schema.safeParse(valid).success).toBe(true);
      });
      test("stays strict: an unknown field is refused (deny_unknown_fields kept)", () => {
        expect(schema.safeParse({ ...valid, extra: 1 }).success).toBe(false);
      });
      test("the tag is load-bearing: a retagged frame is refused", () => {
        expect(schema.safeParse({ ...valid, type: "evil" }).success).toBe(false);
      });
    });
  }
});
