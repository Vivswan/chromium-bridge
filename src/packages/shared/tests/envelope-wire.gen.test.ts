// The generated base wire schemas (envelope-wire.gen.ts), exercised
// adversarially: hostile frames - unknown fields, missing required fields,
// type confusion, nested extras - must all be refused, and nothing may be
// silently defaulted. This is the runtime proof that the json-schema-to-zod
// output fails closed like the Rust serde parsers it is derived from.
//
// The second half pins the DELIBERATE parser asymmetries: for every place
// the enforced validators (envelope.ts / enclave.ts) diverge from the
// generated base, one named test shows the exact divergence - and nothing
// else - so an asymmetry cannot be dropped (or grown) silently. The
// structural twin of these tests is scripts/check-envelope-parity.ts.

import { describe, expect, test } from "bun:test";
import type { z } from "zod";
import {
  ClientListResultSchema,
  ClientRevokeResultSchema,
  EnclaveErrorFrameSchema,
  EnclaveProofFrameSchema,
  KillStatusResultSchema,
  PresenceErrorFrameSchema,
  PresenceProofFrameSchema,
  TrustedClientSchema,
} from "../src/enclave";
import { BridgeReqSchema, BridgeRespSchema } from "../src/envelope";
import {
  BridgeReqWireSchema,
  BridgeRespWireSchema,
  ClientEntryWireSchema,
  ClientListResultWireSchema,
  ClientRevokeResultWireSchema,
  EnclaveErrorWireSchema,
  EnclaveProofWireSchema,
  KillStatusResultWireSchema,
  PresenceErrorWireSchema,
  PresenceProofWireSchema,
} from "../src/envelope-wire.gen";

type Frame = Record<string, unknown>;

const entry: Frame = { name: "codex", anchor: { kind: "hash", value: "abc123" } };

// One representative valid frame per generated schema, plus which of its
// fields are required. The generic harness below derives the hostile
// variants from these. `freeForm` names the fields the CONTRACT leaves
// unconstrained (BridgeReq.args is validated per-op downstream, and
// BridgeResp.data varies per op), so type confusion on them is legal at this
// layer - the args narrowing is the R3 asymmetry, pinned below. `enforced`
// is the wrapped validator the extension actually runs: it must refuse the
// same missing-required and type-confused frames as the base (a wrapper
// override that silently coerces - z.preprocess and friends - is invisible
// to the schema-derived parity gate, so it is caught HERE, behaviorally).
// `enforcedStringOk` names the fields where a string is legal on the
// enforced side only (the id's pinned forward-compat arm). `enforcedStrict`
// marks the wrapped validators that must ALSO refuse unknown fields (the
// envelopes; the control frames are R5-loose, pinned below).
const WIRE_CASES: ReadonlyArray<{
  name: string;
  schema: z.ZodType;
  enforced: z.ZodType;
  valid: Frame;
  required: readonly string[];
  freeForm?: readonly string[];
  enforcedStringOk?: readonly string[];
  enforcedStrict?: boolean;
}> = [
  {
    name: "BridgeReqWireSchema",
    schema: BridgeReqWireSchema,
    enforced: BridgeReqSchema,
    valid: { id: 1, op: "tab_list", tabId: 3, browser: "brave", args: {} },
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
    valid: { ...entry, added_unix: 1700000000 },
    required: ["name", "anchor"],
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
    name: "PresenceProofWireSchema",
    schema: PresenceProofWireSchema,
    enforced: PresenceProofFrameSchema,
    valid: { type: "presence_proof", sig: "s", key_id: "k", pubkey: "p" },
    required: ["type", "sig", "key_id", "pubkey"],
  },
  {
    name: "PresenceErrorWireSchema",
    schema: PresenceErrorWireSchema,
    enforced: PresenceErrorFrameSchema,
    valid: { type: "presence_error", reason: "busy" },
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
];

// Values that violate whatever type the field had - including the SAME base
// family (a number where a string belongs, and vice versa; a bare element
// where an array belongs), so a validator that silently coerces or wraps
// (z.preprocess, z.coerce) fails here even though its derived JSON Schema
// still looks right.
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

describe("generated wire schemas and their wrapped validators fail closed", () => {
  for (const {
    name,
    schema,
    enforced,
    valid,
    required,
    freeForm,
    enforcedStringOk,
    enforcedStrict,
  } of WIRE_CASES) {
    describe(name, () => {
      test("accepts the representative frame", () => {
        expect(schema.safeParse(valid).success).toBe(true);
        expect(enforced.safeParse(valid).success).toBe(true);
      });

      test("accepts the frame with optional fields omitted", () => {
        const minimal = Object.fromEntries(
          Object.entries(valid).filter(([key]) => required.includes(key)),
        );
        expect(schema.safeParse(minimal).success).toBe(true);
        expect(enforced.safeParse(minimal).success).toBe(true);
      });

      test("rejects an unknown field (the R5-loose wrapped frames are pinned below)", () => {
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

  test("rejects nested extras (client entry, anchor)", () => {
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

  test("rejects an anchor outside the two variants (type confusion on the tag)", () => {
    for (const anchor of [
      { kind: "root", value: "x" },
      { kind: "hash" },
      { value: "x" },
      "hash:x",
    ]) {
      expect(ClientEntryWireSchema.safeParse({ ...entry, anchor }).success).toBe(false);
    }
  });

  test("never invents a value for an absent field (no silent defaults)", () => {
    // added_unix carries #[serde(default)] on the Rust side; the generated
    // validator must NOT replay that (a validator that invents fields would
    // hide a missing-field bug from consumers). Absent stays absent.
    const wire = ClientEntryWireSchema.parse(entry);
    expect("added_unix" in wire).toBe(false);
    const wrapped = TrustedClientSchema.parse(entry);
    expect("added_unix" in wrapped).toBe(false);
  });
});

// Every deliberate divergence between the enforced validator and the
// generated base, one test each, named like its RECONCILED_FIELDS pin in
// json-schema-normalize.ts. Each test shows the base and the wrapper
// disagreeing in exactly the approved direction.
describe("the asymmetry layer diverges from the wire base exactly as pinned", () => {
  test("id (ID_FIELD): the enforced envelope adds the forward-compat string arm", () => {
    const req = { id: "req-9", op: "tab_list", args: {} };
    expect(BridgeReqWireSchema.safeParse(req).success).toBe(false);
    expect(BridgeReqSchema.safeParse(req).success).toBe(true);
    const resp = { id: "req-9", ok: true };
    expect(BridgeRespWireSchema.safeParse(resp).success).toBe(false);
    expect(BridgeRespSchema.safeParse(resp).success).toBe(true);
  });

  test("id (ID_FIELD): both sides refuse an unsafe integer in this runtime", () => {
    const req = { id: 2 ** 60, op: "tab_list", args: {} };
    expect(BridgeReqWireSchema.safeParse(req).success).toBe(false);
    expect(BridgeReqSchema.safeParse(req).success).toBe(false);
  });

  test("op: the enforced envelope refuses the empty string early", () => {
    const req = { id: 1, op: "", args: {} };
    expect(BridgeReqWireSchema.safeParse(req).success).toBe(true);
    expect(BridgeReqSchema.safeParse(req).success).toBe(false);
  });

  test("tabId: the enforced envelope drops the serde Option null arm", () => {
    const req = { id: 1, op: "tab_list", tabId: null, args: {} };
    expect(BridgeReqWireSchema.safeParse(req).success).toBe(true);
    expect(BridgeReqSchema.safeParse(req).success).toBe(false);
  });

  test("browser: null arm dropped, label grammar enforced early", () => {
    for (const browser of [null, "a b", "x".repeat(33), ""]) {
      const req = { id: 1, op: "tab_list", browser, args: {} };
      expect(BridgeReqSchema.safeParse(req).success).toBe(false);
    }
    expect(
      BridgeReqWireSchema.safeParse({ id: 1, op: "tab_list", browser: null, args: {} }).success,
    ).toBe(true);
    expect(
      BridgeReqWireSchema.safeParse({ id: 1, op: "tab_list", browser: "a b", args: {} }).success,
    ).toBe(true);
  });

  test("args (R3): free-form on the wire base, narrowed to the OpArgs union", () => {
    const req = { id: 1, op: "tab_list", args: "not an object" };
    expect(BridgeReqWireSchema.safeParse(req).success).toBe(true);
    expect(BridgeReqSchema.safeParse(req).success).toBe(false);
    const outsideUnion = { id: 1, op: "tab_list", args: { notAnArg: 1 } };
    expect(BridgeReqSchema.safeParse(outsideUnion).success).toBe(false);
  });

  test("response error (OPTIONAL_STRING): null arm dropped", () => {
    const resp = { id: 1, ok: false, error: null };
    expect(BridgeRespWireSchema.safeParse(resp).success).toBe(true);
    expect(BridgeRespSchema.safeParse(resp).success).toBe(false);
  });

  test("control frames (R5): strict base, loose enforced reader", () => {
    const frames: ReadonlyArray<[z.ZodType, z.ZodType, Frame]> = [
      [
        EnclaveProofWireSchema,
        EnclaveProofFrameSchema,
        { type: "enclave_proof", sig: "s", key_id: "k", pubkey: "p" },
      ],
      [
        EnclaveErrorWireSchema,
        EnclaveErrorFrameSchema,
        { type: "enclave_error", reason: "denied" },
      ],
      [
        PresenceProofWireSchema,
        PresenceProofFrameSchema,
        { type: "presence_proof", sig: "s", key_id: "k", pubkey: "p" },
      ],
      [
        PresenceErrorWireSchema,
        PresenceErrorFrameSchema,
        { type: "presence_error", reason: "busy" },
      ],
      [
        ClientListResultWireSchema,
        ClientListResultSchema,
        { type: "client_list_result", ok: true, enrolled: true, clients: [] },
      ],
      [
        ClientRevokeResultWireSchema,
        ClientRevokeResultSchema,
        { type: "client_revoke_result", ok: true },
      ],
      [
        KillStatusResultWireSchema,
        KillStatusResultSchema,
        { type: "kill_status_result", ok: true },
      ],
    ];
    for (const [wire, enforced, valid] of frames) {
      const grown = { ...valid, hostAdded: "field" };
      expect(wire.safeParse(grown).success).toBe(false);
      expect(enforced.safeParse(grown).success).toBe(true);
      // Loose never means lax: the validated fields still gate.
      expect(enforced.safeParse({ ...grown, type: "evil" }).success).toBe(false);
    }
  });

  test("proof key material (NONEMPTY_STRING): empty strings refused early", () => {
    for (const field of ["sig", "key_id", "pubkey"]) {
      const proof = { type: "enclave_proof", sig: "s", key_id: "k", pubkey: "p", [field]: "" };
      expect(EnclaveProofWireSchema.safeParse(proof).success).toBe(true);
      expect(EnclaveProofFrameSchema.safeParse(proof).success).toBe(false);
    }
  });

  test("client name (NONEMPTY_STRING): empty label refused early", () => {
    const unnamed = { ...entry, name: "" };
    expect(ClientEntryWireSchema.safeParse(unnamed).success).toBe(true);
    expect(TrustedClientSchema.safeParse(unnamed).success).toBe(false);
  });

  test("anchor (ANCHOR_FIELD): loose single-object spelling, non-empty value", () => {
    const emptyValue = { ...entry, anchor: { kind: "team_id", value: "" } };
    expect(ClientEntryWireSchema.safeParse(emptyValue).success).toBe(true);
    expect(TrustedClientSchema.safeParse(emptyValue).success).toBe(false);
    const grownAnchor = { ...entry, anchor: { kind: "team_id", value: "T1", extra: 1 } };
    expect(ClientEntryWireSchema.safeParse(grownAnchor).success).toBe(false);
    expect(TrustedClientSchema.safeParse(grownAnchor).success).toBe(true);
    // Both sides refuse a kind outside the two variants.
    expect(
      TrustedClientSchema.safeParse({ ...entry, anchor: { kind: "root", value: "x" } }).success,
    ).toBe(false);
  });

  test("added_unix (ADDED_UNIX_FIELD): JS-safe hardening on the enforced side", () => {
    for (const added of [-1, 1.5]) {
      expect(TrustedClientSchema.safeParse({ ...entry, added_unix: added }).success).toBe(false);
      expect(ClientEntryWireSchema.safeParse({ ...entry, added_unix: added }).success).toBe(false);
    }
    expect(TrustedClientSchema.safeParse({ ...entry, added_unix: 2 ** 60 }).success).toBe(false);
  });

  test("killed (OPTIONAL_BOOL) and error (OPTIONAL_STRING): null arms dropped", () => {
    for (const frame of [
      { type: "kill_status_result", ok: false, killed: null },
      { type: "kill_status_result", ok: false, error: null },
    ]) {
      expect(KillStatusResultWireSchema.safeParse(frame).success).toBe(true);
      expect(KillStatusResultSchema.safeParse(frame).success).toBe(false);
    }
  });
});
