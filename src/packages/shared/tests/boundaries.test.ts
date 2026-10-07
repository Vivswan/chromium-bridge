// The popup/options message boundary and the storage-record schemas, exercised adversarially: unknown types,
// malformed payloads, and corrupt records must all be refused or degraded, never interpreted.

import { describe, expect, test } from "bun:test";
import { z } from "zod";
import { EnclaveProofFrameSchema } from "../generated/envelope";
import { CompromisedMarkSchema, EnclaveInboundFrameSchema, EnclavePinSchema } from "../src/enclave";
import {
  anchorFault,
  ClientAnchorSchema,
  RUNTIME_CONTRACT,
  RuntimeMsgSchema,
  type RuntimeMsgType,
} from "../src/runtime-msg";
import { AllowlistSchema, PendingApprovalsSchema } from "../src/storage";

// The router's one parse is all that stands between an extension-page message and a trust-state mutation; a
// loosened field (an optional made of a required one, a loose object admitting extras, a release arm on the
// kill switch) would silently widen what a page may ask for. The roster is read from the contract, so a
// message type added there is covered here with no hand edit, and a field-bearing type with no malformed case
// below fails the roster test by name.
describe("RuntimeMsgSchema", () => {
  const TYPES = Object.keys(RUNTIME_CONTRACT) as RuntimeMsgType[];

  function fieldsOf(type: RuntimeMsgType): string[] {
    const req = RUNTIME_CONTRACT[type].req;
    return req instanceof z.ZodObject ? Object.keys(req.shape).filter((f) => f !== "type") : [];
  }

  test.each([
    { name: "not an object", msg: null },
    { name: "a bare type string", msg: "get_status" },
    { name: "an unknown type", msg: { type: "unknown_type" } },
    { name: "a retired type (screenshots are SW-captured)", msg: { type: "capture_visible_tab" } },
  ])("refuses $name", ({ msg }) => {
    expect(RuntimeMsgSchema.safeParse(msg).success).toBe(false);
  });

  // z.object and z.strictObject have the same TypeScript type, so a request declared loose would admit extras
  // with no failure anywhere else. Zod reports the extra key beside any missing required fields, so no
  // well-formed sample is needed per type.
  test.each(TYPES)("%s refuses an unknown field", (type) => {
    const result = RUNTIME_CONTRACT[type].req.safeParse({ type, extra: 1 });
    expect(result.success ? [] : result.error.issues.map((issue) => issue.code)).toContain(
      "unrecognized_keys",
    );
  });

  // One table keyed by the message type, so a case cannot be refused merely for a misspelled tag.
  const MALFORMED: {
    [K in RuntimeMsgType]?: ReadonlyArray<{
      name: string;
      msg: { type: K } & Record<string, unknown>;
    }>;
  } = {
    resolve_allow: [
      { name: "without allow", msg: { type: "resolve_allow", id: "x" } },
      { name: "with an empty id", msg: { type: "resolve_allow", id: "", allow: true } },
    ],
    add_allow: [
      { name: "without glob", msg: { type: "add_allow" } },
      { name: "with an empty glob", msg: { type: "add_allow", glob: "" } },
      { name: "with a non-string glob", msg: { type: "add_allow", glob: 42 } },
    ],
    remove_allow: [
      { name: "without glob", msg: { type: "remove_allow" } },
      { name: "with an empty glob", msg: { type: "remove_allow", glob: "" } },
    ],
    revoke_client: [
      { name: "with a non-label name", msg: { type: "revoke_client", name: "../etc" } },
    ],
    // The host refuses these at its frame parse without touching its pending presence slot, so the page
    // must refuse them first (runtime-msg.ts ClientAnchorSchema says why).
    pair_client: [
      {
        name: "with a hash anchor outside the digest grammar",
        msg: { type: "pair_client", name: "codex", anchor: { kind: "hash", value: "zz" } },
      },
      {
        name: "with an uppercase hash anchor",
        msg: {
          type: "pair_client",
          name: "codex",
          anchor: { kind: "hash", value: "A".repeat(40) },
        },
      },
      {
        name: "with an empty signer anchor",
        msg: { type: "pair_client", name: "codex", anchor: { kind: "signer", value: "" } },
      },
      {
        name: "with a NUL inside the signer anchor",
        msg: { type: "pair_client", name: "codex", anchor: { kind: "signer", value: "A\u0000B" } },
      },
      {
        name: "with an unpaired high surrogate as the signer anchor",
        msg: { type: "pair_client", name: "codex", anchor: { kind: "signer", value: "\uD800" } },
      },
      {
        name: "with an unpaired low surrogate inside the signer anchor",
        msg: { type: "pair_client", name: "codex", anchor: { kind: "signer", value: "A\uDC00B" } },
      },
      {
        name: "with an anchor kind the host has no parser for",
        msg: { type: "pair_client", name: "codex", anchor: { kind: "parent", value: "x" } },
      },
    ],
    grant_policy: [
      {
        name: "with a field the catalogue does not own",
        msg: { type: "grant_policy", overlay: { unknownField: true } },
      },
    ],
    rollback_policy: [
      {
        name: "with a negative revision",
        msg: { type: "rollback_policy", revision: -1, entry: { id: "a1" } },
      },
      { name: "without the listed row", msg: { type: "rollback_policy", revision: 1 } },
      {
        name: "with a row named by something other than its id",
        msg: { type: "rollback_policy", revision: 1, entry: { index: 1 } },
      },
    ],
    set_kill: [
      {
        name: "with on: false (engage-only by shape; release is the kill_release message)",
        msg: { type: "set_kill", on: false },
      },
    ],
    confirm_ready: [{ name: "with an empty id", msg: { type: "confirm_ready", id: "" } }],
    confirm_resolve: [
      { name: "without approved", msg: { type: "confirm_resolve", id: "confirm_1" } },
    ],
    webauthn_enroll_finish: [
      {
        name: "with an empty attestation_object",
        msg: { type: "webauthn_enroll_finish", attestation_object: "", client_data_json: "Y2Rq" },
      },
      {
        name: "without client_data_json",
        msg: { type: "webauthn_enroll_finish", attestation_object: "YXR0" },
      },
    ],
    webauthn_presence_assert: [
      {
        name: "without signature",
        msg: {
          type: "webauthn_presence_assert",
          nonce: "nonce-0002",
          credential_id: "Y3JlZC1h",
          authenticator_data: "YXV0aA",
          client_data_json: "Y2Rq",
        },
      },
      {
        name: "with an empty nonce",
        msg: {
          type: "webauthn_presence_assert",
          nonce: "",
          credential_id: "Y3JlZC1h",
          authenticator_data: "YXV0aA",
          client_data_json: "Y2Rq",
          signature: "c2ln",
        },
      },
    ],
    webauthn_presence_confirm: [
      { name: "with an empty nonce", msg: { type: "webauthn_presence_confirm", nonce: "" } },
    ],
    repair_registration: [
      {
        name: "with a non-array browsers",
        msg: { type: "repair_registration", browsers: "brave" },
      },
      { name: "with an empty browsers list", msg: { type: "repair_registration", browsers: [] } },
      {
        name: "with a browser outside the enum",
        msg: { type: "repair_registration", browsers: ["brave", "firefox"] },
      },
      {
        name: "with a non-string browser",
        msg: { type: "repair_registration", browsers: [42] },
      },
    ],
    restrict_policy: [
      {
        name: "with an overlay field the catalogue does not own",
        msg: { type: "restrict_policy", overlay: { notAPolicyField: true } },
      },
      { name: "with a non-object overlay", msg: { type: "restrict_policy", overlay: "deny" } },
    ],
    lang_choose: [{ name: "outside the enum", msg: { type: "lang_choose", value: "fr" } }],
  };

  test("every field-bearing request has a malformed-field case, and only those", () => {
    expect(Object.keys(MALFORMED).sort()).toEqual(
      TYPES.filter((t) => fieldsOf(t).length > 0).sort(),
    );
  });

  test.each(
    Object.entries(MALFORMED).flatMap(([type, cases]) => cases.map((c) => ({ type, ...c }))),
  )("refuses $type $name", ({ msg }) => {
    expect(RuntimeMsgSchema.safeParse(msg).success).toBe(false);
  });
});

// The page shows the CLI's sentence for the fault the host's SignerId grammar names (ipc::identity), so the
// fault must be told apart here, not folded into one refusal; and a value no terminal can type (an unpaired
// UTF-16 surrogate) is refused before the host's JSON reader would close the connection over it, while a
// paired surrogate is ordinary text. Well-formedness is the platform's own judgment (String.isWellFormed).
describe("ClientAnchorSchema", () => {
  test.each([
    { kind: "hash", value: "zz", fault: "hash_grammar" },
    { kind: "signer", value: "", fault: "signer_empty" },
    { kind: "signer", value: "A\u0000B", fault: "signer_nul" },
    { kind: "signer", value: "\uD800", fault: "signer_ill_formed" },
    { kind: "signer", value: "A\uDC00B", fault: "signer_ill_formed" },
  ] as const)("names the fault of $kind $value", ({ kind, value, fault }) => {
    const result = ClientAnchorSchema.safeParse({ kind, value });
    expect(result.success ? "accepted" : anchorFault(result.error)).toBe(fault);
  });

  test.each(["TEAMID", "\uD83D\uDE00 Corp", "Developer ID: Example"])(
    "accepts signer %j",
    (value) => {
      expect(ClientAnchorSchema.safeParse({ kind: "signer", value })).toEqual({
        success: true,
        data: { kind: "signer", value },
      });
    },
  );
});

describe("enclave frame schemas", () => {
  test("classifies exactly the three ceremony frame types", () => {
    for (const type of ["enclave_challenge", "enclave_proof", "enclave_error"]) {
      expect(EnclaveInboundFrameSchema.safeParse({ type }).success).toBe(true);
    }
    expect(EnclaveInboundFrameSchema.safeParse({ type: "enclave_evil" }).success).toBe(false);
    expect(EnclaveInboundFrameSchema.safeParse({ op: "tab_list" }).success).toBe(false);
  });

  test("frames are loose: unknown extras don't break classification", () => {
    expect(
      EnclaveInboundFrameSchema.safeParse({ type: "enclave_error", reason: "x", extra: 1 }).success,
    ).toBe(true);
  });

  test("a proof must carry sig, key_id, and pubkey as non-empty strings", () => {
    const whole = { type: "enclave_proof", sig: "s", key_id: "k", pubkey: "p" };
    expect(EnclaveProofFrameSchema.safeParse(whole).success).toBe(true);
    expect(EnclaveProofFrameSchema.safeParse({ ...whole, sig: undefined }).success).toBe(false);
    expect(EnclaveProofFrameSchema.safeParse({ ...whole, key_id: 7 }).success).toBe(false);
    expect(EnclaveProofFrameSchema.safeParse({ ...whole, pubkey: "" }).success).toBe(false);
  });
});

describe("storage record schemas", () => {
  const keyId = "a".repeat(64);

  test("pin records are strict and shape-checked", () => {
    expect(EnclavePinSchema.safeParse({ keyId, pubkeyB64: "AA==", pinnedAt: 1 }).success).toBe(
      true,
    );
    // Uppercase / short / non-hex fingerprints, missing fields, extras: all
    // treated as absent by the reader, which fails closed at the gate.
    expect(
      EnclavePinSchema.safeParse({ keyId: keyId.toUpperCase(), pubkeyB64: "AA==", pinnedAt: 1 })
        .success,
    ).toBe(false);
    expect(
      EnclavePinSchema.safeParse({ keyId: "abc", pubkeyB64: "AA==", pinnedAt: 1 }).success,
    ).toBe(false);
    expect(EnclavePinSchema.safeParse({ keyId, pubkeyB64: "AA==" }).success).toBe(false);
    expect(
      EnclavePinSchema.safeParse({ keyId, pubkeyB64: "AA==", pinnedAt: 1, extra: true }).success,
    ).toBe(false);
  });

  test("compromised marks need a reason and a timestamp", () => {
    expect(CompromisedMarkSchema.safeParse({ reason: "mismatch", at: 1 }).success).toBe(true);
    expect(CompromisedMarkSchema.safeParse({ reason: "", at: 1 }).success).toBe(false);
    expect(CompromisedMarkSchema.safeParse({ at: 1 }).success).toBe(false);
  });

  test("allowlist reads degrade on any non-string entry", () => {
    expect(AllowlistSchema.safeParse(["https://a.example/*"]).success).toBe(true);
    expect(AllowlistSchema.safeParse([]).success).toBe(true);
    expect(AllowlistSchema.safeParse(["ok", 42]).success).toBe(false);
    expect(AllowlistSchema.safeParse("https://a.example/*").success).toBe(false);
  });

  test("pending approvals require id, glob, and an expiry on every entry", () => {
    const entry = { id: "allow_1", glob: "https://a/*", expiresAt: 123 };
    expect(PendingApprovalsSchema.safeParse([entry]).success).toBe(true);
    expect(PendingApprovalsSchema.safeParse([]).success).toBe(true);
    // A single object (the pre-collection record shape) is not a collection.
    expect(PendingApprovalsSchema.safeParse(entry).success).toBe(false);
    expect(PendingApprovalsSchema.safeParse([{ id: "allow_1", glob: "https://a/*" }]).success).toBe(
      false,
    );
    expect(PendingApprovalsSchema.safeParse([{ ...entry, id: "" }]).success).toBe(false);
    expect(PendingApprovalsSchema.safeParse([entry, { id: "x" }]).success).toBe(false);
  });
});
