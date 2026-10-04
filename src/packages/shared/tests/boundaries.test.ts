// The popup/options message boundary and the storage-record schemas,
// exercised adversarially: unknown types, malformed payloads, and corrupt
// records must all be refused or degraded, never interpreted.

import { describe, expect, test } from "bun:test";
import { CompromisedMarkSchema, EnclaveInboundFrameSchema, EnclavePinSchema } from "../src/enclave";
import { EnclaveProofFrameSchema } from "../src/envelope.gen";
import { RuntimeMsgSchema } from "../src/runtime-msg";
import { AllowlistSchema, PendingApprovalsSchema } from "../src/storage";

describe("RuntimeMsgSchema", () => {
  // The router's one parse is all that stands between an extension-page
  // message and a trust-state mutation; a loosened field here (an optional
  // made of a required one, a loose object admitting extras, a release arm on
  // the kill switch) would silently widen what a page may ask for.
  test.each([
    { name: "not an object", msg: null },
    { name: "a bare type string", msg: "get_status" },
    { name: "an unknown type", msg: { type: "unknown_type" } },
    { name: "a retired type (screenshots are SW-captured)", msg: { type: "capture_visible_tab" } },
    { name: "confirm_resolve without approved", msg: { type: "confirm_resolve", id: "confirm_1" } },
    { name: "confirm_ready with an empty id", msg: { type: "confirm_ready", id: "" } },
    { name: "resolve_allow without allow", msg: { type: "resolve_allow", id: "x" } },
    { name: "resolve_allow with an empty id", msg: { type: "resolve_allow", id: "", allow: true } },
    { name: "add_allow without glob", msg: { type: "add_allow" } },
    { name: "add_allow with an empty glob", msg: { type: "add_allow", glob: "" } },
    { name: "add_allow with a non-string glob", msg: { type: "add_allow", glob: 42 } },
    { name: "an unknown field (strict)", msg: { type: "get_status", extra: 1 } },
    { name: "enroll_pair with an unknown field", msg: { type: "enroll_pair", now: true } },
    {
      name: "a kill release (the host refuses it; engage-only by shape)",
      msg: { type: "set_kill", on: false },
    },
    { name: "revoke_client with a non-label name", msg: { type: "revoke_client", name: "../etc" } },
    { name: "lang_choose outside the enum", msg: { type: "lang_choose", value: "fr" } },
  ])("refuses $name", ({ msg }) => {
    expect(RuntimeMsgSchema.safeParse(msg).success).toBe(false);
  });
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
