// The popup/options message boundary and the storage-record schemas,
// exercised adversarially: unknown types, malformed payloads, and corrupt
// records must all be refused or degraded, never interpreted.

import { describe, expect, test } from "bun:test";
import {
  CompromisedMarkSchema,
  EnclaveInboundFrameSchema,
  EnclavePinSchema,
  EnclaveProofFrameSchema,
} from "./enclave";
import { RuntimeMsgSchema } from "./runtime-msg";
import { AllowlistSchema, PendingAllowSchema } from "./storage";

describe("RuntimeMsgSchema", () => {
  test("accepts every message the popup/options/content actually send", () => {
    const good = [
      { type: "resolve_allow", id: "allow_1", allow: true },
      { type: "get_allowlist" },
      { type: "add_allow", glob: "https://example.com/*" },
      { type: "remove_allow", glob: "https://example.com/*" },
      { type: "get_status" },
      { type: "get_enrollment" },
      { type: "confirm_ready", id: "confirm_1" },
      { type: "confirm_resolve", id: "confirm_1", approved: false },
      { type: "enroll_pair" },
      { type: "enroll_verify" },
      { type: "enroll_approve" },
      { type: "enroll_reject" },
      { type: "enroll_revoke" },
    ];
    for (const msg of good) expect(RuntimeMsgSchema.safeParse(msg).success).toBe(true);
  });

  test("refuses unknown types and malformed payloads", () => {
    const bad = [
      null,
      "get_status",
      { type: "unknown_type" },
      { type: "capture_visible_tab" }, // removed: screenshots are SW-captured
      { type: "confirm_resolve", id: "confirm_1" }, // missing approved
      { type: "confirm_ready", id: "" }, // empty id
      { type: "resolve_allow", id: "x" }, // missing allow
      { type: "resolve_allow", id: "", allow: true }, // empty id
      { type: "add_allow" }, // missing glob
      { type: "add_allow", glob: "" }, // empty glob
      { type: "add_allow", glob: 42 },
      { type: "get_status", extra: 1 }, // strict: no unknown fields
      { type: "enroll_pair", now: true },
    ];
    for (const msg of bad) expect(RuntimeMsgSchema.safeParse(msg).success).toBe(false);
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

  test("pendingAllow requires both id and glob", () => {
    expect(PendingAllowSchema.safeParse({ id: "allow_1", glob: "https://a/*" }).success).toBe(true);
    expect(PendingAllowSchema.safeParse({ id: "allow_1" }).success).toBe(false);
    expect(PendingAllowSchema.safeParse({ id: "", glob: "https://a/*" }).success).toBe(false);
  });
});
