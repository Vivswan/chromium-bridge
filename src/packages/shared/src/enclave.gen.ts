// GENERATED from the Rust core (src/packages/core/src/enclave/challenge.rs,
// pubkey.rs, der.rs, and mod.rs REASON_CODES) by scripts/gen-ops.ts - DO NOT
// EDIT. Edit the enclave module, then run `moon run gen`.
//
// The enclave signing contract, TS side: the constants the extension's
// WebCrypto verifier (background/enclave-verify.ts) and the enrollment state
// machine (background/enrollment.ts) enforce. The signed-message ALGORITHM
// (NUL-separated domain || nonce || context, ECDSA P-256/SHA-256) is pinned
// separately by the golden vectors in enclave-fixture.gen.ts.

// Domain-separation prefixes: enrollment challenge signatures (ADR-0021) and
// per-action user-presence signatures (ADR-0031) sign under distinct domains,
// so the two statement types can never be replayed as one another.
export const CHALLENGE_DOMAIN = "chromium-bridge-enclave-v1";
export const PRESENCE_DOMAIN = "chromium-bridge-presence-v1";

// Host-enforced bounds on challenge fields, in UTF-8 bytes (Rust's
// MAX_NONCE_LEN / MAX_CONTEXT_LEN). The verifier rejects anything outside
// them before touching the crypto.
export const MAX_NONCE_BYTES = 256;
export const MAX_CONTEXT_BYTES = 4096;

// Wire byte lengths of the proof fields: the X9.63 uncompressed P-256 point
// and the raw IEEE P1363 r||s signature.
export const PUBKEY_LEN = 65;
export const SIG_LEN = 64;

// The closed set of enclave_error.reason codes the host can emit
// (reason_code in src/packages/core/src/enclave/mod.rs; append-only). The
// enrollment state machine branches on these - its compromise latch fires on
// a subset - so an unrecognized code must degrade to a refusal, never match.
export const ENCLAVE_REASON_CODES = [
  "unsupported_platform",
  "not_enrolled",
  "invalid_challenge",
  "key_invalid",
  "keychain_error",
  "signing_failed",
] as const;

export type EnclaveReasonCode = (typeof ENCLAVE_REASON_CODES)[number];

const ENCLAVE_REASON_SET: ReadonlySet<string> = new Set(ENCLAVE_REASON_CODES);

export function isEnclaveReasonCode(reason: string): reason is EnclaveReasonCode {
  return ENCLAVE_REASON_SET.has(reason);
}

// Fingerprint of the PUBLIC golden-fixture signing key (FIXTURE_KEY_BYTES /
// FIXTURE_KEY_ID in src/packages/core/src/enclave/mod.rs). Its private
// scalar is checked into the repo, so anyone can sign fresh challenges with
// it: it must never become an enrollment identity. The pairing verifier
// (background/enclave-verify.ts) and the stored-pin validators (enclave.ts)
// refuse it fail-closed; the host refuses it in EnrollmentKey::public_key.
export const ENCLAVE_FIXTURE_KEY_ID =
  "4269889431e3131966fcaf6a457141943ed2c35b5b917ae62cb339546f523551";
