// GENERATED from the Rust core (src/packages/core/src/enclave/challenge.rs,
// pubkey.rs, der.rs, and mod.rs REASON_CODES) by scripts/gen-ops.ts - DO NOT
// EDIT. Edit the enclave module, then run `moon run gen`.
//
// The enclave signing contract, TS side: the constants the WebCrypto verifier (background/enclave-verify.ts) and the
// enrollment state machine (background/enrollment.ts) enforce. The signed-message ALGORITHM is pinned separately by
// the golden vectors in enclave-fixture.gen.ts.

// Enrollment challenges and per-action presence sign under distinct domains, so neither can be replayed as the other.
export const CHALLENGE_DOMAIN = "chromium-bridge-enclave-v1";
export const PRESENCE_DOMAIN = "chromium-bridge-presence-v1";

// Host-enforced bounds on challenge fields, in UTF-8 bytes; the verifier rejects anything outside them before the crypto.
export const MAX_NONCE_BYTES = 256;
export const MAX_CONTEXT_BYTES = 4096;

// The X9.63 uncompressed P-256 point and the raw IEEE P1363 r||s signature.
export const PUBKEY_LEN = 65;
export const SIG_LEN = 64;

// The closed, append-only set of enclave_error.reason codes (reason_code in src/packages/core/src/enclave/mod.rs).
// The enrollment state machine's compromise latch fires on a subset, so an unrecognized code must degrade to a
// refusal, never match.
export const ENCLAVE_REASON_CODES = [
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

// Fingerprint of the PUBLIC golden-fixture key (FIXTURE_KEY_ID in src/packages/core/src/enclave/mod.rs). Its private
// scalar is checked into the repo, so it must never become an enrollment identity: the pairing verifier
// (background/enclave-verify.ts), the stored-pin validators (enclave.ts), and the host all refuse it.
export const ENCLAVE_FIXTURE_KEY_ID =
  "4269889431e3131966fcaf6a457141943ed2c35b5b917ae62cb339546f523551";
