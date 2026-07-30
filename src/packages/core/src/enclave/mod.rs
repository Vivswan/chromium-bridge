//! Secure Enclave enrollment key: mint, look up, sign, revoke.
//!
//! The enrollment ceremony (ADR-0021) establishes trust between the extension
//! and this binary at `claude mcp add` time. The host mints a P-256 key inside
//! the Secure Enclave; the private key never leaves the Enclave and every use
//! is gated on user presence (Touch ID / password). The extension pins the
//! PUBLIC key and later verifies `enclave_proof` frames (see
//! [`crate::protocol::EnclaveControl`]) against it, so only a host that can
//! drive THIS machine's Enclave - with the user physically approving - can
//! complete an enrollment.
//!
//! Layout (one concern per submodule; the public API is re-exported here):
//! - [`challenge`]: challenge message construction (shared contract with the
//!   extension) and its bounds.
//! - [`der`]: strict-DER ECDSA signature parsing to the raw P1363 form.
//! - [`encoding`]: base64 (encode-only, for the proof frame).
//! - [`pubkey`]: the validated X9.63 public key + fingerprints.
//! - [`config`]: the on-disk enrollment policy record (policy only, never key
//!   material).
//! - [`key`]: the cross-platform [`EnrollmentKey`] handle and the native-host
//!   challenge responder.
//! - [`macos`]: the keychain/Secure Enclave backend, built on the vetted
//!   `security-framework` crate - no hand-rolled Security.framework FFI.
//!   Other platforms get stubs that fail closed with
//!   [`EnclaveError::Unsupported`].
//! - [`cli`]: the `pair` / `revoke` / `enclave-status` subcommand runners.

mod challenge;
mod cli;
mod config;
mod der;
mod encoding;
mod key;
#[cfg(target_os = "macos")]
mod macos;
mod pubkey;

pub use challenge::{
    challenge_message, presence_message, CHALLENGE_DOMAIN, MAX_CONTEXT_LEN, MAX_NONCE_LEN,
    PRESENCE_DOMAIN,
};
pub use cli::{
    run_pair, run_presence_selftest, run_revoke, run_status, run_status_json, EnclaveKeyState,
    EnclavePolicyReport, EnclaveStatusReport,
};
pub use config::HostConfig;
pub use der::{der_to_raw_signature, SIG_LEN};
pub use encoding::base64_encode;
pub use key::{respond_to_challenge, respond_to_presence_challenge, EnrollmentKey};
pub use pubkey::{EnclavePublicKey, PUBKEY_LEN};

/// Keychain label of the enrollment signing key. Stable across processes: the
/// `pair` CLI mints under this label and the Chrome-spawned `--native-host`
/// process finds the key by searching for it. Versioned so a future algorithm
/// change can mint under a new label without colliding with the old key.
pub const KEY_LABEL: &str = "com.vivswan.chromium-bridge.enclave.signing.v1";

/// The PUBLIC test-vector scalar behind the golden fixture
/// (`examples/emit_enclave_contract.rs` -> enclave-fixture.gen.ts): a fixed,
/// deliberately well-known P-256 private key, so fixture regeneration is
/// deterministic. Because the scalar is public, anyone can sign fresh
/// challenges with it - it protects nothing and must NEVER be accepted as an
/// enrollment identity. [`ensure_not_fixture_key`] enforces that on the host
/// side, and the extension refuses it in its pairing verifier and stored-pin
/// validators (`ENCLAVE_FIXTURE_KEY_ID` in enclave.gen.ts).
pub const FIXTURE_KEY_BYTES: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

/// Fingerprint (lowercase-hex SHA-256 of the X9.63 public point) of
/// [`FIXTURE_KEY_BYTES`]' public half: the deny-listed identity. Pinned to
/// the scalar by `fixture_key_is_pinned_and_refused` below and re-derived at
/// generation time by the fixture emitter, which fails on a mismatch.
pub const FIXTURE_KEY_ID: &str = "4269889431e3131966fcaf6a457141943ed2c35b5b917ae62cb339546f523551";

/// Fail closed when `public` is the golden-fixture key. Called by
/// [`EnrollmentKey::public_key`], the one path that exports the enrollment
/// public half. Defense in depth, honestly weighted: on macOS `lookup()`
/// already refuses any non-Secure-Enclave key, which a software fixture key
/// can never be, and a SUBSTITUTED host binary simply skips this check - the
/// load-bearing deny-list against that adversary is the extension's
/// (`ENCLAVE_FIXTURE_KEY_ID`). The fingerprint is public data, so this
/// comparison carries no timing sensitivity.
pub fn ensure_not_fixture_key(public: &EnclavePublicKey) -> Result<(), EnclaveError> {
    if public.fingerprint_hex() == FIXTURE_KEY_ID {
        return Err(EnclaveError::KeyInvalid(
            "the public golden-fixture key is never enrollable",
        ));
    }
    Ok(())
}

/// Typed failures for the enrollment key operations. The native host maps
/// these to the stable `enclave_error.reason` codes via [`reason_code`].
#[derive(Debug, thiserror::Error)]
pub enum EnclaveError {
    #[error("Secure Enclave enrollment is only supported on macOS")]
    Unsupported,
    #[error("no enrollment key found - run `chromium-bridge pair` first")]
    NotEnrolled,
    #[error("invalid challenge: {0}")]
    InvalidChallenge(&'static str),
    #[error("enrollment key rejected: {0}")]
    KeyInvalid(&'static str),
    #[error("keychain: {0}")]
    Keychain(String),
    #[error("signing: {0}")]
    Signing(String),
}

/// Stable machine-readable reason for an `enclave_error` frame. The extension
/// matches on these; keep them append-only. A new variant fails this
/// exhaustive match at compile time; keeping its code in [`REASON_CODES`]
/// (and the sample list beside it) is enforced at TEST time by
/// `reason_codes_are_exactly_the_emitted_set` - a deliberate trade: an
/// index-based encoding would move part of that guard to compile time but
/// still could not force the sample list to grow, and costs more in
/// readability than the residual it closes.
pub fn reason_code(e: &EnclaveError) -> &'static str {
    match e {
        EnclaveError::Unsupported => "unsupported_platform",
        EnclaveError::NotEnrolled => "not_enrolled",
        EnclaveError::InvalidChallenge(_) => "invalid_challenge",
        EnclaveError::KeyInvalid(_) => "key_invalid",
        EnclaveError::Keychain(_) => "keychain_error",
        EnclaveError::Signing(_) => "signing_failed",
    }
}

/// The closed set of `enclave_error.reason` codes [`reason_code`] can emit,
/// in [`EnclaveError`] variant order. This is the wire vocabulary the
/// extension branches on (its compromise latch fires on a subset), so it is
/// emitted to the TS side as a union (enclave.gen.ts, `moon run gen`);
/// `reason_codes_are_exactly_the_emitted_set` pins it to [`reason_code`].
pub const REASON_CODES: [&str; 6] = [
    "unsupported_platform",
    "not_enrolled",
    "invalid_challenge",
    "key_invalid",
    "keychain_error",
    "signing_failed",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_codes_are_exactly_the_emitted_set() {
        // One sample per variant, compared element-wise (a bijection in
        // variant order) with a distinctness check. This guard is TEST-time:
        // the compiler forces a new variant to get a reason_code() arm, and
        // this test then fails until REASON_CODES grows - but only once the
        // sample list below is extended too, which is a convention this
        // comment states rather than a mechanism. (No stable Rust feature
        // enumerates enum variants without a proc-macro dependency, which
        // the security core does not take for a test convenience.)
        let samples = [
            EnclaveError::Unsupported,
            EnclaveError::NotEnrolled,
            EnclaveError::InvalidChallenge("x"),
            EnclaveError::KeyInvalid("x"),
            EnclaveError::Keychain(String::new()),
            EnclaveError::Signing(String::new()),
        ];
        let produced: Vec<&str> = samples.iter().map(reason_code).collect();
        assert_eq!(produced, REASON_CODES);
        // Distinct codes: a duplicate would collapse two failure modes into
        // one wire value and shrink the generated union.
        let mut deduped = produced.clone();
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(deduped.len(), REASON_CODES.len());
    }

    #[test]
    fn fixture_key_is_pinned_and_refused() {
        use p256::ecdsa::SigningKey;

        // FIXTURE_KEY_ID really is the fingerprint of the public scalar's
        // key (the emitter re-checks this at gen time; this pin holds even
        // when nobody runs gen).
        let sk = SigningKey::from_slice(&FIXTURE_KEY_BYTES)
            .expect("the fixture scalar is a valid P-256 key");
        let point = sk.verifying_key().to_encoded_point(false);
        let public = EnclavePublicKey::from_x963(point.as_bytes().to_vec())
            .expect("p256 emits the X9.63 uncompressed point");
        assert_eq!(public.fingerprint_hex(), FIXTURE_KEY_ID);

        // The deny-list refuses it with the stable key_invalid reason (the
        // extension's compromise latch fires on that code in verify mode).
        let refused = ensure_not_fixture_key(&public).unwrap_err();
        assert_eq!(reason_code(&refused), "key_invalid");
        assert!(refused.to_string().contains("never enrollable"));

        // Any other key passes: the deny-list is exactly one identity wide.
        let other = SigningKey::from_slice(&[0x42; 32]).expect("valid scalar");
        let other_public = EnclavePublicKey::from_x963(
            other
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
        )
        .expect("valid point");
        assert!(ensure_not_fixture_key(&other_public).is_ok());
    }
}
