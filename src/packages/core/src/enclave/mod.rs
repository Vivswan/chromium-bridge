//! The host identity key: a software P-256 key the extension pins at enrollment and verifies `enclave_proof`
//! frames ([`crate::protocol::control::EnclaveControl`]) and the signed policy baseline against. Signing is
//! not presence-gated; user presence is the WebAuthn assertion the extension makes ([`crate::webauthn`]), and
//! what this key proves is that the host answering is the one the user paired.
//!
//! ```text
//! credential store -> the Keychain, Credential Manager, or Secret Service through `keyring`, under an entry
//!                     name derived from the runtime directory, so two directories never share one and the
//!                     entry needs no record to be found again
//! host_key.json    -> the scalar itself, 0600 beside trust.json, when the user ran `pair --file-store`
//! ```
//!
//! A same-user process can read the scalar wherever it lives; docs/security/trust-boundaries.md names that as the
//! accepted narrowing of a software host key: it identifies the installation and nothing stronger.

mod challenge;
mod cli;
mod key;
mod pubkey;
mod record;
mod store;

pub use challenge::{
    challenge_message, policy_message, CHALLENGE_DOMAIN, MAX_CONTEXT_LEN, POLICY_DOMAIN,
};
pub use cli::{
    audit_host_key_revoke, dispose_enrollment_and_policy_baseline, run_pair, run_revoke_all,
    run_status, run_status_json, EnclaveStatusReport,
};
pub(crate) use cli::{key_line, key_report};
pub use key::{respond_to_challenge, EnrollmentKey, Revoked, StoreOutcome};
pub use pubkey::{EnclavePublicKey, PUBKEY_LEN};
pub use record::{HostKeyFile, KeyStore, Scalar};

use base64::Engine as _;

/// Byte length of a signature on the wire: raw IEEE P1363 `r || s`, the form WebCrypto verifies directly.
pub const SIG_LEN: usize = 64;

/// The one engine behind every base64 field handed to the extension (proof frames, the signed policy
/// baseline), so the two sides can never pick different alphabets.
pub fn base64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Accepts only what [`base64_encode`] emits: the STANDARD engine refuses missing padding and nonzero
/// trailing bits (`Zh==`), so a signed document has exactly one spelling (policy/store.rs relies on this).
pub fn base64_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::STANDARD.decode(input)
}

/// Prefix of the credential-store entry name; store.rs appends the runtime directory's digest. Versioned so
/// an algorithm change writes under a new prefix instead of colliding with old entries.
pub const KEY_LABEL: &str = "com.vivswan.chromium-bridge.enclave.signing.v1";

/// The PUBLIC scalar the golden fixture is signed with (`examples/emit_enclave_contract.rs`), well-known so
/// regeneration is deterministic. Anyone can sign with it, so it is never an enrollment identity:
///
/// ```text
/// host side      -> [`ensure_not_fixture_key`] refuses it when a handle is built
/// extension side -> `ENCLAVE_FIXTURE_KEY_ID` in the generated enclave module refuses it at pairing and on
///                   the stored pin
/// ```
pub const FIXTURE_KEY_BYTES: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

/// Lowercase-hex SHA-256 of [`FIXTURE_KEY_BYTES`]' X9.63 point: the deny-listed identity. Derived only at
/// fixture generation, so `fixture_key_is_pinned_and_refused` holds the pin when nobody runs gen.
pub const FIXTURE_KEY_ID: &str = "4269889431e3131966fcaf6a457141943ed2c35b5b917ae62cb339546f523551";

/// A substituted host binary skips this check, so the load-bearing deny-list is the extension's
/// (`ENCLAVE_FIXTURE_KEY_ID`); this one keeps a planted file record from ever becoming a handle. The
/// fingerprint is public, so the compare needs no constant time.
pub fn ensure_not_fixture_key(public: &EnclavePublicKey) -> Result<(), EnclaveError> {
    if public.fingerprint_hex() == FIXTURE_KEY_ID {
        return Err(EnclaveError::KeyInvalid(
            "the public golden-fixture key is never enrollable",
        ));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum EnclaveError {
    #[error("no host key found - run `chromium-bridge pair` first")]
    NotEnrolled,
    #[error("invalid challenge: {0}")]
    InvalidChallenge(&'static str),
    #[error("host key rejected: {0}")]
    KeyInvalid(&'static str),
    /// The credential store or the host key record could not be read or written.
    #[error("key store: {0}")]
    Keychain(String),
    #[error("signing: {0}")]
    Signing(String),
}

/// The extension branches on these strings, so the set is append-only;
/// `reason_codes_are_exactly_the_emitted_set` ties it to [`REASON_CODES`].
pub fn reason_code(e: &EnclaveError) -> &'static str {
    match e {
        EnclaveError::NotEnrolled => "not_enrolled",
        EnclaveError::InvalidChallenge(_) => "invalid_challenge",
        EnclaveError::KeyInvalid(_) => "key_invalid",
        EnclaveError::Keychain(_) => "keychain_error",
        EnclaveError::Signing(_) => "signing_failed",
    }
}

/// The closed set [`reason_code`] emits, in variant order; `moon run gen` emits it to the TS side as a union.
pub const REASON_CODES: [&str; 5] = [
    "not_enrolled",
    "invalid_challenge",
    "key_invalid",
    "keychain_error",
    "signing_failed",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The generated TS union is the external contract: a variant added without a REASON_CODES entry would
    /// emit a code the extension's compromise latch has never seen.
    #[test]
    fn reason_codes_are_exactly_the_emitted_set() {
        let samples = [
            EnclaveError::NotEnrolled,
            EnclaveError::InvalidChallenge("x"),
            EnclaveError::KeyInvalid("x"),
            EnclaveError::Keychain(String::new()),
            EnclaveError::Signing(String::new()),
        ];
        let produced: Vec<&str> = samples.iter().map(reason_code).collect();
        assert_eq!(produced, REASON_CODES);
        let mut deduped = produced.clone();
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(deduped.len(), REASON_CODES.len(), "two codes collapsed");
    }

    /// The one-spelling guarantee the policy store relies on comes from the
    /// engine's configuration, not from code of ours, so it is pinned here.
    #[test]
    fn base64_decode_accepts_exactly_one_spelling_per_byte_string() {
        for bad in [
            // Missing or short padding.
            "Z", "Zg", "Zg=", "Zm9vYQ",
            // Bytes outside the standard alphabet (whitespace, url-safe,
            // non-ASCII).
            "Zm9v\n", "Zm 9v", "Zm9-", "Zm9_", "Zm\u{e9}",
            // Malformed or misplaced padding.
            "====", "Z===", "Zg=v", "Zg==Zg==", "Zm8=Zm8=",
            // Nonzero trailing bits: the canonical spellings are "Zg==" and
            // "Zm8=".
            "Zh==", "Zm9=",
        ] {
            assert!(base64_decode(bad).is_err(), "{bad:?} must be refused");
        }
        for (bytes, canonical) in [(&b"f"[..], "Zg=="), (b"fo", "Zm8="), (b"foo", "Zm9v")] {
            assert_eq!(base64_encode(bytes), canonical, "{bytes:?} encodes once");
            assert_eq!(
                base64_decode(canonical).unwrap(),
                bytes,
                "{canonical} decodes"
            );
        }
    }

    /// FIXTURE_KEY_ID is derived from FIXTURE_KEY_BYTES at generation time only; this holds the pin when
    /// nobody runs gen, and the deny-list is exactly one identity wide.
    #[test]
    fn fixture_key_is_pinned_and_refused() {
        use p256::ecdsa::SigningKey;

        let sk = SigningKey::from_slice(&FIXTURE_KEY_BYTES)
            .expect("the fixture scalar is a valid P-256 key");
        let point = sk.verifying_key().to_sec1_point(false);
        let public = EnclavePublicKey::from_x963(point.as_bytes().to_vec())
            .expect("p256 emits the X9.63 uncompressed point");
        assert_eq!(public.fingerprint_hex(), FIXTURE_KEY_ID);

        let refused = ensure_not_fixture_key(&public).unwrap_err();
        assert_eq!(reason_code(&refused), "key_invalid");
        assert!(refused.to_string().contains("never enrollable"));

        let other = SigningKey::from_slice(&[0x42; 32]).expect("valid scalar");
        let other_public = EnclavePublicKey::from_x963(
            other
                .verifying_key()
                .to_sec1_point(false)
                .as_bytes()
                .to_vec(),
        )
        .expect("valid point");
        assert!(ensure_not_fixture_key(&other_public).is_ok());
    }
}
