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
pub use cli::{run_pair, run_presence_selftest, run_revoke, run_status, run_status_json};
pub use config::HostConfig;
pub use der::der_to_raw_signature;
pub use encoding::base64_encode;
pub use key::{respond_to_challenge, respond_to_presence_challenge, EnrollmentKey};
pub use pubkey::EnclavePublicKey;

/// Keychain label of the enrollment signing key. Stable across processes: the
/// `pair` CLI mints under this label and the Chrome-spawned `--native-host`
/// process finds the key by searching for it. Versioned so a future algorithm
/// change can mint under a new label without colliding with the old key.
pub const KEY_LABEL: &str = "com.vivswan.chromium-bridge.enclave.signing.v1";

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
/// matches on these; keep them append-only.
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
