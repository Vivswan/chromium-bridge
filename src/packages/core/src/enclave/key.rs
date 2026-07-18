//! The cross-platform enrollment key handle and the native-host challenge
//! responder.

use crate::protocol::EnclaveControl;

use super::challenge::{challenge_message, presence_message};
use super::encoding::base64_encode;
use super::pubkey::EnclavePublicKey;
use super::{reason_code, EnclaveError};

/// Handle to the (Enclave-resident) enrollment key. On macOS it wraps a
/// `SecKey`; on other platforms it cannot be constructed and every entry
/// point fails closed with [`EnclaveError::Unsupported`].
pub struct EnrollmentKey {
    #[cfg(target_os = "macos")]
    key: security_framework::key::SecKey,
}

impl EnrollmentKey {
    /// Look up the enrollment key minted by a previous `pair`.
    pub fn lookup() -> Result<Option<Self>, EnclaveError> {
        #[cfg(target_os = "macos")]
        {
            Ok(super::macos::lookup()?.map(|key| Self { key }))
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(EnclaveError::Unsupported)
        }
    }

    /// Mint a fresh enrollment key in the Secure Enclave.
    pub fn mint() -> Result<Self, EnclaveError> {
        #[cfg(target_os = "macos")]
        {
            Ok(Self {
                key: super::macos::generate()?,
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(EnclaveError::Unsupported)
        }
    }

    /// Delete the enrollment key wherever it is stored. Returns whether one
    /// existed.
    pub fn revoke() -> Result<bool, EnclaveError> {
        #[cfg(target_os = "macos")]
        {
            super::macos::delete()
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(EnclaveError::Unsupported)
        }
    }

    pub fn public_key(&self) -> Result<EnclavePublicKey, EnclaveError> {
        #[cfg(target_os = "macos")]
        {
            super::macos::public_key(&self.key)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(EnclaveError::Unsupported)
        }
    }

    /// Sign an enrollment challenge (raises the presence prompt) and return
    /// the raw 64-byte P1363 signature.
    pub fn sign_challenge(
        &self,
        nonce: &str,
        context: Option<&str>,
    ) -> Result<[u8; 64], EnclaveError> {
        self.sign_message(challenge_message(nonce, context)?)
    }

    /// Sign a per-action presence challenge (ADR-0031) under the presence
    /// domain (raises the presence prompt - the Touch ID tap IS the
    /// approval) and return the raw 64-byte P1363 signature.
    pub fn sign_presence(
        &self,
        nonce: &str,
        context: Option<&str>,
    ) -> Result<[u8; 64], EnclaveError> {
        self.sign_message(presence_message(nonce, context)?)
    }

    fn sign_message(&self, message: Vec<u8>) -> Result<[u8; 64], EnclaveError> {
        #[cfg(target_os = "macos")]
        {
            super::macos::sign(&self.key, &message)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = message;
            Err(EnclaveError::Unsupported)
        }
    }
}

/// Answer an `enclave_challenge` control frame: look the key up, sign the
/// challenge (presence prompt), and build the proof — or a typed error frame.
/// Never panics and never leaks key material; detailed failure context goes to
/// stderr, the extension only sees the stable reason code.
pub fn respond_to_challenge(nonce: &str, context: Option<&str>) -> EnclaveControl {
    match challenge_proof(nonce, context, Purpose::Enrollment) {
        Ok(frame) => frame,
        Err(e) => {
            log_warn!("enclave", "challenge failed: {e}");
            EnclaveControl::EnclaveError {
                reason: reason_code(&e).to_string(),
            }
        }
    }
}

/// Answer a `presence_challenge` control frame (ADR-0031): sign the
/// per-action presence statement under the presence domain, raising the
/// user-presence prompt - the Touch ID tap is the approval the extension
/// verifies against its pinned key. Same fail-closed shape as
/// [`respond_to_challenge`], with the presence frame types.
pub fn respond_to_presence_challenge(nonce: &str, context: Option<&str>) -> EnclaveControl {
    match challenge_proof(nonce, context, Purpose::Presence) {
        Ok(frame) => frame,
        Err(e) => {
            log_warn!("enclave", "presence challenge failed: {e}");
            EnclaveControl::PresenceError {
                reason: reason_code(&e).to_string(),
            }
        }
    }
}

/// Which statement type a proof is for; picks the signature domain and the
/// reply frame shape.
#[derive(Clone, Copy)]
enum Purpose {
    Enrollment,
    Presence,
}

fn challenge_proof(
    nonce: &str,
    context: Option<&str>,
    purpose: Purpose,
) -> Result<EnclaveControl, EnclaveError> {
    // Validate the challenge before touching the keychain, so malformed input
    // cannot trigger a presence prompt. Both domains share one validation
    // matrix; building the message is the validation.
    match purpose {
        Purpose::Enrollment => challenge_message(nonce, context)?,
        Purpose::Presence => presence_message(nonce, context)?,
    };
    let key = EnrollmentKey::lookup()?.ok_or(EnclaveError::NotEnrolled)?;
    let public = key.public_key()?;
    let (sig, frame): (_, fn(String, String, String) -> EnclaveControl) = match purpose {
        Purpose::Enrollment => (
            key.sign_challenge(nonce, context)?,
            |sig, key_id, pubkey| EnclaveControl::EnclaveProof {
                sig,
                key_id,
                pubkey,
            },
        ),
        Purpose::Presence => (key.sign_presence(nonce, context)?, |sig, key_id, pubkey| {
            EnclaveControl::PresenceProof {
                sig,
                key_id,
                pubkey,
            }
        }),
    };
    Ok(frame(
        base64_encode(&sig),
        public.fingerprint_hex(),
        public.to_base64(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn non_macos_fails_closed_with_unsupported() {
        assert!(matches!(
            EnrollmentKey::lookup(),
            Err(EnclaveError::Unsupported)
        ));
        assert!(matches!(
            EnrollmentKey::mint(),
            Err(EnclaveError::Unsupported)
        ));
        assert!(matches!(
            EnrollmentKey::revoke(),
            Err(EnclaveError::Unsupported)
        ));
        // And the challenge paths report the stable reason code, each in its
        // own frame family.
        match respond_to_challenge("nonce", None) {
            EnclaveControl::EnclaveError { reason } => {
                assert_eq!(reason, "unsupported_platform");
            }
            other => panic!("expected enclave_error, got {other:?}"),
        }
        match respond_to_presence_challenge("nonce", None) {
            EnclaveControl::PresenceError { reason } => {
                assert_eq!(reason, "unsupported_platform");
            }
            other => panic!("expected presence_error, got {other:?}"),
        }
    }

    #[test]
    fn malformed_challenge_yields_invalid_challenge_before_any_keychain_io() {
        // NUL in the nonce: rejected by validation, so the reply is
        // invalid_challenge on every platform (no keychain lookup happens).
        match respond_to_challenge("a\0b", None) {
            EnclaveControl::EnclaveError { reason } => {
                assert_eq!(reason, "invalid_challenge");
            }
            other => panic!("expected enclave_error, got {other:?}"),
        }
        // The presence responder validates identically, in its own frame
        // family - and on macOS this must refuse BEFORE the keychain, or the
        // test itself would raise a presence prompt.
        match respond_to_presence_challenge("a\0b", None) {
            EnclaveControl::PresenceError { reason } => {
                assert_eq!(reason, "invalid_challenge");
            }
            other => panic!("expected presence_error, got {other:?}"),
        }
    }
}
