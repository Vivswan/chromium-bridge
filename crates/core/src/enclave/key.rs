//! The cross-platform enrollment key handle and the native-host challenge
//! responder.

use crate::protocol::EnclaveControl;

use super::challenge::challenge_message;
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

    /// Sign a challenge (raises the presence prompt) and return the raw
    /// 64-byte P1363 signature.
    pub fn sign_challenge(
        &self,
        nonce: &str,
        context: Option<&str>,
    ) -> Result<[u8; 64], EnclaveError> {
        let message = challenge_message(nonce, context)?;
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
    match challenge_proof(nonce, context) {
        Ok(frame) => frame,
        Err(e) => {
            log_warn!("enclave", "challenge failed: {e}");
            EnclaveControl::EnclaveError {
                reason: reason_code(&e).to_string(),
            }
        }
    }
}

fn challenge_proof(nonce: &str, context: Option<&str>) -> Result<EnclaveControl, EnclaveError> {
    // Validate the challenge before touching the keychain, so malformed input
    // cannot trigger a presence prompt.
    challenge_message(nonce, context)?;
    let key = EnrollmentKey::lookup()?.ok_or(EnclaveError::NotEnrolled)?;
    let public = key.public_key()?;
    let sig = key.sign_challenge(nonce, context)?;
    Ok(EnclaveControl::EnclaveProof {
        sig: base64_encode(&sig),
        key_id: public.fingerprint_hex(),
        pubkey: public.to_base64(),
    })
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
        // And the challenge path reports the stable reason code.
        match respond_to_challenge("nonce", None) {
            EnclaveControl::EnclaveError { reason } => {
                assert_eq!(reason, "unsupported_platform");
            }
            other => panic!("expected enclave_error, got {other:?}"),
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
    }
}
