//! Challenge message construction: the exact byte string a challenge
//! signature covers, shared as a contract with the extension's WebCrypto
//! verifier.

use super::EnclaveError;

/// Domain-separation prefix for challenge signatures. Binds every signature
/// this key produces to the enrollment protocol, so a proof can never be
/// replayed as a signature over some other meaning of the same bytes.
pub const CHALLENGE_DOMAIN: &str = "chromium-bridge-enclave-v1";

/// Bounds on attacker-supplied challenge fields (the extension relays them
/// from its own logic today, but zero trust says bound them anyway).
pub const MAX_NONCE_LEN: usize = 256;
pub const MAX_CONTEXT_LEN: usize = 4096;

/// Build the exact byte string a challenge signature covers:
///
/// ```text
/// UTF8(CHALLENGE_DOMAIN) || 0x00 || UTF8(nonce) || 0x00 || UTF8(context or "")
/// ```
///
/// The NUL separators make the encoding injective (no nonce/context pair can
/// collide with another), so both fields must be NUL-free; they are also
/// length-bounded. The extension must reconstruct this byte string exactly to
/// verify the proof with WebCrypto.
pub fn challenge_message(nonce: &str, context: Option<&str>) -> Result<Vec<u8>, EnclaveError> {
    if nonce.is_empty() {
        return Err(EnclaveError::InvalidChallenge("empty nonce"));
    }
    if nonce.len() > MAX_NONCE_LEN {
        return Err(EnclaveError::InvalidChallenge("nonce too long"));
    }
    if nonce.contains('\0') {
        return Err(EnclaveError::InvalidChallenge("nonce contains NUL"));
    }
    let context = context.unwrap_or("");
    if context.len() > MAX_CONTEXT_LEN {
        return Err(EnclaveError::InvalidChallenge("context too long"));
    }
    if context.contains('\0') {
        return Err(EnclaveError::InvalidChallenge("context contains NUL"));
    }
    let mut msg = Vec::with_capacity(CHALLENGE_DOMAIN.len() + nonce.len() + context.len() + 2);
    msg.extend_from_slice(CHALLENGE_DOMAIN.as_bytes());
    msg.push(0);
    msg.extend_from_slice(nonce.as_bytes());
    msg.push(0);
    msg.extend_from_slice(context.as_bytes());
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_message_is_domain_separated_and_injective() {
        let m = challenge_message("abc", Some("ctx")).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(CHALLENGE_DOMAIN.as_bytes());
        expected.push(0);
        expected.extend_from_slice(b"abc");
        expected.push(0);
        expected.extend_from_slice(b"ctx");
        assert_eq!(m, expected);

        // No context serializes as an empty context, and cannot collide with
        // a nonce that happens to contain the other field's bytes.
        assert_eq!(
            challenge_message("abc", None).unwrap(),
            challenge_message("abc", Some("")).unwrap()
        );
        assert_ne!(
            challenge_message("ab", Some("c")).unwrap(),
            challenge_message("abc", None).unwrap()
        );
    }

    #[test]
    fn challenge_message_rejects_bad_fields() {
        assert!(matches!(
            challenge_message("", None),
            Err(EnclaveError::InvalidChallenge(_))
        ));
        assert!(challenge_message(&"x".repeat(MAX_NONCE_LEN + 1), None).is_err());
        assert!(challenge_message("a\0b", None).is_err());
        assert!(challenge_message("ok", Some("a\0b")).is_err());
        assert!(challenge_message("ok", Some(&"x".repeat(MAX_CONTEXT_LEN + 1))).is_err());
        // At the bounds is fine.
        assert!(challenge_message(&"x".repeat(MAX_NONCE_LEN), None).is_ok());
        assert!(challenge_message("ok", Some(&"x".repeat(MAX_CONTEXT_LEN))).is_ok());
    }
}
