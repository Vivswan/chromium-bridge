//! Challenge message construction: the exact byte strings the enrollment and
//! presence signatures cover, shared as a contract with the extension's
//! WebCrypto verifier.

use super::EnclaveError;

/// Domain-separation prefix for ENROLLMENT challenge signatures (the pair /
/// verify ceremony, ADR-0021). Binds every such signature to the enrollment
/// protocol, so a proof can never be replayed as a signature over some other
/// meaning of the same bytes.
pub const CHALLENGE_DOMAIN: &str = "chromium-bridge-enclave-v1";

/// Domain-separation prefix for PER-ACTION user-presence signatures
/// (ADR-0031): the Touch ID approval of one `page_eval` / `page_upload`
/// confirmation. A distinct domain from [`CHALLENGE_DOMAIN`] on purpose, so
/// the two statement types - "I am the enrolled host" and "the user approved
/// this one action" - can never be replayed as one another, even if the
/// extension's nonce handling ever regressed.
pub const PRESENCE_DOMAIN: &str = "chromium-bridge-presence-v1";

/// Bounds on attacker-supplied challenge fields (the extension relays them
/// from its own logic today, but zero trust says bound them anyway).
pub const MAX_NONCE_LEN: usize = 256;
pub const MAX_CONTEXT_LEN: usize = 4096;

/// Build the exact byte string an ENROLLMENT challenge signature covers:
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
    domain_message(CHALLENGE_DOMAIN, nonce, context)
}

/// Build the exact byte string a PER-ACTION presence signature covers: the
/// same NUL-separated shape as [`challenge_message`], under
/// [`PRESENCE_DOMAIN`].
pub fn presence_message(nonce: &str, context: Option<&str>) -> Result<Vec<u8>, EnclaveError> {
    domain_message(PRESENCE_DOMAIN, nonce, context)
}

fn domain_message(
    domain: &str,
    nonce: &str,
    context: Option<&str>,
) -> Result<Vec<u8>, EnclaveError> {
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
    let mut msg = Vec::with_capacity(domain.len() + nonce.len() + context.len() + 2);
    msg.extend_from_slice(domain.as_bytes());
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
        // The presence builder shares the exact validation matrix.
        assert!(presence_message("", None).is_err());
        assert!(presence_message("a\0b", None).is_err());
        assert!(presence_message("ok", Some(&"x".repeat(MAX_CONTEXT_LEN + 1))).is_err());
        assert!(presence_message("ok", Some(&"x".repeat(MAX_CONTEXT_LEN))).is_ok());
    }

    #[test]
    fn presence_and_enrollment_messages_can_never_collide() {
        // Same nonce, same context: the two domains produce different byte
        // strings, so a signature over one statement type can never verify as
        // the other. The domains are also prefix-incompatible (neither is a
        // prefix of the other up to the first NUL).
        let enroll = challenge_message("nonce", Some("ctx")).unwrap();
        let presence = presence_message("nonce", Some("ctx")).unwrap();
        assert_ne!(enroll, presence);
        assert!(enroll.starts_with(CHALLENGE_DOMAIN.as_bytes()));
        assert!(presence.starts_with(PRESENCE_DOMAIN.as_bytes()));
        assert_ne!(CHALLENGE_DOMAIN, PRESENCE_DOMAIN);
    }
}
