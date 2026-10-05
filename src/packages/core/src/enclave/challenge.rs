//! Challenge message construction: the exact byte strings the host-key challenge and policy signatures
//! cover, shared as a contract with the extension's WebCrypto verifier.

use super::EnclaveError;

/// Domain-separation prefix for host-key CHALLENGE signatures (the pair / verify ceremony). Binds every such
/// signature to the ceremony, so a proof can never be replayed as a signature over some other meaning of the
/// same bytes.
pub const CHALLENGE_DOMAIN: &str = "chromium-bridge-enclave-v1";

/// Domain-separation prefix for POLICY document signatures: the host key's signature over the host-owned
/// policy baseline. Distinct from [`CHALLENGE_DOMAIN`] on purpose, so a policy signature can never be replayed
/// as a challenge proof, nor a proof as a policy.
pub const POLICY_DOMAIN: &str = "chromium-bridge-policy-v1";

/// Bounds on attacker-supplied challenge fields (the extension relays them
/// from its own logic today, but zero trust says bound them anyway).
pub const MAX_NONCE_LEN: usize = 256;
pub const MAX_CONTEXT_LEN: usize = 4096;

/// Build the exact byte string a host-key CHALLENGE signature covers:
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

/// Build the exact byte string a POLICY signature covers:
///
/// ```text
/// UTF8(POLICY_DOMAIN) || 0x00 || doc_bytes
/// ```
///
/// The document is signed exactly as stored, no canonicalization, and MAY contain NULs. Cross-domain injectivity
/// still holds because both domain constants are NUL-free and distinct, so the bytes before the first NUL name
/// the domain unambiguously (pinned by `the_two_domains_can_never_collide` below).
pub fn policy_message(doc_bytes: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(
        POLICY_DOMAIN
            .len()
            .saturating_add(doc_bytes.len())
            .saturating_add(1),
    );
    msg.extend_from_slice(POLICY_DOMAIN.as_bytes());
    msg.push(0);
    msg.extend_from_slice(doc_bytes);
    msg
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
    let mut msg = Vec::with_capacity(
        domain
            .len()
            .saturating_add(nonce.len())
            .saturating_add(context.len())
            .saturating_add(2),
    );
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
    }

    #[test]
    fn policy_message_is_exact_domain_nul_doc() {
        let m = policy_message(b"doc-bytes");
        let mut expected = Vec::new();
        expected.extend_from_slice(POLICY_DOMAIN.as_bytes());
        expected.push(0);
        expected.extend_from_slice(b"doc-bytes");
        assert_eq!(m, expected);
        // Empty and NUL-carrying documents are legal: the doc bytes are
        // signed as-is, and within the policy domain the message is the
        // identity on them.
        assert_eq!(policy_message(b""), {
            let mut e = POLICY_DOMAIN.as_bytes().to_vec();
            e.push(0);
            e
        });
        assert_ne!(policy_message(b"a\0b"), policy_message(b"a\0c"));
    }

    #[test]
    fn the_two_domains_can_never_collide() {
        // The domain constants are distinct, NUL-free, and neither is a prefix of the other, so the bytes
        // before the first NUL identify the domain of any message unambiguously.
        for domain in [CHALLENGE_DOMAIN, POLICY_DOMAIN] {
            assert!(!domain.contains('\0'), "{domain} must be NUL-free");
        }
        assert_ne!(CHALLENGE_DOMAIN, POLICY_DOMAIN);
        assert!(!CHALLENGE_DOMAIN.starts_with(POLICY_DOMAIN));
        assert!(!POLICY_DOMAIN.starts_with(CHALLENGE_DOMAIN));

        // The tricky case: a policy document whose bytes embed a NUL exactly where the challenge shape puts
        // its separator. Everything after the domain matches the challenge message byte for byte, so only
        // the domain prefix keeps them apart.
        let challenge = challenge_message("nonce", Some("ctx")).unwrap();
        let policy = policy_message(b"nonce\0ctx");
        assert_ne!(challenge, policy);
        assert!(challenge.starts_with(CHALLENGE_DOMAIN.as_bytes()));
        assert!(policy.starts_with(POLICY_DOMAIN.as_bytes()));
    }
}
