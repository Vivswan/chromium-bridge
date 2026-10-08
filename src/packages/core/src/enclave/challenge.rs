use super::EnclaveError;
use crate::webauthn::{bounded_nul_free, FieldFault, MAX_NONCE_LEN};

/// Domain separation for the pair / verify ceremony: a proof can never be replayed as a signature over
/// another meaning of the same bytes.
pub const CHALLENGE_DOMAIN: &str = "genkan-enclave-v1";

/// Distinct from [`CHALLENGE_DOMAIN`] so a policy signature is never a challenge proof, nor a proof a policy.
pub const POLICY_DOMAIN: &str = "genkan-policy-v1";

/// Bounds on attacker-supplied challenge fields (the extension relays them
/// from its own logic today, but zero trust says bound them anyway).
pub const MAX_CONTEXT_LEN: usize = 4096;

/// The exact bytes a CHALLENGE signature covers; the extension rebuilds them byte for byte before WebCrypto
/// verifies. The NUL separators make the encoding injective, so both fields must be NUL-free.
///
/// ```text
/// UTF8(CHALLENGE_DOMAIN) || 0x00 || UTF8(nonce) || 0x00 || UTF8(context or "")
/// ```
pub fn challenge_message(nonce: &str, context: Option<&str>) -> Result<Vec<u8>, EnclaveError> {
    domain_message(CHALLENGE_DOMAIN, nonce, context)
}

/// The exact bytes a POLICY signature covers: the document as stored, no canonicalization, NULs allowed.
/// Injectivity across domains holds because both domain constants are NUL-free and neither prefixes the other
/// (`the_two_domains_can_never_collide`).
///
/// ```text
/// UTF8(POLICY_DOMAIN) || 0x00 || doc_bytes
/// ```
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
    match bounded_nul_free(nonce, MAX_NONCE_LEN) {
        Ok(()) => {}
        Err(FieldFault::Empty) => return Err(EnclaveError::InvalidChallenge("empty nonce")),
        Err(FieldFault::TooLong) => return Err(EnclaveError::InvalidChallenge("nonce too long")),
        Err(FieldFault::Nul) => return Err(EnclaveError::InvalidChallenge("nonce contains NUL")),
    }
    let context = context.unwrap_or("");
    match bounded_nul_free(context, MAX_CONTEXT_LEN) {
        Ok(()) | Err(FieldFault::Empty) => {}
        Err(FieldFault::TooLong) => return Err(EnclaveError::InvalidChallenge("context too long")),
        Err(FieldFault::Nul) => return Err(EnclaveError::InvalidChallenge("context contains NUL")),
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

    /// The extension rebuilds these bytes before WebCrypto verifies, and protocol/control.rs promises that
    /// an absent context and "" sign identically while no nonce can borrow the context's bytes.
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

        assert_eq!(
            challenge_message("abc", None).unwrap(),
            challenge_message("abc", Some("")).unwrap()
        );
        assert_ne!(
            challenge_message("ab", Some("c")).unwrap(),
            challenge_message("abc", None).unwrap()
        );
    }

    /// The refusal texts are what `respond_to_challenge` logs, and the bounds are the contract
    /// protocol/control.rs states: a field at the bound signs, one past it is refused.
    #[test]
    fn challenge_message_rejects_bad_fields() {
        let long_nonce = "x".repeat(MAX_NONCE_LEN + 1);
        let max_nonce = "x".repeat(MAX_NONCE_LEN);
        let long_context = "x".repeat(MAX_CONTEXT_LEN + 1);
        let max_context = "x".repeat(MAX_CONTEXT_LEN);
        let cases = [
            (
                "empty nonce",
                "",
                None,
                Err("invalid challenge: empty nonce"),
            ),
            (
                "nonce past the bound",
                &long_nonce,
                None,
                Err("invalid challenge: nonce too long"),
            ),
            (
                "NUL in the nonce",
                "a\0b",
                None,
                Err("invalid challenge: nonce contains NUL"),
            ),
            (
                "NUL in the context",
                "ok",
                Some("a\0b"),
                Err("invalid challenge: context contains NUL"),
            ),
            (
                "context past the bound",
                "ok",
                Some(&long_context),
                Err("invalid challenge: context too long"),
            ),
            ("nonce at the bound", &max_nonce, None, Ok(())),
            ("context at the bound", "ok", Some(&max_context), Ok(())),
        ];
        for (case, nonce, context, expected) in cases {
            let got = challenge_message(nonce, context)
                .map(drop)
                .map_err(|e| e.to_string());
            assert_eq!(
                got.as_ref().map(drop).map_err(String::as_str),
                expected,
                "{case}"
            );
        }
    }

    #[test]
    fn policy_message_is_exact_domain_nul_doc() {
        let m = policy_message(b"doc-bytes");
        let mut expected = Vec::new();
        expected.extend_from_slice(POLICY_DOMAIN.as_bytes());
        expected.push(0);
        expected.extend_from_slice(b"doc-bytes");
        assert_eq!(m, expected);
        // Empty and NUL-carrying documents are legal: the bytes are signed as stored.
        assert_eq!(policy_message(b""), {
            let mut e = POLICY_DOMAIN.as_bytes().to_vec();
            e.push(0);
            e
        });
        assert_ne!(policy_message(b"a\0b"), policy_message(b"a\0c"));
    }

    /// The domain constants are distinct, NUL-free, and neither is a prefix of the other, so the bytes before
    /// the first NUL identify the domain of any message. The hard case: a policy document embedding a NUL
    /// where the challenge shape puts its separator matches a challenge message byte for byte after the domain.
    #[test]
    fn the_two_domains_can_never_collide() {
        for domain in [CHALLENGE_DOMAIN, POLICY_DOMAIN] {
            assert!(!domain.contains('\0'), "{domain} must be NUL-free");
        }
        assert_ne!(CHALLENGE_DOMAIN, POLICY_DOMAIN);
        assert!(!CHALLENGE_DOMAIN.starts_with(POLICY_DOMAIN));
        assert!(!POLICY_DOMAIN.starts_with(CHALLENGE_DOMAIN));

        let challenge = challenge_message("nonce", Some("ctx")).unwrap();
        let policy = policy_message(b"nonce\0ctx");
        assert_ne!(challenge, policy);
        assert!(challenge.starts_with(CHALLENGE_DOMAIN.as_bytes()));
        assert!(policy.starts_with(POLICY_DOMAIN.as_bytes()));
    }
}
