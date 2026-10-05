//! Every way an assertion or a registration is refused, each a named variant with a stable wire code the
//! extension can show. A refusal is never a boolean: the audit trail and the user see which check failed.

use super::authenticator_data::AuthDataError;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// A base64url field did not decode; `field` names it.
    #[error("{field} is not base64url")]
    Encoding { field: &'static str },
    #[error(transparent)]
    AuthenticatorData(AuthDataError),
    /// An assertion carrying attested credential data: a registration response answering a presence request.
    #[error("assertion carries attested credential data")]
    UnexpectedAttestedCredential,
    #[error("rpIdHash is not the hash of this extension's id")]
    RpIdMismatch,
    #[error("the UP flag is clear: no user gesture was made")]
    UserNotPresent,
    /// Either counter nonzero and the received one not strictly greater: a cloned authenticator or a replay.
    #[error("signCount {received} did not increase past the stored {stored}")]
    SignCountNotIncreased { stored: u32, received: u32 },
    /// Backup eligibility is fixed at creation; a change means another credential source is answering.
    #[error("backup eligibility {received} differs from the enrolled {stored}")]
    BackupEligibilityChanged { stored: bool, received: bool },
    #[error("clientDataJSON is not the JSON object the WebAuthn client writes")]
    ClientDataMalformed,
    #[error("clientDataJSON.type is {got:?}, not {want:?}")]
    ClientDataType { got: String, want: &'static str },
    #[error("clientDataJSON.challenge is not this statement's challenge")]
    ChallengeMismatch,
    #[error("clientDataJSON.origin {got:?} is not this extension's origin")]
    OriginMismatch { got: String },
    /// `crossOrigin: true`, or a `topOrigin` (which only a cross-origin ceremony carries).
    #[error("clientDataJSON describes a cross-origin ceremony")]
    CrossOrigin,
    #[error("signature is not a DER ECDSA signature")]
    SignatureMalformed,
    #[error("signature does not verify under the credential's public key")]
    SignatureInvalid,
    #[error("attestationObject is not the CBOR map {{ fmt, attStmt, authData }}")]
    AttestationMalformed,
    #[error("{len} unparsed bytes follow the attestation object")]
    AttestationTrailingBytes { len: usize },
    /// Only `none` is accepted: this host never trusts an attestation chain, so no other format is parsed.
    #[error("attestation format {got:?} is not \"none\"")]
    AttestationFormat { got: String },
    #[error("attestation statement is not empty")]
    AttestationStatementNotEmpty,
    #[error("registration carries no attested credential data")]
    NoAttestedCredential,
}

impl Refusal {
    /// The stable snake_case code the result frames carry.
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::Encoding { .. } => "encoding",
            Refusal::AuthenticatorData(AuthDataError::TooShort { .. }) => "authdata_too_short",
            Refusal::AuthenticatorData(AuthDataError::ReservedFlags { .. }) => {
                "authdata_reserved_flags"
            }
            Refusal::AuthenticatorData(AuthDataError::Extensions) => "authdata_extensions",
            Refusal::AuthenticatorData(AuthDataError::BackupStateWithoutEligibility) => {
                "authdata_backup_state_without_eligibility"
            }
            Refusal::AuthenticatorData(AuthDataError::AttestedCredentialTruncated) => {
                "authdata_attested_truncated"
            }
            Refusal::AuthenticatorData(AuthDataError::CredentialId(_)) => "credential_id_invalid",
            Refusal::AuthenticatorData(AuthDataError::PublicKey(_)) => "public_key_invalid",
            Refusal::AuthenticatorData(AuthDataError::TrailingBytes { .. }) => {
                "authdata_trailing_bytes"
            }
            Refusal::UnexpectedAttestedCredential => "unexpected_attested_credential",
            Refusal::RpIdMismatch => "rp_id_mismatch",
            Refusal::UserNotPresent => "user_not_present",
            Refusal::SignCountNotIncreased { .. } => "sign_count_not_increased",
            Refusal::BackupEligibilityChanged { .. } => "backup_eligibility_changed",
            Refusal::ClientDataMalformed => "client_data_malformed",
            Refusal::ClientDataType { .. } => "client_data_type",
            Refusal::ChallengeMismatch => "challenge_mismatch",
            Refusal::OriginMismatch { .. } => "origin_mismatch",
            Refusal::CrossOrigin => "cross_origin",
            Refusal::SignatureMalformed => "signature_malformed",
            Refusal::SignatureInvalid => "signature_invalid",
            Refusal::AttestationMalformed => "attestation_malformed",
            Refusal::AttestationTrailingBytes { .. } => "attestation_trailing_bytes",
            Refusal::AttestationFormat { .. } => "attestation_format",
            Refusal::AttestationStatementNotEmpty => "attestation_statement_not_empty",
            Refusal::NoAttestedCredential => "no_attested_credential",
        }
    }
}
