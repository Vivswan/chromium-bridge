//! Every way an assertion or a registration is refused, each a named variant with a stable wire code the
//! extension can show. A refusal is never a boolean: the audit trail and the user see which check failed.

use std::fmt;

use super::authenticator_data::AuthDataError;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
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
    #[error("attestation format {got:?} is not \"none\"")]
    AttestationFormat { got: String },
    #[error("attestation statement is not empty")]
    AttestationStatementNotEmpty,
    #[error("registration carries no attested credential data")]
    NoAttestedCredential,
}

impl Refusal {
    /// The stable snake_case code the result frames carry.
    pub fn code(&self) -> RefusalCode {
        match self {
            Refusal::Encoding { .. } => RefusalCode::Encoding,
            Refusal::AuthenticatorData(AuthDataError::TooShort { .. }) => {
                RefusalCode::AuthdataTooShort
            }
            Refusal::AuthenticatorData(AuthDataError::ReservedFlags { .. }) => {
                RefusalCode::AuthdataReservedFlags
            }
            Refusal::AuthenticatorData(AuthDataError::Extensions) => {
                RefusalCode::AuthdataExtensions
            }
            Refusal::AuthenticatorData(AuthDataError::BackupStateWithoutEligibility) => {
                RefusalCode::AuthdataBackupStateWithoutEligibility
            }
            Refusal::AuthenticatorData(AuthDataError::AttestedCredentialTruncated) => {
                RefusalCode::AuthdataAttestedTruncated
            }
            Refusal::AuthenticatorData(AuthDataError::CredentialId(_)) => {
                RefusalCode::CredentialIdInvalid
            }
            Refusal::AuthenticatorData(AuthDataError::PublicKey(_)) => {
                RefusalCode::PublicKeyInvalid
            }
            Refusal::AuthenticatorData(AuthDataError::TrailingBytes { .. }) => {
                RefusalCode::AuthdataTrailingBytes
            }
            Refusal::UnexpectedAttestedCredential => RefusalCode::UnexpectedAttestedCredential,
            Refusal::RpIdMismatch => RefusalCode::RpIdMismatch,
            Refusal::UserNotPresent => RefusalCode::UserNotPresent,
            Refusal::SignCountNotIncreased { .. } => RefusalCode::SignCountNotIncreased,
            Refusal::BackupEligibilityChanged { .. } => RefusalCode::BackupEligibilityChanged,
            Refusal::ClientDataMalformed => RefusalCode::ClientDataMalformed,
            Refusal::ClientDataType { .. } => RefusalCode::ClientDataType,
            Refusal::ChallengeMismatch => RefusalCode::ChallengeMismatch,
            Refusal::OriginMismatch { .. } => RefusalCode::OriginMismatch,
            Refusal::CrossOrigin => RefusalCode::CrossOrigin,
            Refusal::SignatureMalformed => RefusalCode::SignatureMalformed,
            Refusal::SignatureInvalid => RefusalCode::SignatureInvalid,
            Refusal::AttestationMalformed => RefusalCode::AttestationMalformed,
            Refusal::AttestationTrailingBytes { .. } => RefusalCode::AttestationTrailingBytes,
            Refusal::AttestationFormat { .. } => RefusalCode::AttestationFormat,
            Refusal::AttestationStatementNotEmpty => RefusalCode::AttestationStatementNotEmpty,
            Refusal::NoAttestedCredential => RefusalCode::NoAttestedCredential,
        }
    }
}

/// Every reason code a refused `presence_result` or `enroll_result` can carry: the one vocabulary the
/// extension's pages key their sentences on (src/apps/extension/src/lib/refusals.ts, typed from
/// the roster `emit_contract` walks). The host mints a reason from a variant alone, so a code the page has
/// no sentence for cannot leave this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::Display, strum::VariantArray)]
#[strum(serialize_all = "snake_case")]
pub enum RefusalCode {
    // the verifier ([`Refusal`])
    Encoding,
    AuthdataTooShort,
    AuthdataReservedFlags,
    AuthdataExtensions,
    AuthdataBackupStateWithoutEligibility,
    AuthdataAttestedTruncated,
    AuthdataTrailingBytes,
    CredentialIdInvalid,
    PublicKeyInvalid,
    UnexpectedAttestedCredential,
    RpIdMismatch,
    UserNotPresent,
    SignCountNotIncreased,
    BackupEligibilityChanged,
    ClientDataMalformed,
    ClientDataType,
    ChallengeMismatch,
    OriginMismatch,
    CrossOrigin,
    SignatureMalformed,
    SignatureInvalid,
    AttestationMalformed,
    AttestationTrailingBytes,
    AttestationFormat,
    AttestationStatementNotEmpty,
    NoAttestedCredential,
    // the presence gate (`crate::presence::PresenceError`)
    NotInteractive,
    Declined,
    IoError,
    CredentialNotEnrolled,
    WrongBrowserLabel,
    SoftwareConfirmationNotAllowed,
    RequestMismatch,
    StoreError,
    // the exchange itself (`crate::native_host::presence`)
    PresenceRequired,
    Nonce,
    NoRequestOutstanding,
    NoEnrollmentOutstanding,
    MachineAlreadyEnrolled,
    /// `browser_revoke` from a browser with nothing enrolled.
    NotEnrolled,
    /// A `presence_begin` named something other than the two page operations the host mints requests for.
    InvalidAction,
    /// A `presence_begin` named an origin the host mints no statement for: an opaque `null`, or one shaped
    /// outside what `Origin::parse` admits.
    InvalidOrigin,
}

impl RefusalCode {
    pub fn detailed(self, detail: impl fmt::Display) -> Reason {
        Reason {
            code: self,
            detail: Some(detail.to_string()),
        }
    }
}

/// The `reason` a refused result frame carries: the code, then `: <detail>` when the host has one. The
/// options page splits at the first `: `, so the detail may hold anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason {
    code: RefusalCode,
    detail: Option<String>,
}

impl From<RefusalCode> for Reason {
    fn from(code: RefusalCode) -> Self {
        Reason { code, detail: None }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.detail {
            Some(detail) => write!(f, "{}: {detail}", self.code),
            None => write!(f, "{}", self.code),
        }
    }
}
