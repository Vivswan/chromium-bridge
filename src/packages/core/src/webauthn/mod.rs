//! WebAuthn user presence: the host-side verifier for the assertions the extension makes with the
//! browser's platform authenticator (Touch ID, Windows Hello, a FIDO2 key). Every capability-granting act
//! needs a signature only a human gesture can produce; the extension is the WebAuthn client and this module
//! is the relying party, verifying against the credential public key recorded at enrollment.
//!
//! ```text
//! host    statement (domain || browser label || action || nonce) -> challenge = sha256(statement)
//! ext     navigator.credentials.get({ challenge, rpId: <extension id> })   <- the human gesture
//! host    verify_assertion: rpIdHash, UP flag, signCount, clientDataJSON, ECDSA P-256 over
//!         authenticatorData || sha256(clientDataJSON)
//! ```
//!
//! `chrome-extension://<id>` is a valid WebAuthn origin whose RP ID is the extension id, so the only RP this
//! host ever serves is [`RpId::pinned`]. Attestation is never trusted: registration accepts `fmt: "none"`
//! only and takes the credential key from `attestedCredentialData`. Every refusal is a named variant.

mod authenticator_data;
mod base64url;
mod client_data;
mod credential;
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod encode;
mod refusal;
mod registration;
mod statement;
mod store;
mod verify;

#[cfg(test)]
mod tests;

pub use authenticator_data::{
    AttestedCredential, AuthDataError, AuthenticatorData, BackupState, Flags,
    MAX_CREDENTIAL_ID_LEN, MIN_CREDENTIAL_ID_LEN,
};
pub use base64url::{decode as base64url_decode, encode as base64url_encode};
pub use credential::{
    CosePublicKey, Credential, CredentialId, CredentialIdError, KeyRefusal, RpId,
};
pub use refusal::Refusal;
pub use registration::{parse_registration, Registered, Registration};
pub use statement::{
    Action, Challenge, Nonce, Statement, StatementDomain, ENROLL_DOMAIN, MAX_ACTION_LEN,
    MAX_NONCE_LEN, PRESENCE_DOMAIN,
};
pub use store::EnrollmentStore;
pub use verify::{verify_assertion, Assertion, Verified};
