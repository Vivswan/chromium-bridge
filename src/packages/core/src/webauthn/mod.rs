//! WebAuthn user presence: the host is the relying party, the extension is the client, and every
//! capability-granting act needs a signature only a human gesture can produce.
//!
//! ```text
//! host    statement (domain || browser label || action || nonce) -> challenge = sha256(statement)
//! ext     navigator.credentials.get({ challenge })                 <- the human gesture
//! host    verify_assertion against the key recorded at enrollment
//! ```
//!
//! The only RP this host serves is [`RpId::pinned`] (`chrome-extension://<id>`: Chromium rewrites an
//! extension's rp.id claim to its origin). Attestation is never trusted (registration.rs). Enrollments live
//! in the trust record (store.rs); the request/answer exchange is [`crate::presence::request`].

mod authenticator_data;
mod base64url;
mod cli;
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
pub use cli::run_revoke_browser;
pub use credential::{
    CosePublicKey, Credential, CredentialId, CredentialIdError, KeyRefusal, RpId,
};
pub use refusal::{Reason, Refusal, RefusalCode};
pub use registration::{parse_registration, Registered, Registration};
pub use statement::{
    Action, Challenge, Nonce, Origin, PageOp, Statement, StatementDomain, ENROLL_DOMAIN,
    MAX_ACTION_LEN, MAX_NONCE_LEN, MAX_ORIGIN_LEN, PRESENCE_DOMAIN,
};
pub(crate) use store::audit_browsers_revoked;
pub use store::{
    advance_sign_count, counter_advances, record, revoke_browser, BrowserRevoked, CounterError,
    Enrollment, EnrollmentAuthority, RevokeBrowserError,
};
pub use verify::{verify_assertion, Assertion, Verified};
