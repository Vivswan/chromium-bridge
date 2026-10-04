//! The store contract the verifier's callers need: which credentials a browser enrolled, and the two writes
//! a ceremony makes. The trust-state record owns the implementation.

use crate::ipc::BrowserLabel;

use super::credential::{Credential, CredentialId};

pub trait EnrollmentStore {
    type Error: std::error::Error;

    /// Every credential enrolled from the browser wearing `label`; an assertion from any other credential
    /// is refused before verification.
    fn credentials(&self, label: &BrowserLabel) -> Result<Vec<Credential>, Self::Error>;

    /// Record a credential an accepted registration produced.
    fn record(&mut self, label: &BrowserLabel, credential: Credential) -> Result<(), Self::Error>;

    /// Record the `sign_count` an accepted assertion carried, so the next one must exceed it.
    fn advance_sign_count(
        &mut self,
        label: &BrowserLabel,
        id: &CredentialId,
        sign_count: u32,
    ) -> Result<(), Self::Error>;
}
