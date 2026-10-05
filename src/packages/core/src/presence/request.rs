//! One capability-granting act awaiting the extension's answer: the statement the host minted, the rule for
//! who may answer, and the two answers that can close it. Both minters live here, so the no-downgrade rule
//! is one place: an assertion must come from a credential the rule admits as enrolled NOW, and the window may
//! vouch only when the rule admits none.

use std::io;

use crate::ipc::BrowserLabel;
use crate::webauthn::{
    advance_sign_count, verify_assertion, Action, Assertion, Challenge, CounterError, CredentialId,
    Enrollment, Nonce, Refusal, RpId, Statement, StatementDomain, Verified,
};

use super::{PresenceAttestation, PresenceError, PresencePath};

/// Who may answer, judged against the enrollments as they stand when the answer arrives, not against a list
/// taken when the request was minted: a credential re-enrolled under another browser in between must not
/// answer the first browser's request.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Answerers {
    /// Credentials enrolled under this browser's label.
    Browser(BrowserLabel),
    /// Any credential enrolled on the machine.
    AnyEnrolled,
}

impl Answerers {
    fn admits(&self, enrollment: &Enrollment) -> bool {
        match self {
            Answerers::Browser(label) => &enrollment.label == label,
            Answerers::AnyEnrolled => true,
        }
    }
}

/// The outstanding request. Holding it is the host's business (one at a time per browser connection);
/// answering it consumes it, so a request can never vouch twice.
#[derive(Debug)]
pub struct PresenceRequest {
    statement: Statement,
    answerers: Answerers,
    /// The credential ids the rule admitted when the request was minted: the `allowCredentials` hint the
    /// authenticator gets, never the check itself.
    hint: Vec<CredentialId>,
}

impl PresenceRequest {
    /// A request for `label`'s own act: only credentials enrolled under that label may answer. An empty hint
    /// is a browser with no enrolled credential, whose only answer is the window.
    pub fn for_browser(
        label: &BrowserLabel,
        action: Action,
        enrolled: &[Enrollment],
    ) -> io::Result<Self> {
        Self::new(label, action, Answerers::Browser(label.clone()), enrolled)
    }

    /// A request to enroll a credential for `label` on a machine that already has enrollments: any enrolled
    /// credential may approve, which is what lets a second browser be enrolled at all.
    pub fn for_enrollment(label: &BrowserLabel, enrolled: &[Enrollment]) -> io::Result<Self> {
        let action = Action::parse(&format!("enroll a credential for browser '{label}'"))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "label too long for an action")
            })?;
        Self::new(label, action, Answerers::AnyEnrolled, enrolled)
    }

    fn new(
        label: &BrowserLabel,
        action: Action,
        answerers: Answerers,
        enrolled: &[Enrollment],
    ) -> io::Result<Self> {
        let hint = enrolled
            .iter()
            .filter(|e| answerers.admits(e))
            .map(|e| e.credential.id.clone())
            .collect();
        Ok(PresenceRequest {
            statement: Statement {
                domain: StatementDomain::Presence,
                browser_label: label.clone(),
                action,
                nonce: Nonce::fresh()?,
            },
            answerers,
            hint,
        })
    }

    pub fn nonce(&self) -> &Nonce {
        &self.statement.nonce
    }

    pub fn action(&self) -> &Action {
        &self.statement.action
    }

    pub fn challenge(&self) -> Challenge {
        self.statement.challenge()
    }

    pub fn allowed_credential_ids(&self) -> &[CredentialId] {
        &self.hint
    }

    /// Answer with an assertion, judged against `enrolled` as it stands now. The advanced sign counter is
    /// persisted to the trust record before the attestation is minted, and that write re-checks the counter
    /// against the stored one under the lock, so neither a stale snapshot nor a counter that failed to land
    /// leaves a proof behind.
    ///
    /// ```text
    /// id matches no enrollment            -> credential_not_enrolled
    /// id enrolled, the rule refuses it    -> wrong_browser_label
    /// verify_assertion refuses            -> its code (a replay stalls the counter; a stale nonce mismatches the challenge)
    /// ```
    pub fn assert(
        self,
        enrolled: &[Enrollment],
        id: &CredentialId,
        assertion: &Assertion,
    ) -> Result<PresenceAttestation, PresenceError> {
        let enrollment = enrolled
            .iter()
            .find(|e| &e.credential.id == id)
            .ok_or(PresenceError::CredentialNotEnrolled)?;
        if !self.answerers.admits(enrollment) {
            return Err(PresenceError::WrongBrowser {
                enrolled_under: enrollment.label.clone(),
            });
        }
        let Verified { sign_count, .. } = verify_assertion(
            &enrollment.credential,
            &self.statement,
            &RpId::pinned(),
            assertion,
        )
        .map_err(PresenceError::Refused)?;
        advance_sign_count(id, sign_count).map_err(|e| match e {
            CounterError::NotEnrolled => PresenceError::CredentialNotEnrolled,
            CounterError::Stale { stored } => {
                PresenceError::Refused(Refusal::SignCountNotIncreased {
                    stored,
                    received: sign_count,
                })
            }
            CounterError::Io(e) => PresenceError::Store(e),
        })?;
        Ok(PresenceAttestation {
            path: PresencePath::WebAuthn(id.clone()),
        })
    }

    /// Answer with the window: the software confirmation, allowed only when the rule admits no credential as
    /// `enrolled` stands now.
    pub fn confirm_window(
        self,
        enrolled: &[Enrollment],
    ) -> Result<PresenceAttestation, PresenceError> {
        if enrolled.iter().any(|e| self.answerers.admits(e)) {
            return Err(PresenceError::SoftwareConfirmationNotAllowed);
        }
        Ok(PresenceAttestation {
            path: PresencePath::ConfirmWindow,
        })
    }
}
