//! The host side of the extension's WebAuthn exchange: enrollment and per-act presence for one browser
//! connection. One request is outstanding at a time; a new one supersedes it, so an abandoned ceremony never
//! wedges the host, and the superseded nonce can no longer verify anything.
//!
//! ```text
//! enroll_begin      -> no enrollment on the machine: trust on first use, enroll_options at once
//!                      otherwise: presence_request any enrolled credential may answer, then enroll_options
//! enroll_finish     -> registration verified against the outstanding enrollment statement, stored, enroll_result
//! kill_release      -> presence_request only credentials enrolled under THIS browser may answer; on an accepted
//!                      assertion the switch is released and kill_status_result follows presence_result
//! presence_assert   -> verified against the outstanding request, the sign counter persisted, then the pending
//!                      act runs; every refusal is one presence_result code
//! presence_confirm  -> the window's answer to the outstanding request, named by its nonce; accepted only when the
//!                      request admits no enrolled credential, so an enrolled browser is never demoted to a click
//! ```

use crate::audit::{self, AuditKind, AuditRecord, Surface};
use crate::ipc::BrowserLabel;
use crate::presence::request::PresenceRequest;
use crate::presence::{PresenceAttestation, PresenceError, PresencePath};
use crate::protocol::control::{
    EnrollOutcome, HostReply, KillStatus, PresenceOutcome, WebAuthnControl,
};
use crate::trust::TrustState;
use crate::webauthn::{
    self, parse_registration, Action, Assertion, CredentialId, Enrollment, EnrollmentAuthority,
    Nonce, Registration, RpId, Statement, StatementDomain,
};

/// The per-connection exchange state. The label is the browser this host fronts; every statement binds it.
pub(super) struct Exchange {
    label: BrowserLabel,
    pending: Option<Pending>,
}

enum Pending {
    /// `enroll_begin` answered; `enroll_finish` must echo this statement's challenge, and the write runs
    /// under the authority that opened it.
    Enrollment {
        statement: Statement,
        authority: EnrollmentAuthority,
    },
    /// A capability-granting act awaits the user's answer.
    Presence {
        request: PresenceRequest,
        act: PendingAct,
    },
}

/// What runs once presence is attested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingAct {
    KillRelease,
    /// A machine with enrollments asked to enroll another credential.
    EnrollBegin,
}

impl PendingAct {
    fn audit_name(self) -> &'static str {
        match self {
            PendingAct::KillRelease => "kill_release",
            PendingAct::EnrollBegin => "enroll_begin",
        }
    }
}

impl Exchange {
    pub(super) fn new(label: BrowserLabel) -> Self {
        Exchange {
            label,
            pending: None,
        }
    }

    /// `enroll_begin`: the first credential on a fresh machine is trust on first use; every later one needs
    /// an assertion from an enrolled authenticator first.
    pub(super) fn enroll_begin(&mut self) -> Vec<HostReply> {
        let enrolled = match enrollments() {
            Ok(enrolled) => enrolled,
            Err(e) => return vec![enroll_refused(format!("store_error: {e}"))],
        };
        if enrolled.is_empty() {
            return self.start_enrollment(&enrolled, EnrollmentAuthority::FirstUse);
        }
        match PresenceRequest::for_enrollment(&self.label, &enrolled) {
            Ok(request) => self.await_presence(request, PendingAct::EnrollBegin),
            Err(e) => vec![enroll_refused(format!("nonce: {e}"))],
        }
    }

    /// `kill_release`: restoring capability, so presence first. The request names only this browser's
    /// credentials; a browser with none can answer with its software confirmation.
    pub(super) fn kill_release(&mut self) -> Vec<HostReply> {
        // A refusal before the request exists is audited like one at the gate, so every release attempt
        // leaves a trail entry.
        let refused_early = |e: std::io::Error| {
            let detail = e.to_string();
            crate::kill::audit_refused_release(Surface::Extension, &PresenceError::Store(e));
            vec![kill_unreadable(detail)]
        };
        let enrolled = match enrollments() {
            Ok(enrolled) => enrolled,
            Err(e) => return refused_early(e),
        };
        let Some(action) = Action::parse("release the kill switch") else {
            return refused_early(std::io::Error::other("action text invalid"));
        };
        match PresenceRequest::for_browser(&self.label, action, &enrolled) {
            Ok(request) => self.await_presence(request, PendingAct::KillRelease),
            Err(e) => refused_early(e),
        }
    }

    /// `presence_assert`: close the outstanding request with an assertion, then run its act.
    pub(super) fn presence_assert(
        &mut self,
        credential_id: &str,
        assertion: Result<Assertion, webauthn::Refusal>,
    ) -> Vec<HostReply> {
        let Some(Pending::Presence { request, act }) = self.pending.take() else {
            return vec![presence_refused("no_request_outstanding".into())];
        };
        let outcome = CredentialId::from_base64url(credential_id)
            .map_err(|_| {
                PresenceError::Refused(webauthn::Refusal::Encoding {
                    field: "credential_id",
                })
            })
            .and_then(|id| {
                let assertion = assertion.map_err(PresenceError::Refused)?;
                let enrolled = enrollments().map_err(PresenceError::Store)?;
                request.assert(&enrolled, &id, &assertion)
            });
        self.settle(act, outcome)
    }

    /// `presence_confirm`: the window answered the outstanding request. The nonce names the request so a
    /// confirmation for a superseded one cannot ride a newer request (`request_mismatch`); the window rule
    /// itself is the request's.
    pub(super) fn presence_confirm(&mut self, nonce: &str) -> Vec<HostReply> {
        let Some(Pending::Presence { request, act }) = self.pending.take() else {
            return vec![presence_refused("no_request_outstanding".into())];
        };
        let outcome = if request.nonce().as_str() == nonce {
            enrollments()
                .map_err(PresenceError::Store)
                .and_then(|enrolled| request.confirm_window(&enrolled))
        } else {
            Err(PresenceError::RequestMismatch)
        };
        self.settle(act, outcome)
    }

    /// Close the request with its verdict: audit it, and on an attestation run the act it was minted for.
    fn settle(
        &mut self,
        act: PendingAct,
        outcome: Result<PresenceAttestation, PresenceError>,
    ) -> Vec<HostReply> {
        let auth = match outcome {
            Ok(auth) => auth,
            Err(e) => {
                audit::record(
                    AuditRecord::new(AuditKind::PresenceAssert)
                        .surface(Surface::Extension)
                        .outcome("refused")
                        .detail(&format!("act={}; {e}", act.audit_name())),
                );
                if act == PendingAct::KillRelease {
                    crate::kill::audit_refused_release(Surface::Extension, &e);
                }
                return vec![presence_refused(e.code().into())];
            }
        };
        audit::record(
            AuditRecord::new(AuditKind::PresenceAssert)
                .surface(Surface::Extension)
                .outcome("ok")
                .detail(&format!(
                    "act={}; auth={}",
                    act.audit_name(),
                    auth.path().audit_label()
                )),
        );
        let mut replies = vec![PresenceOutcome::Approved.into_frame().into()];
        match act {
            PendingAct::KillRelease => {
                let status = match crate::kill::release(Surface::Extension, auth) {
                    Ok(epoch) => {
                        log_info!(
                            "native-host",
                            "extension released the kill switch (epoch {epoch})"
                        );
                        KillStatus::Read { killed: false }
                    }
                    Err(e) => KillStatus::Unreadable {
                        error: e.to_string(),
                    },
                };
                replies.push(status.into_frame().into());
            }
            PendingAct::EnrollBegin => match enrollments() {
                Ok(enrolled) => replies
                    .extend(self.start_enrollment(&enrolled, EnrollmentAuthority::Approved(auth))),
                Err(e) => replies.push(enroll_refused(format!("store_error: {e}"))),
            },
        }
        replies
    }

    /// `enroll_finish`: verify the registration against the outstanding enrollment statement and store it.
    pub(super) fn enroll_finish(
        &mut self,
        registration: Result<Registration, webauthn::Refusal>,
    ) -> Vec<HostReply> {
        let Some(Pending::Enrollment {
            statement,
            authority,
        }) = self.pending.take()
        else {
            return vec![enroll_refused("no_enrollment_outstanding".into())];
        };
        let registered = registration.and_then(|registration| {
            parse_registration(&statement, &RpId::pinned(), &registration)
        });
        let registered = match registered {
            Ok(registered) => registered,
            Err(refusal) => {
                log_warn!("native-host", "enrollment refused: {refusal}");
                audit::record(
                    AuditRecord::new(AuditKind::Enroll)
                        .surface(Surface::Extension)
                        .outcome("refused")
                        .detail(&format!("browser={}; {refusal}", self.label)),
                );
                return vec![enroll_refused(refusal.code().into())];
            }
        };
        let credential_id = registered.credential.id.to_base64url();
        let fingerprint = PresencePath::WebAuthn(registered.credential.id.clone()).audit_label();
        let authorized_by = match &authority {
            EnrollmentAuthority::FirstUse => "first_use".to_string(),
            EnrollmentAuthority::Approved(auth) => auth.path().audit_label(),
        };
        let enroll_audit = |outcome: &str, detail: String| {
            audit::record(
                AuditRecord::new(AuditKind::Enroll)
                    .surface(Surface::Extension)
                    .outcome(outcome)
                    .detail(&format!("browser={}; {detail}", self.label)),
            );
        };
        match webauthn::record(&self.label, registered.credential, authority) {
            Ok(_) => {
                log_info!(
                    "native-host",
                    "enrolled credential {credential_id} for browser '{}' (user verified: {})",
                    self.label,
                    registered.user_verified
                );
                enroll_audit(
                    "ok",
                    format!("credential={fingerprint}; authorized_by={authorized_by}"),
                );
                vec![EnrollOutcome::Enrolled { credential_id }
                    .into_frame()
                    .into()]
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                log_warn!("native-host", "first-use enrollment refused: {e}");
                enroll_audit("refused", "machine_already_enrolled".into());
                vec![enroll_refused("machine_already_enrolled".into())]
            }
            Err(e) => {
                enroll_audit("refused", format!("store_error: {e}"));
                vec![enroll_refused(format!("store_error: {e}"))]
            }
        }
    }

    fn await_presence(&mut self, request: PresenceRequest, act: PendingAct) -> Vec<HostReply> {
        let frame = WebAuthnControl::PresenceRequest {
            challenge: request.challenge().to_base64url(),
            nonce: request.nonce().as_str().to_string(),
            action: request.action().as_str().to_string(),
            allowed_credential_ids: request
                .allowed_credential_ids()
                .iter()
                .map(CredentialId::to_base64url)
                .collect(),
        };
        self.pending = Some(Pending::Presence { request, act });
        vec![frame.into()]
    }

    fn start_enrollment(
        &mut self,
        enrolled: &[Enrollment],
        authority: EnrollmentAuthority,
    ) -> Vec<HostReply> {
        let nonce = match Nonce::fresh() {
            Ok(nonce) => nonce,
            Err(e) => return vec![enroll_refused(format!("nonce: {e}"))],
        };
        let Some(action) = Action::parse("enroll") else {
            return vec![enroll_refused("action text invalid".into())];
        };
        let statement = Statement {
            domain: StatementDomain::Enrollment,
            browser_label: self.label.clone(),
            action,
            nonce,
        };
        let frame = WebAuthnControl::EnrollOptions {
            challenge: statement.challenge().to_base64url(),
            nonce: statement.nonce.as_str().to_string(),
            user_id: webauthn::base64url_encode(self.label.as_str().as_bytes()),
            user_name: self.label.as_str().to_string(),
            exclude_credential_ids: enrolled
                .iter()
                .filter(|e| e.label == self.label)
                .map(|e| e.credential.id.to_base64url())
                .collect(),
        };
        self.pending = Some(Pending::Enrollment {
            statement,
            authority,
        });
        vec![frame.into()]
    }
}

/// The enrollments as of now: re-read per step, so a credential revoked between the request and its answer
/// is refused.
fn enrollments() -> std::io::Result<Vec<Enrollment>> {
    TrustState::current().map(|trust| trust.enrollments().to_vec())
}

fn enroll_refused(reason: String) -> HostReply {
    EnrollOutcome::Refused { reason }.into_frame().into()
}

fn presence_refused(reason: String) -> HostReply {
    PresenceOutcome::Refused { reason }.into_frame().into()
}

fn kill_unreadable(error: String) -> HostReply {
    KillStatus::Unreadable { error }.into_frame().into()
}

#[cfg(test)]
mod tests;
