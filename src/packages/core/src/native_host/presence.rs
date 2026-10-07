//! The host side of the extension's WebAuthn exchange: enrollment and per-act presence for one browser
//! connection. One slot ([`Pending`]) holds what is outstanding, and every request answers in one reply, so the
//! extension's single-flight exchange never waits on a tap.
//!
//! ```text
//! enroll_begin      -> fresh machine: enroll_options (trust on first use)
//!                      enrolled machine: presence_request + enroll_result { presence_required }
//!                      held approval: enroll_options
//! enroll_finish     -> enroll_result
//! kill_release      -> presence_request (this browser's credentials); on approval presence_result, kill_status_result
//! presence_begin    -> presence_request for a page operation (this browser's credentials); on approval presence_result,
//!                      and the extension runs the op it asked about
//! policy_set        -> presence_request the same way; on approval presence_result, policy_set_result, policy_current;
//!                      a keyless host or an invalid request is refused before any request exists
//! policy_rollback   -> policy_rollback_result free when the target only tightens; otherwise as policy_set
//! client_pair       -> presence_request the same way; on approval presence_result, client_pair_result
//! presence_assert   -> presence_result, then the pending act
//! presence_confirm  -> presence_result (the window's answer; only where the request admits no credential)
//! browser_revoke    -> browser_revoke_result: this browser's enrollments forgotten (no proof: it removes capability)
//! ```
//!
//! A grant's statement names the change it approves (`set policy: cdpMode=on,confirmGraceMs=30000`), bounded by
//! [`MAX_ACTION_LEN`]; a change summary past the bound is refused before any request exists, since a tap must
//! be shown what it approves in full. The pending act holds the write prepared before the request opened (the
//! exact document bytes, the key, the store observation), bound to the tap by the single-use nonce: the
//! extension cannot swap the values between the request and its answer, and a store that moves meanwhile (a
//! restriction landing while the tap is awaited) refuses the write as a conflict, as it does on the CLI.

use std::time::{Duration, Instant};

use crate::allowlist::{self, Anchor, ClientName, PairClientError};
use crate::audit::{self, AuditKind, AuditRecord, Surface};
use crate::ipc::BrowserLabel;
use crate::policy::{
    self, Grant, HistoryEntryRef, PolicyOverlay, PolicyValues, PolicyWriteError, PreparedGrant,
    RollbackPlan, StoreObservation,
};
use crate::presence::request::PresenceRequest;
use crate::presence::{PresenceAttestation, PresenceError, PresencePath};
use crate::protocol::control::{
    EnrollOutcome, HostReply, KillStatus, PresenceOutcome, RevokeOutcome, WebAuthnControl,
    WriteLane, WriteVerdict,
};
use crate::trust::TrustState;
use crate::webauthn::{
    self, parse_registration, Action, Assertion, CredentialId, Enrollment, EnrollmentAuthority,
    Nonce, Origin, PageOp, Reason, RefusalCode, Registration, RpId, Statement, StatementDomain,
    MAX_ACTION_LEN,
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
    /// Presence was attested for enrolling another credential; the next `enroll_begin` consumes it. Any
    /// other WebAuthn request supersedes it (a refused `browser_revoke` excepted: it changed nothing),
    /// [`APPROVAL_TTL`] bounds it, and an emptied store voids it (first use governs again), so an approval
    /// never outlives the ceremony it was given for.
    EnrollmentApproved {
        auth: PresenceAttestation,
        since: Instant,
    },
}

/// How long an enrollment approval waits for the page's next `enroll_begin`. The page asks the moment the
/// tap's verdict lands; a minute covers a slow worker wake, not an idle connection holding a user gesture.
const APPROVAL_TTL: Duration = Duration::from_secs(60);

/// What runs once presence is attested.
#[derive(Debug)]
enum PendingAct {
    KillRelease,
    /// A machine with enrollments asked to enroll another credential.
    EnrollBegin,
    /// The extension asked about a page operation on a page; the attestation is its answer, and the
    /// extension runs the op. The origin is kept for the trail: the statement that bound it is consumed by
    /// the answer.
    PageOp {
        op: PageOp,
        origin: Origin,
    },
    /// A signed policy write, prepared before its request opened, and which frame answers. Boxed: the prepared
    /// write carries the document bytes and the key, far larger than the other acts.
    PolicyGrant {
        prepared: Box<PreparedGrant>,
        lane: GrantLane,
    },
    /// A trusted-client pairing.
    ClientPair {
        name: ClientName,
        anchor: Anchor,
    },
}

/// Which request opened a signed write, so its verdict answers on that request's result frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrantLane {
    Set,
    Rollback { revision: u64 },
}

impl GrantLane {
    fn result(self) -> WriteLane {
        match self {
            GrantLane::Set => WriteLane::PolicySet,
            GrantLane::Rollback { .. } => WriteLane::PolicyRollback,
        }
    }

    /// What the tap approves, in the words the prompt shows.
    fn action_text(self, grant: &Grant) -> String {
        match self {
            GrantLane::Set => format!("set policy: {}", grant.summary()),
            GrantLane::Rollback { revision } => {
                format!(
                    "roll policy back to revision {revision}: {}",
                    grant.summary()
                )
            }
        }
    }
}

/// The one refusal for a statement past [`MAX_ACTION_LEN`], the bound a presence prompt can show; `what` names
/// the lane's summary. The fields' own grammars reject NUL, so a statement that fails to parse is over-long.
fn summary_too_long(what: &str) -> String {
    format!("the {what} summary exceeds the {MAX_ACTION_LEN}-byte bound a presence prompt can show")
}

impl PendingAct {
    /// The fields that open this act's audit records: the act, and for a page op the origin it was asked
    /// about. The origin's bound keeps the fixed-length auth path of an `ok` record inside the audit cap; a
    /// refusal's reason is unbounded and comes last, where the cap can shorten only it.
    fn audit_detail(&self) -> String {
        match self {
            PendingAct::KillRelease => "act=kill_release".to_string(),
            PendingAct::EnrollBegin => "act=enroll_begin".to_string(),
            PendingAct::PageOp { op, origin } => {
                format!("act={}; origin={}", op.as_str(), origin.as_str())
            }
            PendingAct::PolicyGrant {
                lane: GrantLane::Set,
                ..
            } => "act=policy_set".to_string(),
            PendingAct::PolicyGrant {
                lane: GrantLane::Rollback { .. },
                ..
            } => "act=policy_rollback".to_string(),
            PendingAct::ClientPair { .. } => "act=client_pair".to_string(),
        }
    }

    /// The act's own refused record beside the presence one, so each lane's trail reads as it does when the
    /// CLI's gate refuses the same act.
    fn audit_refusal(&self, e: &PresenceError) {
        match self {
            PendingAct::KillRelease => crate::kill::audit_refused_release(Surface::Extension, e),
            PendingAct::EnrollBegin | PendingAct::PageOp { .. } => {}
            PendingAct::PolicyGrant { prepared, .. } => {
                prepared.audit_refused(&format!("presence: {e}"));
            }
            PendingAct::ClientPair { name, .. } => {
                allowlist::audit_pair_refused(name, Surface::Extension, e);
            }
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
    /// an assertion from an enrolled authenticator first, after which the same request is made again.
    pub(super) fn enroll_begin(&mut self) -> Vec<HostReply> {
        let approval = match self.pending.take() {
            Some(Pending::EnrollmentApproved { auth, since })
                if since.elapsed() <= APPROVAL_TTL =>
            {
                Some(auth)
            }
            Some(
                Pending::EnrollmentApproved { .. }
                | Pending::Enrollment { .. }
                | Pending::Presence { .. },
            )
            | None => None,
        };
        let enrolled = match enrollments() {
            Ok(enrolled) => enrolled,
            Err(e) => return vec![enroll_refused(RefusalCode::StoreError.detailed(e))],
        };
        if enrolled.is_empty() {
            return self.start_enrollment(&enrolled, EnrollmentAuthority::FirstUse);
        }
        if let Some(auth) = approval {
            return self.start_enrollment(&enrolled, EnrollmentAuthority::Approved(auth));
        }
        match PresenceRequest::for_enrollment(&self.label, &enrolled) {
            Ok(request) => {
                let mut replies = self.await_presence(request, PendingAct::EnrollBegin);
                replies.push(enroll_refused(RefusalCode::PresenceRequired));
                replies
            }
            Err(e) => vec![enroll_refused(RefusalCode::Nonce.detailed(e))],
        }
    }

    /// `kill_release`: restoring capability, so presence first. The request names only this browser's
    /// credentials; a browser with none can answer with its software confirmation.
    pub(super) fn kill_release(&mut self) -> Vec<HostReply> {
        self.pending = None;
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
        match PresenceRequest::for_browser(&self.label, Action::release_kill_switch(), &enrolled) {
            Ok(request) => self.await_presence(request, PendingAct::KillRelease),
            Err(e) => refused_early(e),
        }
    }

    /// `presence_begin`: a page operation the policy routes to the authenticator. The extension names the op
    /// and the page's origin; the statement binds both, so the tap approves exactly that act on that page,
    /// and only this browser's credentials may answer (the window where it has none). A refusal here answers
    /// before anything is pending, leaves an outstanding request as it was, and names its reason in the trail.
    pub(super) fn presence_begin(&mut self, action: &str, origin: &str) -> Vec<HostReply> {
        let refused = |reason: Reason| {
            audit::record(
                AuditRecord::new(AuditKind::PresenceAssert)
                    .surface(Surface::Extension)
                    .outcome("refused")
                    .detail(&format!("act=presence_begin; {reason}")),
            );
            vec![presence_refused(reason)]
        };
        let Some(op) = PageOp::parse(action) else {
            return refused(RefusalCode::InvalidAction.into());
        };
        let Some(origin) = Origin::parse(origin) else {
            return refused(RefusalCode::InvalidOrigin.into());
        };
        let enrolled = match enrollments() {
            Ok(enrolled) => enrolled,
            Err(e) => return refused(RefusalCode::StoreError.detailed(e)),
        };
        match PresenceRequest::for_browser(&self.label, Action::page_op(op, &origin), &enrolled) {
            Ok(request) => self.await_presence(request, PendingAct::PageOp { op, origin }),
            Err(e) => refused(RefusalCode::Nonce.detailed(e)),
        }
    }

    /// `policy_set`: the signed grant lane. The request's own validity and the prompt's bound are decided on
    /// the request alone, before the first store read, so a malformed field is refused by its grammar's words
    /// and an oversized change by the bound's whatever the store's state; the plan over the current baseline
    /// comes after, and an unreadable store refuses with the CLI's words and nothing pending.
    pub(super) fn policy_set(&mut self, overlay: PolicyOverlay) -> Vec<HostReply> {
        self.pending = None;
        let lane = GrantLane::Set;
        // The touched fields' values are the overlay's whatever the baseline, so the summary is known now.
        let preview = Grant {
            values: policy::fold(&PolicyValues::default(), &overlay),
            touched: policy::touched_fields(&overlay),
        };
        let action = match grant_action(lane, &preview) {
            Ok(action) => action,
            Err(error) => return vec![refused_write(lane.result(), error)],
        };
        match policy::plan_grant(&overlay) {
            Ok(grant) => self.begin_grant(grant, lane, action, None),
            Err(error) => vec![refused_write(lane.result(), error)],
        }
    }

    /// `policy_rollback`: the plan decides the lane exactly as `policy rollback` does. A no-op answers at once,
    /// a tightening rides the free lane, a relaxation is a grant behind a tap; each holds to the store the plan
    /// was read over and refuses one that moved since as a conflict. `entry` is the row the page listed, so a
    /// revision the ring holds more than once is no obstacle to it.
    pub(super) fn policy_rollback(
        &mut self,
        revision: u64,
        entry: Option<HistoryEntryRef>,
    ) -> Vec<HostReply> {
        self.pending = None;
        let lane = WriteLane::PolicyRollback;
        let inputs = match policy::rollback_inputs(revision, entry) {
            Ok(inputs) => inputs,
            Err(error) => return vec![refused_write(lane, error)],
        };
        match inputs.plan() {
            RollbackPlan::NoChange => match policy::confirm_unmoved(&inputs.over) {
                Ok(()) => vec![WriteVerdict::Applied.into_frame(lane)],
                Err(e) => vec![refused_write(lane, e.to_string())],
            },
            RollbackPlan::Tighten { overlay, .. } => super::restrict_replies(
                policy::restrict_planned(overlay, &inputs.over, Surface::Extension),
                lane,
            ),
            RollbackPlan::Relax(grant) => {
                let lane = GrantLane::Rollback { revision };
                match grant_action(lane, &grant) {
                    Ok(action) => self.begin_grant(grant, lane, action, Some(&inputs.over)),
                    Err(error) => vec![refused_write(lane.result(), error)],
                }
            }
        }
    }

    /// Open the presence request for a grant whose statement already parsed: the write is prepared (the store
    /// observation, then the host key, the up-front keyless refusal), held to the store a rollback's plan was
    /// read over, and the request minted. Refused before any request exists, with the words `policy set` prints.
    fn begin_grant(
        &mut self,
        grant: Grant,
        lane: GrantLane,
        action: Action,
        planned_over: Option<&StoreObservation>,
    ) -> Vec<HostReply> {
        let result = lane.result();
        let prepared = policy::prepare_grant(grant.values, grant.touched, Surface::Extension)
            .and_then(|prepared| match planned_over {
                Some(over) => prepared.planned_over(over),
                None => Ok(prepared),
            });
        let prepared = match prepared {
            Ok(prepared) => Box::new(prepared),
            Err(e) => return vec![refused_write(result, e.to_string())],
        };
        let refused_early = |e: std::io::Error| {
            let e = PresenceError::Store(e);
            prepared.audit_refused(&format!("presence: {e}"));
            vec![refused_write(
                result,
                PolicyWriteError::Refused(e.to_string()).to_string(),
            )]
        };
        let enrolled = match enrollments() {
            Ok(enrolled) => enrolled,
            Err(e) => return refused_early(e),
        };
        match PresenceRequest::for_browser(&self.label, action, &enrolled) {
            Ok(request) => self.await_presence(request, PendingAct::PolicyGrant { prepared, lane }),
            Err(e) => refused_early(e),
        }
    }

    /// `client_pair`: granting harness capability, so presence first. The name and anchor were validated by
    /// their parsers at the frame boundary; a summary past the action bound (a long signer id) is refused here,
    /// before any request exists.
    pub(super) fn client_pair(&mut self, name: ClientName, anchor: Anchor) -> Vec<HostReply> {
        self.pending = None;
        let lane = WriteLane::ClientPair;
        let Some(action) = Action::parse(&format!("pair trusted client '{name}' on {anchor}"))
        else {
            return vec![refused_write(
                lane,
                PairClientError::Invalid(summary_too_long("pairing")).to_string(),
            )];
        };
        let refused_early = |e: std::io::Error| {
            let e = PresenceError::Store(e);
            allowlist::audit_pair_refused(&name, Surface::Extension, &e);
            vec![refused_write(
                lane,
                PairClientError::Presence(e).to_string(),
            )]
        };
        let enrolled = match enrollments() {
            Ok(enrolled) => enrolled,
            Err(e) => return refused_early(e),
        };
        match PresenceRequest::for_browser(&self.label, action, &enrolled) {
            Ok(request) => self.await_presence(request, PendingAct::ClientPair { name, anchor }),
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
            return vec![presence_refused(RefusalCode::NoRequestOutstanding)];
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
            return vec![presence_refused(RefusalCode::NoRequestOutstanding)];
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
                        .detail(&format!("{}; {e}", act.audit_detail())),
                );
                act.audit_refusal(&e);
                return vec![presence_refused(e.code())];
            }
        };
        audit::record(
            AuditRecord::new(AuditKind::PresenceAssert)
                .surface(Surface::Extension)
                .outcome("ok")
                .detail(&format!(
                    "{}; auth={}",
                    act.audit_detail(),
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
            PendingAct::EnrollBegin => {
                self.pending = Some(Pending::EnrollmentApproved {
                    auth,
                    since: Instant::now(),
                });
            }
            // The approval is the whole answer: the extension holds the op and runs it on the verdict.
            PendingAct::PageOp { .. } => {}
            PendingAct::PolicyGrant { prepared, lane } => {
                let result = lane.result();
                match prepared.commit(auth) {
                    Ok(path) => {
                        log_info!(
                            "native-host",
                            "extension signed a policy baseline (authorized by {})",
                            path.wire_name()
                        );
                        replies.push(WriteVerdict::Applied.into_frame(result));
                        replies.push(super::policy_current_reply().into());
                    }
                    Err(e) => {
                        log_warn!(
                            "native-host",
                            "extension-requested policy grant failed: {e}"
                        );
                        replies.push(refused_write(result, e.to_string()));
                    }
                }
            }
            PendingAct::ClientPair { name, anchor } => {
                match allowlist::pair_client_with_presence(
                    &name,
                    anchor,
                    Surface::Extension,
                    |_reason| Ok(auth),
                ) {
                    Ok(path) => {
                        log_info!(
                            "native-host",
                            "extension paired trusted client '{name}' (authorized by {})",
                            path.wire_name()
                        );
                        replies.push(WriteVerdict::Applied.into_frame(WriteLane::ClientPair));
                    }
                    Err(e) => {
                        log_warn!("native-host", "extension-requested pairing failed: {e}");
                        replies.push(refused_write(WriteLane::ClientPair, e.to_string()));
                    }
                }
            }
        }
        replies
    }

    /// `browser_revoke`: forget every authenticator enrolled under this host's label. The frame names no label,
    /// so the reach is exactly this host's: one browser, or every browser sharing an unlabelled manifest
    /// (`default`). Whatever was outstanding is void once the store forgot this browser; a refusal changed
    /// nothing, so the request stays for the worker's answer (a browser with no credential still answers
    /// its own request through the window).
    pub(super) fn browser_revoke(&mut self) -> Vec<HostReply> {
        let outcome = match webauthn::revoke_browser(&self.label, Surface::Extension) {
            Ok(revoked) => {
                log_info!(
                    "native-host",
                    "browser '{}' forgot its {} enrolled credential(s)",
                    self.label,
                    revoked.forgotten.len()
                );
                self.pending = None;
                RevokeOutcome::Forgotten
            }
            Err(webauthn::RevokeBrowserError::NotEnrolled { .. }) => {
                revoke_refused(RefusalCode::NotEnrolled)
            }
            Err(webauthn::RevokeBrowserError::Io(e)) => {
                revoke_refused(RefusalCode::StoreError.detailed(e))
            }
        };
        vec![outcome.into_frame().into()]
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
            return vec![enroll_refused(RefusalCode::NoEnrollmentOutstanding)];
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
                return vec![enroll_refused(refusal.code())];
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
                enroll_audit("refused", RefusalCode::MachineAlreadyEnrolled.to_string());
                vec![enroll_refused(RefusalCode::MachineAlreadyEnrolled)]
            }
            Err(e) => {
                let reason = RefusalCode::StoreError.detailed(e);
                enroll_audit("refused", reason.to_string());
                vec![enroll_refused(reason)]
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
            Err(e) => return vec![enroll_refused(RefusalCode::Nonce.detailed(e))],
        };
        let statement = Statement {
            domain: StatementDomain::Enrollment,
            browser_label: self.label.clone(),
            action: Action::enroll(),
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

impl Exchange {
    /// Tests only: age the held approval past its lifetime.
    #[cfg(test)]
    pub(super) fn expire_approval_for_tests(&mut self) {
        if let Some(Pending::EnrollmentApproved { since, .. }) = &mut self.pending {
            *since = Instant::now()
                .checked_sub(APPROVAL_TTL.saturating_add(Duration::from_secs(1)))
                .unwrap_or_else(Instant::now);
        }
    }
}

/// The enrollments as of now: re-read per step, so a credential revoked between the request and its answer
/// is refused.
fn enrollments() -> std::io::Result<Vec<Enrollment>> {
    TrustState::current().map(|trust| trust.enrollments().to_vec())
}

fn enroll_refused(reason: impl Into<Reason>) -> HostReply {
    EnrollOutcome::Refused {
        reason: reason.into().to_string(),
    }
    .into_frame()
    .into()
}

fn presence_refused(reason: impl Into<Reason>) -> HostReply {
    PresenceOutcome::Refused {
        reason: reason.into().to_string(),
    }
    .into_frame()
    .into()
}

fn revoke_refused(reason: impl Into<Reason>) -> RevokeOutcome {
    RevokeOutcome::Refused {
        reason: reason.into().to_string(),
    }
}

fn kill_unreadable(error: String) -> HostReply {
    KillStatus::Unreadable { error }.into_frame().into()
}

/// The statement a grant's tap approves, or the refusal in the lane's own words: the tool list is the
/// summary's only free-form text, so its grammar decides first, then the bound a presence prompt can show.
fn grant_action(lane: GrantLane, grant: &Grant) -> Result<Action, String> {
    policy::validate_disabled_tools(&grant.values.disabled_tools)
        .map_err(|m| PolicyWriteError::Invalid(m.into()).to_string())?;
    Action::parse(&lane.action_text(grant))
        .ok_or_else(|| PolicyWriteError::Invalid(summary_too_long("change")).to_string())
}

fn refused_write(lane: WriteLane, error: String) -> HostReply {
    WriteVerdict::Refused { error }.into_frame(lane)
}

#[cfg(test)]
mod tests;
