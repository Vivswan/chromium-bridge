//! Native-host mode: the `--native-host` subprocess Chrome spawns. It is intentionally dumb, so all real tool
//! logic stays in the MCP server on the other side of the socket; EOF on stdin (Chrome disconnected) is the
//! shutdown signal.
//!
//! ```text
//! stdin  -> socket   native-messaging frames forwarded as NDJSON lines, except the host-handled control frames
//!                    (host-key ceremony, revocation and client admin, kill switch, WebAuthn enrollment and
//!                    presence, policy grants and restrictions, language), which are answered HERE and never
//!                    reach the server
//! socket -> stdout   NDJSON lines framed for Chrome, except a control frame from the server, which is an
//!                    injection and is dropped
//! ```
//!
//! The `enclave_revoked` push is host-originated on purpose: the socket->stdout pump drops any server-injected
//! control frame, so only this process can put that frame in front of the extension. It fires at startup when
//! the key is already gone and live when the host-key epoch moves. The WebAuthn exchange (`presence.rs`) is the
//! same way: only this process can push a `presence_request`.

use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::cli::FixTargets;
use crate::enclave::EnrollmentKey;
use crate::ipc::{self, BrowserLabel};
use crate::protocol::control::{
    classify_nm_frame, host_control_type, AdminControl, AuditReadLimit, AuditReport, DoctorOutcome,
    EnclaveControl, FrameDisposition, HistoryReport, HostReply, HostRequest, KillStatus,
    MalformedReply, PolicyControl, PolicyHistoryRow, PolicyStatus, RegistrationReport,
    RegistrationRow, RepairBrowsers, WriteLane, WriteVerdict,
};
use crate::protocol::{bridge_read, bridge_write, nm_read_frame, nm_write_frame};
use crate::runtime_record::RuntimeRecord as _;
use crate::trust::{Clients, TrustState, POLL_INTERVAL};
use crate::webauthn::{Assertion, Registration};
use serde::Serialize;
use serde_json::Value;

/// Serialize a host-handled control frame and write it to Chrome via the shared stdout writer. `nm_write_frame` flushes per frame, so
/// taking the lock per frame keeps replies atomic with respect to the
/// socket->stdout pump.
fn write_control_reply<W: Write, T: Serialize>(out: &Mutex<W>, reply: &T) -> io::Result<()> {
    let value = serde_json::to_value(reply)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("encode reply: {e}")))?;
    let mut out = out
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    nm_write_frame(&mut *out, &value)
}

mod presence;

use presence::Exchange;

// ---- revocation handlers and the host-originated push ------------------------

/// Handle an `enclave_revoke` frame from the extension through the shared disposal seam, so the SAME critical
/// section that deletes the key also clears the signed policy baseline and bumps the host-key epoch; the
/// extension-originated path is the one most likely to leave a baseline signed by a dead key behind, so it
/// must not hand-roll the deletion. Replies `enclave_revoked` when the key is gone (including when none
/// existed), or a typed `enclave_error`.
fn revoke_host_key() -> EnclaveControl {
    match crate::enclave::dispose_enrollment_and_policy_baseline() {
        Ok(revoked) => {
            crate::enclave::audit_host_key_revoke(crate::audit::Surface::Extension, &revoked);
            if revoked.key_in_use_is_gone() {
                log_info!(
                    "native-host",
                    "extension revoked the host key (existed: {})",
                    revoked.existed()
                );
                return EnclaveControl::EnclaveRevoked {};
            }
            // No file key, and the store did not answer: the end state the frame promises is not confirmed.
            let crate::enclave::StoreOutcome::Unanswered(e) = revoked.store else {
                return EnclaveControl::EnclaveRevoked {};
            };
            log_warn!("native-host", "extension-requested revoke unconfirmed: {e}");
            EnclaveControl::EnclaveError {
                reason: crate::enclave::reason_code(&e).to_string(),
            }
        }
        Err(e) => {
            log_warn!("native-host", "extension-requested revoke failed: {e}");
            EnclaveControl::EnclaveError {
                reason: crate::enclave::reason_code(&e).to_string(),
            }
        }
    }
}

/// Handle a `client_list` frame: report the trusted-client allowlist from one read of the trust record. An
/// unreadable record answers `ok: false` with the error and no enrollment claim.
fn admin_client_list() -> AdminControl {
    match TrustState::current() {
        Ok(trust) => match trust.clients() {
            Clients::Paired(clients) => AdminControl::ClientListResult {
                ok: true,
                enrolled: true,
                clients: clients.clone(),
                error: None,
            },
            Clients::NeverPaired => AdminControl::ClientListResult {
                ok: true,
                enrolled: false,
                clients: Vec::new(),
                error: None,
            },
        },
        Err(e) => AdminControl::ClientListResult {
            ok: false,
            enrolled: false,
            clients: Vec::new(),
            error: Some(format!("trust record unreadable: {e}")),
        },
    }
}

/// Handle a `client_revoke` frame: remove one trusted client. The rewrite is one atomic write of the trust
/// record, so a live broker refuses that client's next request.
fn admin_client_revoke(name: &str) -> AdminControl {
    if !ipc::validate_label(name) {
        return AdminControl::ClientRevokeResult {
            ok: false,
            error: Some("invalid client name".into()),
        };
    }
    // The RevokeClient audit record is written inside allowlist::revoke
    // (log-after-decide), so no revoke surface can forget the trail entry.
    match crate::allowlist::revoke(name, crate::audit::Surface::Extension) {
        Ok(true) => {
            log_info!("native-host", "extension revoked trusted client '{name}'");
            AdminControl::ClientRevokeResult {
                ok: true,
                error: None,
            }
        }
        Ok(false) => AdminControl::ClientRevokeResult {
            ok: false,
            error: Some(format!("no trusted client named '{name}'")),
        },
        Err(e) => AdminControl::ClientRevokeResult {
            ok: false,
            error: Some(e.to_string()),
        },
    }
}

/// Handle a `doctor_report` frame: the facts plain `doctor` gathers and the host key's state, through the
/// same gather, so the page reads what the terminal prints.
fn doctor_report_reply() -> AdminControl {
    DoctorOutcome::Report(Box::new(crate::doctor::wire_report())).into_frame()
}

/// Handle an `audit_read` frame: the newest records of the host's trail through the reader behind
/// `chromium-bridge audit`, the CLI's default page size when the frame names none. Read-only; an unreadable
/// trail answers its error and no entries.
fn audit_read_reply(limit: Option<AuditReadLimit>) -> AdminControl {
    let limit = limit.map_or(crate::audit::DEFAULT_AUDIT_LIMIT, AuditReadLimit::get);
    match crate::audit::read(limit) {
        Ok(page) => AuditReport::from(page),
        Err(e) => AuditReport::Unavailable {
            error: e.to_string(),
        },
    }
    .into_frame()
}

/// Handle a `registration_status` frame: the per-browser rows `doctor` diagnoses, from one read of the
/// resolver.
fn registration_status_reply() -> AdminControl {
    registration_report(crate::doctor::gather_manifests()).into_frame()
}

/// The wire report for one manifest gather. Pure, so the row mapping is testable without a HOME.
fn registration_report(
    manifests: Result<Vec<crate::doctor::ManifestStatus>, String>,
) -> RegistrationReport {
    match manifests {
        Ok(rows) => RegistrationReport::Rows(rows.iter().map(RegistrationRow::from).collect()),
        Err(error) => RegistrationReport::Unavailable { error },
    }
}

/// Handle a `registration_repair` frame: `doctor --fix` for the detected browsers, or `--browser` for the
/// named ones, through the same seam, then the fresh rows. The frame never widens the scope (this account's)
/// or the foreign-manifest rule. The lines the CLI prints go to the log instead (stdout is the protocol
/// here), and a repair that failed on any target answers that failure in place of rows, so the extension
/// re-asks for the state it should show.
fn registration_repair_reply(browsers: Option<RepairBrowsers>) -> AdminControl {
    let targets = browsers.map_or(FixTargets::Detected, RepairBrowsers::into_targets);
    let outcomes = match crate::registration::fix(
        &targets,
        crate::browsers::Scope::User,
        crate::registration::ForeignManifest::Refuse,
    ) {
        Ok(outcomes) => outcomes,
        Err(e) => {
            log_warn!(
                "native-host",
                "extension-requested repair could not start: {e}"
            );
            return RegistrationReport::Unavailable {
                error: e.to_string(),
            }
            .into_frame();
        }
    };
    let mut failures = Vec::new();
    for outcome in &outcomes {
        match &outcome.result {
            Ok(lines) => {
                for line in lines {
                    log_info!("native-host", "repair {}: {line}", outcome.target);
                }
            }
            Err(e) => failures.push(format!("{}: {e}", outcome.target)),
        }
    }
    if failures.is_empty() {
        registration_status_reply()
    } else {
        let error = failures.join("; ");
        log_warn!("native-host", "extension-requested repair failed: {error}");
        RegistrationReport::Unavailable { error }.into_frame()
    }
}

/// Run the free restriction lane for `overlay` and answer on `lane`: the verdict, then the freshly loaded
/// `policy_current` when the restriction applied. The seam's epoch bump is best-effort after the store write and
/// `confirmPageEval` is enforced in the extension's mirror alone, so the written state is pushed here; the watch's
/// push on a successful bump duplicates it. `policy_restrict` answers on its own lane, a tightening rollback on
/// the rollback lane.
fn restrict_replies(overlay: crate::policy::PolicyOverlay, lane: WriteLane) -> Vec<HostReply> {
    match crate::policy::restrict(overlay, crate::audit::Surface::Extension) {
        Ok(()) => {
            log_info!("native-host", "extension applied a policy restriction");
            vec![
                WriteVerdict::Applied.into_frame(lane),
                policy_current_reply().into(),
            ]
        }
        Err(e) => {
            log_warn!(
                "native-host",
                "extension-requested policy restriction refused: {e}"
            );
            vec![WriteVerdict::Refused {
                error: e.to_string(),
            }
            .into_frame(lane)]
        }
    }
}

/// Answer a `policy_history` frame: the superseded-revision ring as the CLI's report reads it, projected row by
/// row; an unreadable ring is the error alone.
fn policy_history_reply() -> PolicyControl {
    match crate::policy::gather_history_report() {
        Ok(report) => {
            HistoryReport::Entries(report.entries.iter().map(PolicyHistoryRow::from).collect())
        }
        Err(error) => HistoryReport::Unavailable { error },
    }
    .into_frame()
}

// ---- kill-switch control frames and the audit-event sink ----------------------

/// The current kill state as a `kill_status_result` frame, via the typed
/// [`KillStatus`]: unreadable state carries no `killed` claim at all - the
/// extension must treat it as unknown and fail closed, and handing it a
/// boolean would invite trusting it. The typed state makes the mixed shapes
/// unconstructible; `into_frame` owns the wire flattening.
fn kill_status_reply() -> AdminControl {
    let status = match crate::kill::is_killed() {
        Ok(killed) => KillStatus::Read { killed },
        Err(e) => KillStatus::Unreadable {
            error: format!("kill state unreadable: {e}"),
        },
    };
    status.into_frame()
}

/// Handle `kill_engage` from the extension. The core API performs the latch flip + epoch bump in one critical
/// section and audits it with `surface: extension`. The reply reports the resulting state, which the
/// extension's SW-only mirror adopts. Engage only reduces capability (the brake stays one action away on every
/// surface), so it needs no presence gate.
fn handle_kill_engage() -> AdminControl {
    let status = match crate::kill::engage(crate::audit::Surface::Extension) {
        Ok(epoch) => {
            log_info!(
                "native-host",
                "extension ENGAGED the kill switch (epoch {epoch})"
            );
            KillStatus::Read { killed: true }
        }
        Err(e) => {
            log_warn!("native-host", "extension-requested kill engage failed: {e}");
            KillStatus::Unreadable {
                error: e.to_string(),
            }
        }
    };
    status.into_frame()
}

// ---- host-owned policy and shared-language control frames ---------------------

/// The current policy state as a `policy_current` frame. The baseline travels as the stored bytes, never
/// re-serialized or canonicalized: the extension verifies the exact bytes against its own pin.
///
/// ```text
/// store content damaged (effective() fails) -> ok: false, the same deny-all reading the dispatch gate takes of that state
/// store absent or unreadable                -> ok: false, so the extension keeps its deny baseline
/// ```
fn policy_current_reply() -> PolicyControl {
    let status = match crate::policy::PolicyStore::load() {
        Ok(Some(store)) => match store.effective() {
            Ok(_) => PolicyStatus::Present {
                baseline_b64: store.baseline_b64,
                sig_b64: store.sig_b64,
                overlay: store.overlay,
            },
            Err(e) => PolicyStatus::Unavailable {
                error: format!("policy store damaged: {e}"),
            },
        },
        Ok(None) => PolicyStatus::Unavailable {
            error: "no policy baseline on this host".into(),
        },
        Err(e) => PolicyStatus::Unavailable {
            error: format!("policy store unreadable: {e}"),
        },
    };
    status.into_frame()
}

/// The current shared language as a `lang_current` frame, or `None` when the store is unreadable (fail closed:
/// skip the reply / push and log, rather than answer with a guessed value that could reset a receiver's
/// sequence). An absent store reads as the default, which is a normal answer, not an error.
fn lang_current_frame() -> Option<PolicyControl> {
    match crate::lang::load_current() {
        Ok((value, seq)) => Some(PolicyControl::LangCurrent { value, seq }),
        Err(e) => {
            log_warn!(
                "native-host",
                "language store unreadable ({e}); not answering lang_current"
            );
            None
        }
    }
}

/// Handle a `lang_set`: an out-of-enum value is refused and the previous value stands (reply the UNCHANGED
/// `lang_current`); a valid value is applied, bumping the sequence only if it changed, and the resulting
/// `lang_current` is the reply. `None` only when the store is unreadable (see [`lang_current_frame`]).
fn handle_lang_set(value: String) -> Option<PolicyControl> {
    let Some(value) = crate::lang::UiLang::parse(&value) else {
        log_warn!(
            "native-host",
            "refusing out-of-enum lang_set {value:?}; the previous language stands"
        );
        return lang_current_frame();
    };
    match crate::lang::set(value) {
        Ok((value, seq)) => Some(PolicyControl::LangCurrent { value, seq }),
        Err(e) => {
            log_warn!(
                "native-host",
                "lang_set could not be applied ({e}); the previous language stands"
            );
            lang_current_frame()
        }
    }
}

/// Push the current `policy_current` to the extension. Best-effort: a failed write only delays the state to the
/// extension's own `policy_get`.
fn push_policy_current<W: Write>(out: &Mutex<W>) {
    if let Err(e) = write_control_reply(out, &policy_current_reply()) {
        log_warn!("native-host", "could not push policy_current: {e}");
    }
}

/// Push the current `lang_current` to the extension. Best-effort, and skipped entirely when the store is
/// unreadable (already logged).
fn push_lang_current<W: Write>(out: &Mutex<W>) {
    if let Some(frame) = lang_current_frame() {
        if let Err(e) = write_control_reply(out, &frame) {
            log_warn!("native-host", "could not push lang_current: {e}");
        }
    }
}

/// Whether the host key is verifiably ABSENT: the push below must never fire because a same-user process
/// scribbled on the (writable) trust record while the key still exists. `Ok(None)` is the only absent answer;
/// an error (a suspect `KeyInvalid` state, an unreachable store) is not treated as gone.
fn enrollment_key_is_gone() -> bool {
    matches!(EnrollmentKey::lookup(), Ok(None))
}

/// Push the host-originated `enclave_revoked` frame: the extension flips its pinned state to compromised
/// without waiting for an opt-in reverify. Harmless toward an unpinned extension (it ignores the frame).
fn push_revoked<W: Write>(out: &Mutex<W>) {
    log_info!(
        "native-host",
        "host key is revoked; notifying the extension (enclave_revoked)"
    );
    if let Err(e) = write_control_reply(out, &EnclaveControl::EnclaveRevoked {}) {
        log_warn!("native-host", "could not push enclave_revoked: {e}");
    }
}

/// Push the kill state unsolicited: on every observed transition, and at startup only when the news is bad
/// (killed or unreadable). A healthy startup stays quiet because the extension queries `kill_status` on every connect
/// anyway (that query is what clears a stale killed mirror after a CLI unkill); the policy and language pushes DO fire
/// at every connect, since the extension never speaks first on those frames and its dispatch barrier waits for the
/// policy push.
fn push_kill_status<W: Write>(out: &Mutex<W>) {
    if let Err(e) = write_control_reply(out, &kill_status_reply()) {
        log_warn!("native-host", "could not push kill_status_result: {e}");
    }
}

/// The trust-record fields the watch compares between polls, each keying one push.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Watched {
    /// Moves when the enrollment key is revoked.
    host_key_epoch: u64,
    /// Moves on every kill transition, either direction, driving the `kill_status_result` push.
    kill_epoch: u64,
    /// Moves on every host-owned policy change, driving the `policy_current` push.
    policy_epoch: u64,
    /// Moves on every shared-language change, driving the `lang_current` push.
    lang_epoch: u64,
}

impl Watched {
    fn of(trust: &TrustState) -> Self {
        Watched {
            host_key_epoch: trust.host_key_epoch(),
            kill_epoch: trust.kill_epoch(),
            policy_epoch: trust.policy_epoch(),
            lang_epoch: trust.lang_epoch(),
        }
    }
}

/// Watch the trust record while this host runs and push out-of-band transitions (host-key revocation, kill,
/// policy, language) to the extension. With `unkill_observed` (a killed bridge's control-plane mode) an observed
/// release is HANDED to the loop via the flag rather than exiting here: exiting would drop control frames still
/// buffered on stdin, including a `kill_engage` the extension was already told was sent (see [`drain_then_decide`]).
///
/// ```text
/// host-key triggers  -> need a RECORDED revocation (host_key_epoch > 0) AND a keychain-confirmed absent key, so a
///                       scribbled-on trust record cannot fake one
/// observed release   -> pushed BEFORE the flag is raised, so the mirror is not left engaged across the respawn gap
/// ```
fn spawn_trust_watch(
    out: Arc<Mutex<BufWriter<io::Stdout>>>,
    unkill_observed: Option<Arc<AtomicBool>>,
) {
    thread::spawn(move || {
        // A policy-capable host identifies itself at every connect (push_kill_status says why the kill state
        // stays quiet instead): unconditional, before the trust-record read below.
        push_policy_current(&out);
        push_lang_current(&out);
        // Startup posture: bad news is announced now (a key revoked or a kill
        // engaged while no host was running); a healthy kill state stays quiet.
        let mut last: Option<Watched> = match TrustState::current() {
            Ok(trust) => {
                if trust.host_key_epoch() > 0 && enrollment_key_is_gone() {
                    push_revoked(&out);
                }
                if trust.killed() {
                    push_kill_status(&out);
                }
                Some(Watched::of(&trust))
            }
            Err(e) => {
                log_warn!("native-host", "trust record unreadable: {e}");
                push_kill_status(&out); // pushes ok:false (unknown, fail closed)
                None
            }
        };
        loop {
            thread::sleep(POLL_INTERVAL);
            last = watch_tick(
                last,
                TrustState::current(),
                &out,
                unkill_observed.as_deref(),
            );
        }
    });
}

/// One poll of the watch: push what changed since `last` and hand an observed release to the control-plane loop
/// through `unkill_observed`. Returns the state the next poll compares against, `None` after an unreadable read
/// so the next readable one re-runs the startup posture.
///
/// ```text
/// unreadable                     -> once per gap: log, push the unknown kill state
/// readable after unreadable      -> every watched state was unobservable across the gap: push all of them, and a
///                                   released record hands over the release too (the documented recovery from an
///                                   unreadable record is deleting it, which reads as the released bootstrap)
/// kill marker moved, not killed  -> the release handoff, after the push so the mirror is not left engaged
/// ```
fn watch_tick<W: Write>(
    last: Option<Watched>,
    read: io::Result<TrustState>,
    out: &Mutex<W>,
    unkill_observed: Option<&AtomicBool>,
) -> Option<Watched> {
    let trust = match read {
        Ok(trust) => trust,
        Err(e) => {
            if last.is_some() {
                log_warn!("native-host", "trust record unreadable: {e}");
                push_kill_status(out);
            }
            return None;
        }
    };
    let cur = Watched::of(&trust);
    // Lazy: the keychain is asked only when the host-key marker moved (or across a gap), not on every poll of a
    // machine whose marker stays non-zero forever after a revoke.
    let key_gone = || trust.host_key_epoch() > 0 && enrollment_key_is_gone();
    let released = match last {
        Some(prev) => {
            if prev.host_key_epoch != cur.host_key_epoch && key_gone() {
                push_revoked(out);
            }
            let kill_moved = prev.kill_epoch != cur.kill_epoch;
            if kill_moved {
                push_kill_status(out);
            }
            if prev.policy_epoch != cur.policy_epoch {
                push_policy_current(out);
            }
            if prev.lang_epoch != cur.lang_epoch {
                push_lang_current(out);
            }
            kill_moved && !trust.killed()
        }
        None => {
            if key_gone() {
                push_revoked(out);
            }
            push_kill_status(out);
            push_policy_current(out);
            push_lang_current(out);
            !trust.killed()
        }
    };
    if released {
        if let Some(flag) = unkill_observed {
            log_info!(
                "native-host",
                "kill switch released; handing the transition to the control-plane loop"
            );
            flag.store(true, Ordering::Release);
        }
    }
    Some(cur)
}

fn write_replies<W: Write>(out: &Mutex<W>, replies: Vec<HostReply>) -> io::Result<()> {
    replies
        .iter()
        .try_for_each(|reply| write_control_reply(out, reply))
}

/// What one inbound native-messaging frame turned into.
enum Inbound {
    /// A host-handled control frame: the reply (if any) has been written.
    Handled,
    /// Not a control frame: the caller decides (forward over the bridge in
    /// normal mode; drop in control-plane mode).
    Forward(Value),
}

/// Handle one frame from Chrome against the host-handled control surface. Shared by the normal
/// stdin->socket pump and the control-plane-only loop, so the two modes cannot drift in what they answer.
/// An `Err` means a control REPLY could not be written (stdout gone), which ends the calling loop.
fn handle_control_frame<W: Write>(
    frame: Value,
    out: &Mutex<W>,
    exchange: &mut Exchange,
) -> io::Result<Inbound> {
    match classify_nm_frame(&frame) {
        FrameDisposition::Forward => Ok(Inbound::Forward(frame)),
        FrameDisposition::Handle(request) => {
            handle_request(request, out, exchange)?;
            Ok(Inbound::Handled)
        }
        FrameDisposition::Malformed { tag, error } => {
            log_warn!("native-host", "malformed {tag} frame from browser: {error}");
            match tag.malformed_reply() {
                MalformedReply::Drop => {}
                MalformedReply::Send(reply) => write_control_reply(out, &reply)?,
                MalformedReply::LangCurrent => {
                    if let Some(reply) = lang_current_frame() {
                        write_control_reply(out, &reply)?;
                    }
                }
            }
            Ok(Inbound::Handled)
        }
    }
}

/// Answer one parsed request. Exhaustive on purpose: a [`HostRequest`] variant without an arm here does
/// not compile, so no inbound frame type can ship unhandled. The WebAuthn arms hand the exchange its frame
/// and write every reply it returns, in order; the exchange is owned by the one thread that dispatches
/// frames in either mode.
fn handle_request<W: Write>(
    request: HostRequest,
    out: &Mutex<W>,
    exchange: &mut Exchange,
) -> io::Result<()> {
    match request {
        HostRequest::EnclaveChallenge { nonce, context } => {
            log_info!("native-host", "answering host-key challenge locally");
            let reply = crate::enclave::respond_to_challenge(&nonce, context.as_deref());
            write_control_reply(out, &reply)
        }
        HostRequest::EnrollBegin {} => write_replies(out, exchange.enroll_begin()),
        HostRequest::EnrollFinish {
            attestation_object,
            client_data_json,
        } => {
            let registration = Registration::from_base64url(&attestation_object, &client_data_json);
            write_replies(out, exchange.enroll_finish(registration))
        }
        HostRequest::PresenceBegin { action, origin } => {
            write_replies(out, exchange.presence_begin(&action, &origin))
        }
        HostRequest::PresenceAssert {
            credential_id,
            authenticator_data,
            client_data_json,
            signature,
        } => {
            let assertion =
                Assertion::from_base64url(&authenticator_data, &client_data_json, &signature);
            write_replies(out, exchange.presence_assert(&credential_id, assertion))
        }
        HostRequest::PresenceConfirm { nonce } => {
            write_replies(out, exchange.presence_confirm(&nonce))
        }
        HostRequest::BrowserRevoke {} => write_replies(out, exchange.browser_revoke()),
        HostRequest::EnclaveRevoke {} => write_control_reply(out, &revoke_host_key()),
        HostRequest::ClientList {} => write_control_reply(out, &admin_client_list()),
        HostRequest::ClientRevoke { name } => write_control_reply(out, &admin_client_revoke(&name)),
        HostRequest::ClientPair { name, anchor } => {
            write_replies(out, exchange.client_pair(name, anchor))
        }
        HostRequest::KillStatus {} => write_control_reply(out, &kill_status_reply()),
        HostRequest::KillEngage {} => write_control_reply(out, &handle_kill_engage()),
        HostRequest::KillRelease {} => write_replies(out, exchange.kill_release()),
        HostRequest::DoctorReport {} => write_control_reply(out, &doctor_report_reply()),
        HostRequest::AuditRead { limit } => write_control_reply(out, &audit_read_reply(limit)),
        HostRequest::RegistrationStatus {} => {
            write_control_reply(out, &registration_status_reply())
        }
        HostRequest::RegistrationRepair { browsers } => {
            write_control_reply(out, &registration_repair_reply(browsers))
        }
        HostRequest::PolicyGet {} => write_control_reply(out, &policy_current_reply()),
        HostRequest::PolicyRestrict { overlay } => {
            write_replies(out, restrict_replies(overlay, WriteLane::PolicyRestrict))
        }
        HostRequest::PolicySet { overlay } => write_replies(out, exchange.policy_set(overlay)),
        HostRequest::PolicyHistory {} => write_control_reply(out, &policy_history_reply()),
        HostRequest::PolicyRollback { revision } => {
            write_replies(out, exchange.policy_rollback(revision))
        }
        HostRequest::LangGet {} => match lang_current_frame() {
            Some(reply) => write_control_reply(out, &reply),
            None => Ok(()),
        },
        HostRequest::LangSet { value } => match handle_lang_set(value) {
            Some(reply) => write_control_reply(out, &reply),
            None => Ok(()),
        },
        HostRequest::AuditEvent {
            kind,
            outcome,
            tool,
            name,
            detail,
            cid,
        } => {
            let mut rec = crate::audit::AuditRecord::new(kind.into())
                .surface(crate::audit::Surface::Extension);
            rec.outcome = outcome;
            rec.tool = tool;
            rec.name = name;
            rec.detail = detail;
            rec.cid = cid;
            crate::audit::record(rec);
            Ok(())
        }
    }
}

// ---- control-plane-only mode ---------------------------------------------------

/// One event on the control-plane loop's inbound channel.
enum PlaneEvent {
    /// A native-messaging frame from Chrome.
    Frame(Value),
    /// stdin EOF: Chrome tore the port down.
    Eof,
    /// stdin read error (framing violation, pipe error).
    ReadError(String),
}

/// Why the control-plane loop ended.
#[derive(Debug, PartialEq, Eq)]
enum PlaneExit {
    /// stdin is gone (EOF or read error), a control reply could not be
    /// written, or the reader thread died: Chrome is done with this host.
    StdinClosed,
    /// The kill switch authoritatively read released after a drained-quiet
    /// pipe: exit so the extension reconnects into a bridge-mode host.
    Unkilled,
}

/// The control-plane loop's verdict on an observed unkill.
enum UnkillDecision {
    Exit(PlaneExit),
    /// The state does not authoritatively read alive after the drain (a
    /// drained frame re-engaged the switch, or the record is unreadable):
    /// keep serving the control plane, fail closed.
    Stay,
}

/// How long the pipe must stay quiet, after an observed unkill, before the
/// state re-check and exit. Bytes Chrome accepted before the release reply
/// reached the extension are long since readable; this window only covers
/// their last hop into our stdin.
const UNKILL_DRAIN_SETTLE: Duration = Duration::from_millis(200);

/// How often the loop wakes from an idle channel to check the unkill flag.
const PLANE_TICK: Duration = Duration::from_millis(100);

/// The unkill transition, taken only by the control-plane loop: drain the control frames already buffered on
/// stdin, then re-read the kill state and exit only on an authoritative alive. The extension's panic path is
/// told ok:true the moment a `kill_engage` is accepted for the pipe, so one that raced an in-flight release may
/// still be sitting in our stdin when the watch observes the released state.
///
/// ```text
/// drained frame re-engaged the switch  -> stay in control-plane mode
/// state unreadable after the drain     -> stay; leaving killed mode on ambiguity would fail open
/// frame lands after the settle window  -> dies with the process; the extension's latch stays engaged and it
///                                         re-posts the engage on reconnect (at-least-once, idempotent here)
/// ```
fn drain_then_decide<H, K>(
    frames: &mpsc::Receiver<PlaneEvent>,
    handle: &mut H,
    killed_now: &K,
) -> UnkillDecision
where
    H: FnMut(Value) -> io::Result<()>,
    K: Fn() -> io::Result<bool>,
{
    loop {
        match frames.recv_timeout(UNKILL_DRAIN_SETTLE) {
            Ok(PlaneEvent::Frame(frame)) => {
                if let Err(e) = handle(frame) {
                    log_warn!("native-host", "control reply write error: {e}");
                    return UnkillDecision::Exit(PlaneExit::StdinClosed);
                }
            }
            Ok(PlaneEvent::Eof) => {
                log_info!("native-host", "stdin EOF, shutting down");
                return UnkillDecision::Exit(PlaneExit::StdinClosed);
            }
            Ok(PlaneEvent::ReadError(e)) => {
                log_warn!("native-host", "stdin read error: {e}");
                return UnkillDecision::Exit(PlaneExit::StdinClosed);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => break,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return UnkillDecision::Exit(PlaneExit::StdinClosed)
            }
        }
    }
    match killed_now() {
        Ok(false) => UnkillDecision::Exit(PlaneExit::Unkilled),
        Ok(true) => {
            log_info!(
                "native-host",
                "kill switch re-engaged during the release drain; staying in control-plane mode"
            );
            UnkillDecision::Stay
        }
        Err(e) => {
            log_warn!(
                "native-host",
                "kill state unreadable after the release ({e}); staying in \
                 control-plane mode (fail closed)"
            );
            UnkillDecision::Stay
        }
    }
}

/// The control-plane pump: handle channel events, and take the unkill
/// transition through [`drain_then_decide`] whenever the watch raises the
/// flag. Extracted from [`run_control_plane`] so the frame/flag interleaving
/// is unit-testable without a real stdin.
fn control_plane_loop<H, K>(
    frames: &mpsc::Receiver<PlaneEvent>,
    unkill_observed: &AtomicBool,
    handle: &mut H,
    killed_now: &K,
) -> PlaneExit
where
    H: FnMut(Value) -> io::Result<()>,
    K: Fn() -> io::Result<bool>,
{
    loop {
        if unkill_observed.swap(false, Ordering::AcqRel) {
            match drain_then_decide(frames, handle, killed_now) {
                UnkillDecision::Exit(exit) => return exit,
                UnkillDecision::Stay => {}
            }
        }
        match frames.recv_timeout(PLANE_TICK) {
            Ok(PlaneEvent::Frame(frame)) => {
                if let Err(e) = handle(frame) {
                    log_warn!("native-host", "control reply write error: {e}");
                    return PlaneExit::StdinClosed;
                }
            }
            Ok(PlaneEvent::Eof) => {
                log_info!("native-host", "stdin EOF, shutting down");
                return PlaneExit::StdinClosed;
            }
            Ok(PlaneEvent::ReadError(e)) => {
                log_warn!("native-host", "stdin read error: {e}");
                return PlaneExit::StdinClosed;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return PlaneExit::StdinClosed,
        }
    }
}

/// Control-plane-only mode: the bridge is killed or its state is unreadable, so nothing may flow between
/// browser and broker, yet this host must stay up because the extension's SW-only kill mirror is fed by its pushes.
/// stdin is read on its own thread feeding a channel so the loop can interleave frames with the unkill flag
/// (see [`drain_then_decide`]).
/// ```text
/// control frame (kill_engage, kill_status, kill_release)  -> answered; kill_release opens the presence exchange
/// bridge frame                                             -> dropped and logged; no socket is dialed
/// release (CLI unkill, or the exchange) seen by the watch  -> queued frames drained, then exit if the kill is still
///                                                            released (the extension reconnects into a bridge host);
///                                                            a queued kill_engage or unreadable kill state stays here
/// ```
fn run_control_plane(mut exchange: Exchange) -> i32 {
    let stdout_writer = Arc::new(Mutex::new(BufWriter::new(io::stdout())));
    // The watch raises this flag on an observed release; leaving this mode
    // is the LOOP's decision, after the drain (see drain_then_decide).
    let unkill_observed = Arc::new(AtomicBool::new(false));
    spawn_trust_watch(
        Arc::clone(&stdout_writer),
        Some(Arc::clone(&unkill_observed)),
    );
    // Bound 1, not more: native-messaging frames can reach tens of MB each, and an unbounded queue would let a
    // faulty or hostile extension stack them in memory while the loop is blocked on a presence prompt. A full
    // channel parks the reader thread, which parks Chrome's pipe; the peak held is about three frames (one being
    // handled, one queued, one parsed in the blocked reader), enough for the reader to stay a frame ahead during
    // the unkill drain.
    let (frame_tx, frame_rx) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut stdin = io::stdin();
        loop {
            let event = match nm_read_frame(&mut stdin) {
                Ok(Some(frame)) => PlaneEvent::Frame(frame),
                Ok(None) => PlaneEvent::Eof,
                Err(e) => PlaneEvent::ReadError(e.to_string()),
            };
            let ends = !matches!(event, PlaneEvent::Frame(_));
            if frame_tx.send(event).is_err() || ends {
                return;
            }
        }
    });
    let mut handle = |frame: Value| -> io::Result<()> {
        match handle_control_frame(frame, &stdout_writer, &mut exchange)? {
            Inbound::Handled => {}
            Inbound::Forward(_) => {
                // Fail closed: no bridge traffic while killed. The extension's
                // own gate refuses ops too; this covers a raced or tampered
                // sender.
                log_warn!(
                    "native-host",
                    "dropping bridge frame while the kill switch is engaged"
                );
            }
        }
        Ok(())
    };
    let exit = control_plane_loop(&frame_rx, &unkill_observed, &mut handle, &|| {
        crate::kill::is_killed()
    });
    if exit == PlaneExit::Unkilled {
        log_info!(
            "native-host",
            "kill switch released; exiting so the extension reconnects into a \
             bridge-mode host"
        );
    }
    0
}

/// `label` is the browser this host fronts (`--label <name>`, baked into the
/// per-browser wrapper by the registration engine, validated at the argv
/// boundary). It rides in the signed handshake response so the MCP server
/// can key its connection registry by browser.
pub fn run(label: Option<BrowserLabel>) -> i32 {
    // Capture our own executable identity before dialing, so attesting the
    // server compares against the genuine binary and we fail fast if we cannot
    // hash our own image.
    if let Err(e) = ipc::ensure_own_identity() {
        log_error!(
            "native-host",
            "cannot establish own executable identity: {e}"
        );
        return 1;
    }

    // The exchange binds every WebAuthn statement to the browser this host fronts, the same label the
    // handshake signs; an unlabelled wrapper is the default browser here as there.
    let mut exchange = Exchange::new(label.clone().unwrap_or_else(BrowserLabel::default_label));

    // While the kill switch is engaged, or its state cannot be read, this host bridges NOTHING. It does not
    // even dial the broker (which refuses browser attaches while killed); it drops into the control-plane-only
    // mode instead, which keeps the extension's release surface reachable and its kill mirror fed.
    match crate::kill::is_killed() {
        Ok(false) => {}
        Ok(true) => {
            log_error!(
                "native-host",
                "kill switch is engaged; serving the control plane only (no bridge traffic)"
            );
            return run_control_plane(exchange);
        }
        Err(e) => {
            log_error!(
                "native-host",
                "kill state unreadable ({e}); failing closed to the control plane only"
            );
            return run_control_plane(exchange);
        }
    }

    // Connect to the MCP server's bridge socket (reads the lock file).
    let stream = match ipc::connect() {
        Ok(s) => s,
        Err(e) => {
            log_error!("native-host", "cannot connect to MCP server: {e}");
            // No way to talk to Chrome usefully without the server; exit so
            // the extension sees onDisconnect and can surface the error.
            return 1;
        }
    };
    log_info!("native-host", "connected to MCP server bridge socket");

    // Kernel-attest the SERVER before speaking the handshake or forwarding any
    // frames: require it to be another instance of THIS binary. Fail closed so
    // a hostile same-user process cannot impersonate the MCP server.
    if let Err(e) = ipc::attest_peer(&stream) {
        log_error!("native-host", "server attestation failed: {e}");
        return 1;
    }

    // Build the buffered halves the pumps will reuse, then authenticate over
    // them BEFORE any pumping. Doing the handshake on the same buffers the
    // pumps keep guarantees the challenge/response never mixes with forwarded
    // frames and that no byte read during the handshake is lost.
    let read_half = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            log_error!("native-host", "clone stream: {e}");
            return 1;
        }
    };
    let mut reader = BufReader::new(read_half);
    let mut writer = BufWriter::new(stream);
    if let Err(e) = ipc::client_handshake(&mut reader, &mut writer, label.clone()) {
        log_error!("native-host", "bridge handshake failed: {e}");
        return 1;
    }
    // Declare our role to the broker: a native host fronting a browser. The
    // browser label was already MAC-signed in the handshake response, so this
    // frame only carries the role. The broker replies with an AttachReply;
    // anything but Accepted (a capacity/version refusal, or a closed socket)
    // means we exit so Chrome tears down the port and the extension reconnects.
    if let Err(e) =
        crate::protocol::bridge_write(&mut writer, &crate::protocol::AttachRequest::Browser {})
    {
        log_error!("native-host", "attach declaration failed: {e}");
        return 1;
    }
    match crate::protocol::bridge_read::<_, crate::protocol::AttachReply>(&mut reader) {
        Ok(Some(crate::protocol::AttachReply::Accepted {})) => {}
        Ok(Some(other)) => {
            log_error!(
                "native-host",
                "broker did not accept this browser attach: {other:?}"
            );
            return 1;
        }
        Ok(None) => {
            log_error!(
                "native-host",
                "broker closed before accepting the browser attach"
            );
            return 1;
        }
        Err(e) => {
            log_error!(
                "native-host",
                "reading the broker's attach reply failed: {e}"
            );
            return 1;
        }
    }
    log_info!(
        "native-host",
        "bridge handshake complete (label '{}')",
        label
            .as_ref()
            .map_or(ipc::DEFAULT_LABEL, ipc::BrowserLabel::as_str)
    );

    // Whichever pump ends first exits the whole process: joining both threads would deadlock when the socket side
    // dies (the stdin thread sits in nm_read_frame waiting for a frame Chrome, still alive, never sends, the zombie
    // keeps stdin/stdout open, the extension's onDisconnect never fires, and it never reconnects to the freshly
    // written lock file). process::exit runs no destructors, but every writer flushes per frame, so no buffered data
    // is lost on the normal close paths.

    // stdout is shared: the socket->stdout pump owns it in steady state, and
    // the stdin->socket thread borrows it briefly to answer host-handled
    // control frames (which reply toward Chrome, not toward the socket). A
    // mutex around one buffered writer keeps frames whole; every write flushes.
    let stdout_writer = Arc::new(Mutex::new(BufWriter::new(io::stdout())));

    // Notify the extension when the host key has been revoked out-of-band, and keep its kill mirror fed (at
    // startup and on every observed transition). No unkill flag: in bridge mode an engaged kill ends this
    // process via the broker severing the socket.
    spawn_trust_watch(Arc::clone(&stdout_writer), None);

    // Thread A: stdin -> socket
    let ctrl_out = Arc::clone(&stdout_writer);
    thread::spawn(move || {
        let mut stdin = io::stdin();
        let mut sock = writer;
        loop {
            let frame: Option<Value> = match nm_read_frame(&mut stdin) {
                Ok(v) => v,
                Err(e) => {
                    log_warn!("native-host", "stdin read error: {e}");
                    break;
                }
            };
            let frame = match frame {
                Some(v) => v,
                None => {
                    // EOF on stdin: Chrome disconnected. Canonical shutdown.
                    log_info!("native-host", "stdin EOF, shutting down");
                    break;
                }
            };
            // Host-handled control frames are addressed to THIS process and must never reach the socket;
            // everything else forwards.
            match handle_control_frame(frame, &ctrl_out, &mut exchange) {
                Ok(Inbound::Handled) => continue,
                Ok(Inbound::Forward(frame)) => {
                    if let Err(e) = bridge_write(&mut sock, &frame) {
                        log_warn!("native-host", "bridge write error: {e}");
                        break;
                    }
                }
                Err(e) => {
                    log_warn!("native-host", "control reply write error: {e}");
                    break;
                }
            }
        }
        // Either side breaking means this process is done. Exit immediately so
        // Chrome tears down the port and the extension reconnects.
        log_debug!(
            "native-host",
            "stdin->socket thread ending; exiting process"
        );
        std::process::exit(0);
    });

    // Thread B: socket -> stdout. This thread is the main one; if IT exits we
    // simply fall through to the return below (which also ends the process).
    // The handshake is already complete, so every line here is a real frame
    // bound for Chrome.
    let out_handle = thread::spawn(move || {
        // Forwarded frames share stdout with Thread A's control replies,
        // so the pump locks the buffered writer per frame (never across the
        // blocking socket read) - otherwise a challenge reply could not be
        // written while this thread waits on the socket, hanging the ceremony.
        pump_socket_to_stdout(&mut reader, &stdout_writer);
        log_debug!("native-host", "socket->stdout thread ending");
    });

    // Block until the socket->stdout thread ends. The stdin->socket thread will
    // have already called process::exit(0) on its own close path; if it
    // hasn't, we exit here once the socket side closes.
    let _ = out_handle.join();
    log_debug!("native-host", "exit");
    std::process::exit(0);
}

/// Pump NDJSON lines from the bridge socket to stdout as native-messaging frames. [`bridge_read`] bounds every
/// line by `BRIDGE_MAX_LINE`: the server passed attestation, but even an attested peer must not exhaust memory
/// with one newline-less line. The lock on `out` is taken per frame, never across the blocking read, so the
/// stdin->socket thread's control replies can interleave while this pump waits on the socket.
///
/// ```text
/// read error, an over-cap line included  -> fail closed: the pump ends, the process exits, Chrome tears the port down
/// host control frame on the socket leg   -> an injection (a spurious `enclave_error` to burn the extension's nonce,
///                                           an `enclave_revoked` to fake a compromise, a forged `client_list_result`):
///                                           dropped and logged; a recognized, bounded frame, so the pump keeps going
/// ```
fn pump_socket_to_stdout<R: BufRead, W: Write>(reader: &mut R, out: &Mutex<W>) {
    loop {
        let value: Value = match bridge_read(reader) {
            Ok(Some(v)) => v,
            Ok(None) => {
                log_info!("native-host", "bridge EOF");
                break;
            }
            Err(e) => {
                log_warn!("native-host", "bridge read error: {e}");
                break;
            }
        };
        if let Some(kind) = host_control_type(&value) {
            log_warn!(
                "native-host",
                "dropping {kind} frame injected by the server; host control \
                 frames never legitimately arrive on the socket leg"
            );
            continue;
        }
        let mut out = out
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(e) = nm_write_frame(&mut *out, &value) {
            log_warn!("native-host", "stdout write error: {e}");
            break;
        }
    }
}

#[cfg(test)]
mod tests;
