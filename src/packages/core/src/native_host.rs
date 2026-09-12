//! Native-host mode: the `--native-host` subprocess Chrome spawns. It is intentionally dumb, so all real tool
//! logic stays in the MCP server on the other side of the socket; EOF on stdin (Chrome disconnected) is the
//! shutdown signal.
//!
//! ```text
//! stdin  -> socket   native-messaging frames forwarded as NDJSON lines, except the host-handled control frames
//!                    (enrollment ceremony, revocation and client admin, kill switch, presence, policy and
//!                    language), which are answered HERE and never reach the server
//! socket -> stdout   NDJSON lines framed for Chrome, except a control frame from the server, which is an
//!                    injection and is dropped
//! ```
//!
//! The `enclave_revoked` push (ADR-0025) is host-originated on purpose: the socket->stdout pump drops any
//! server-injected control frame, so only this process can put that frame in front of the extension. It fires
//! at startup when the key is already gone and live when the host-key epoch moves.

use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::enclave::EnrollmentKey;
use crate::ipc;
use crate::protocol::control::{
    classify_nm_frame, host_control_type, AdminControl, AdminKind, AuditEventFields,
    EnclaveControl, FrameDisposition, KillStatus, PolicyControl, PolicyKind, PolicyStatus,
    PolicyUnavailableReason,
};
use crate::protocol::{bridge_read, bridge_write, nm_read_frame, nm_write_frame};
use crate::revocation::{Revocation, REVOCATION_POLL};
use serde::Serialize;
use serde_json::Value;

/// Serialize a host-handled control frame (enclave or admin) and write it to
/// Chrome via the shared stdout writer. `nm_write_frame` flushes per frame, so
/// taking the lock per frame keeps replies atomic with respect to the
/// socket->stdout pump.
fn write_control_reply<T: Serialize>(
    out: &Mutex<BufWriter<io::Stdout>>,
    reply: &T,
) -> io::Result<()> {
    let value = serde_json::to_value(reply)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("encode reply: {e}")))?;
    let mut out = out
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    nm_write_frame(&mut *out, &value)
}

// ---- ADR-0025: revocation handlers and the host-originated push -------------

/// Handle an `enclave_revoke` frame from the extension: route through the
/// shared enrollment-disposal seam (ADR-0032 decision 3) so the SAME critical
/// section that deletes the key also clears the signed policy baseline and
/// bumps the host-key epoch - the extension-originated path is the one most
/// likely to leave a surviving baseline (the "artifact of a dead key" trap),
/// so it must not hand-roll the deletion. Replies `enclave_revoked` when the
/// requested end state holds (the key is gone -- including when none existed),
/// or a typed `enclave_error`.
fn revoke_host_key() -> EnclaveControl {
    match crate::enclave::dispose_enrollment_and_policy_baseline() {
        Ok(existed) => {
            log_info!(
                "native-host",
                "extension revoked the enrollment key (existed: {existed})"
            );
            // Log-after-decide (ADR-0030): the disposal is complete.
            crate::enclave::audit_host_key_revoke(crate::audit::Surface::Extension);
            EnclaveControl::EnclaveRevoked {}
        }
        Err(e) => {
            log_warn!("native-host", "extension-requested revoke failed: {e}");
            EnclaveControl::EnclaveError {
                reason: crate::enclave::reason_code(&e).to_string(),
            }
        }
    }
}

/// Handle a `client_list` frame: report the trusted-client allowlist, honoring
/// the tamper-evidence latch (an absent-but-latched list is an error, not
/// "unenrolled").
fn admin_client_list() -> AdminControl {
    let rev = match Revocation::current() {
        Ok(rev) => rev,
        Err(e) => {
            return AdminControl::ClientListResult {
                ok: false,
                enrolled: false,
                clients: Vec::new(),
                error: Some(format!("revocation record unreadable: {e}")),
            };
        }
    };
    match crate::allowlist::load_enforced(&rev) {
        Ok(Some(list)) => AdminControl::ClientListResult {
            ok: true,
            enrolled: true,
            clients: list.clients,
            error: None,
        },
        Ok(None) => AdminControl::ClientListResult {
            ok: true,
            enrolled: false,
            clients: Vec::new(),
            error: None,
        },
        Err(e) => AdminControl::ClientListResult {
            ok: false,
            enrolled: true,
            clients: Vec::new(),
            error: Some(e.to_string()),
        },
    }
}

/// Handle a `client_revoke` frame: remove one trusted client.
/// `Allowlist::revoke` rewrites the list and bumps the revocation epoch in one
/// critical section, so a live broker drops that client's connections.
fn admin_client_revoke(name: &str) -> AdminControl {
    if !ipc::validate_label(name) {
        return AdminControl::ClientRevokeResult {
            ok: false,
            error: Some("invalid client name".into()),
        };
    }
    // The RevokeClient audit record is written inside Allowlist::revoke
    // (log-after-decide), so no revoke surface can forget the trail entry.
    match crate::allowlist::Allowlist::revoke(name, crate::audit::Surface::Extension) {
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

// ---- ADR-0030: kill-switch control frames and the audit-event sink ----------

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

/// Handle `kill_engage` from the extension (ADR-0030). The core API performs
/// the latch flip + epoch bump in one critical section and audits it with
/// `surface: extension`. The reply reports the resulting state, which the
/// extension's SW-only mirror adopts. Engage only reduces capability (the
/// brake stays one action away on every surface, ADR-0032 decision 1), so it
/// needs no presence gate.
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

/// Handle `kill_release` from the extension: REFUSE it, audited (ADR-0032
/// decision 6). Release wholesale-restores capability and now moves to the
/// strongest gates - `chromium-bridge unkill` and the desktop app, both behind
/// the ADR-0031 presence ladder - so the extension no longer holds a release
/// surface at all (its UI drops the control, keeping engage). This host answers
/// the retired frame with a refusal rather than silently dropping it, so a
/// stale extension's pending request resolves and the trail records the
/// attempt. The refusal is not a state read, so it carries no `killed` claim.
fn handle_kill_release_refused() -> AdminControl {
    // Log-after-decide (ADR-0030): the refusal is the decision.
    crate::audit::record(
        crate::audit::AuditRecord::new(crate::audit::AuditKind::KillRelease)
            .surface(crate::audit::Surface::Extension)
            .outcome("refused")
            .detail(
                "extension kill_release retired (ADR-0032 decision 6); release is app/CLI only",
            ),
    );
    log_warn!(
        "native-host",
        "refusing extension-originated kill_release: retired (ADR-0032 decision 6); \
         release via the desktop app or `chromium-bridge unkill`"
    );
    KillStatus::Unreadable {
        error: "kill_release from the extension is retired (ADR-0032); release via the \
                desktop app or `chromium-bridge unkill`"
            .into(),
    }
    .into_frame()
}

/// Record one extension-side decision in the audit trail (ADR-0030). The
/// fields arrive by name, and the kind is already the typed, extension-owned
/// [`crate::audit::AuditKind`]: [`classify_nm_frame`] mapped it through
/// [`crate::audit::extension_kind`] and the surface is stamped HERE, so the
/// browser leg cannot forge host-side events (an admission, a kill) into the
/// trail. Fire-and-forget: no reply.
fn handle_audit_event(fields: AuditEventFields) {
    let AuditEventFields {
        kind,
        outcome,
        tool,
        name,
        detail,
        cid,
    } = fields;
    let mut rec = crate::audit::AuditRecord::new(kind).surface(crate::audit::Surface::Extension);
    rec.outcome = outcome;
    rec.tool = tool;
    rec.name = name;
    rec.detail = detail;
    rec.cid = cid;
    crate::audit::record(rec);
}

/// The reply for a malformed admin request frame: the matching result frame
/// with `ok: false`, so the extension's pending request resolves instead of
/// timing out. Exhaustive over [`AdminKind`] with no catch-all: the compiler
/// holds every request kind to a reply of its own type.
fn malformed_admin_reply(kind: AdminKind) -> AdminControl {
    match kind {
        AdminKind::ClientList => AdminControl::ClientListResult {
            ok: false,
            enrolled: false,
            clients: Vec::new(),
            error: Some("malformed client_list frame".into()),
        },
        AdminKind::ClientRevoke => AdminControl::ClientRevokeResult {
            ok: false,
            error: Some("malformed client_revoke frame".into()),
        },
        AdminKind::KillStatus | AdminKind::KillEngage | AdminKind::KillRelease => {
            KillStatus::Unreadable {
                error: format!("malformed {} frame", kind.wire_tag()),
            }
            .into_frame()
        }
    }
}

// ---- ADR-0032: host-owned policy and shared-language control frames ----------

/// The current policy state as a `policy_current` frame (ADR-0032 decision 4). The baseline travels as the stored
/// bytes, never re-serialized or canonicalized: the extension verifies the exact bytes against its own pin (decision 3).
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
                reason: Some(PolicyUnavailableReason::Damaged),
                error: format!("policy store damaged: {e}"),
            },
        },
        Ok(None) => PolicyStatus::Unavailable {
            reason: Some(PolicyUnavailableReason::Absent),
            error: "no policy baseline on this host".into(),
        },
        Err(e) => PolicyStatus::Unavailable {
            reason: Some(PolicyUnavailableReason::Unreadable),
            error: format!("policy store unreadable: {e}"),
        },
    };
    status.into_frame()
}

/// The current shared language as a `lang_current` frame (ADR-0032 decision
/// 7), or `None` when the store is unreadable (fail closed: skip the reply /
/// push and log, rather than answer with a guessed value that could reset a
/// receiver's sequence). An absent store reads as the default, which is a
/// normal answer, not an error.
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

/// Handle a `lang_set` (ADR-0032 decision 7): an out-of-enum value is refused
/// and the previous value stands (reply the UNCHANGED `lang_current`); a valid
/// value is applied, bumping the sequence only if it changed, and the
/// resulting `lang_current` is the reply. `None` only when the store is
/// unreadable (see [`lang_current_frame`]).
fn handle_lang_set(value: String) -> Option<PolicyControl> {
    if !crate::lang::is_valid_lang(&value) {
        log_warn!(
            "native-host",
            "refusing out-of-enum lang_set {value:?}; the previous language stands"
        );
        return lang_current_frame();
    }
    match crate::lang::set(&value) {
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

/// The reply for a malformed policy/language REQUEST frame, mirroring
/// [`malformed_admin_reply`]: exhaustive over [`PolicyKind`], so the reply
/// type provably matches the request. A malformed `policy_get` answers
/// `policy_current { ok: false }`; a malformed `lang_get`/`lang_set` answers
/// `lang_current` with the UNCHANGED value+seq (decision 7). `None` only when
/// the language store is unreadable.
fn malformed_policy_reply(kind: PolicyKind) -> Option<PolicyControl> {
    match kind {
        PolicyKind::PolicyGet => Some(
            PolicyStatus::Unavailable {
                // A malformed REQUEST is not a store-availability state, so it
                // carries no structured reason: the extension must not read a
                // bad-frame reply as "no baseline, send the legacy import".
                reason: None,
                error: "malformed policy_get frame".into(),
            }
            .into_frame(),
        ),
        PolicyKind::LangGet | PolicyKind::LangSet => lang_current_frame(),
    }
}

/// Push the current `policy_current` to the extension (ADR-0032 decision 4).
/// Best-effort: a failed write only delays the state to the extension's own
/// `policy_get`.
fn push_policy_current(out: &Mutex<BufWriter<io::Stdout>>) {
    if let Err(e) = write_control_reply(out, &policy_current_reply()) {
        log_warn!("native-host", "could not push policy_current: {e}");
    }
}

/// Push the current `lang_current` to the extension (ADR-0032 decision 7).
/// Best-effort, and skipped entirely when the store is unreadable (already
/// logged).
fn push_lang_current(out: &Mutex<BufWriter<io::Stdout>>) {
    if let Some(frame) = lang_current_frame() {
        if let Err(e) = write_control_reply(out, &frame) {
            log_warn!("native-host", "could not push lang_current: {e}");
        }
    }
}

/// Whether the enrollment key is verifiably ABSENT from the keychain. This is
/// keychain truth, not file truth: the push below must never fire because a
/// same-user process scribbled on the (writable) revocation file while the
/// key still exists. `Ok(None)` is the only absent answer; an error (including
/// non-macOS `Unsupported` and a suspect `KeyInvalid` state) is not treated as
/// gone.
fn enrollment_key_is_gone() -> bool {
    matches!(EnrollmentKey::lookup(), Ok(None))
}

/// Push the host-originated `enclave_revoked` frame (ADR-0025): the extension
/// flips its pinned state to compromised without waiting for an opt-in
/// reverify. Harmless toward an unpinned extension (it ignores the frame).
fn push_revoked(out: &Mutex<BufWriter<io::Stdout>>) {
    log_info!(
        "native-host",
        "enrollment key is revoked; notifying the extension (enclave_revoked)"
    );
    if let Err(e) = write_control_reply(out, &EnclaveControl::EnclaveRevoked {}) {
        log_warn!("native-host", "could not push enclave_revoked: {e}");
    }
}

/// Push the kill state unsolicited (ADR-0030): on every observed transition, and at startup only when the news is bad
/// (killed or unreadable). A healthy startup stays quiet because the extension queries `kill_status` on every connect
/// anyway (that query is what clears a stale killed mirror after a CLI unkill); the policy and language pushes DO fire
/// at every connect, since the extension never speaks first on those frames and its dispatch barrier waits for the
/// policy push (ADR-0032 decision 4).
fn push_kill_status(out: &Mutex<BufWriter<io::Stdout>>) {
    if let Err(e) = write_control_reply(out, &kill_status_reply()) {
        log_warn!("native-host", "could not push kill_status_result: {e}");
    }
}

/// The revocation epochs the watch compares between polls, by name: a
/// positional tuple here would let a silent swap cross one epoch's check with
/// another's push, so each epoch travels under its own field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WatchedEpochs {
    /// `Revocation::host_key_epoch` - bumps when the enrollment key is revoked.
    host_key: u64,
    /// `Revocation::kill_epoch` - bumps on every kill-switch transition.
    kill: u64,
    /// `Revocation::policy_epoch` - bumps on every host-owned policy change
    /// (ADR-0032 decision 4), driving the `policy_current` push.
    policy: u64,
    /// `Revocation::lang_epoch` - bumps on every shared-language change
    /// (ADR-0032 decision 7), driving the `lang_current` push.
    lang: u64,
}

impl WatchedEpochs {
    fn of(rev: &Revocation) -> Self {
        WatchedEpochs {
            host_key: rev.host_key_epoch,
            kill: rev.kill_epoch,
            policy: rev.policy_epoch,
            lang: rev.lang_epoch,
        }
    }
}

/// Watch the revocation record while this host runs and push out-of-band transitions (host-key revocation, kill,
/// policy, language) to the extension. With `unkill_observed` (a killed bridge's control-plane mode) an observed
/// release is HANDED to the loop via the flag rather than exiting here: exiting would drop control frames still
/// buffered on stdin, including a `kill_engage` the extension was already told was sent (see [`drain_then_decide`]).
///
/// ```text
/// host-key triggers  -> need a RECORDED revocation (host_key_epoch > 0) AND a keychain-confirmed absent key, so a
///                       scribbled-on revocation file cannot fake one (ADR-0025)
/// observed release   -> pushed BEFORE the flag is raised, so the mirror is not left engaged across the respawn gap
/// ```
fn spawn_revocation_watch(
    out: Arc<Mutex<BufWriter<io::Stdout>>>,
    unkill_observed: Option<Arc<AtomicBool>>,
) {
    thread::spawn(move || {
        // A policy-capable host identifies itself at every connect (ADR-0032 decision 4; push_kill_status says
        // why the kill state stays quiet instead): unconditional, before the revocation-record read below.
        push_policy_current(&out);
        push_lang_current(&out);
        // Startup posture: bad news is announced now (a key revoked or a kill
        // engaged while no host was running); a healthy kill state stays quiet.
        let mut last: Option<WatchedEpochs> = match Revocation::current() {
            Ok(rev) => {
                if rev.host_key_epoch > 0 && enrollment_key_is_gone() {
                    push_revoked(&out);
                }
                if rev.killed {
                    push_kill_status(&out);
                }
                Some(WatchedEpochs::of(&rev))
            }
            Err(e) => {
                log_warn!("native-host", "revocation record unreadable: {e}");
                push_kill_status(&out); // pushes ok:false (unknown, fail closed)
                None
            }
        };
        loop {
            // Re-read every `revocation::REVOCATION_POLL` to notice an
            // out-of-band host-key revocation while connected (the startup
            // check covers revocations from when no host was running).
            thread::sleep(REVOCATION_POLL);
            match Revocation::current() {
                Ok(rev) => {
                    let cur = WatchedEpochs::of(&rev);
                    if let Some(prev) = last {
                        if prev.host_key != cur.host_key
                            && rev.host_key_epoch > 0
                            && enrollment_key_is_gone()
                        {
                            push_revoked(&out);
                        }
                        if prev.kill != cur.kill {
                            push_kill_status(&out);
                            if !rev.killed {
                                if let Some(flag) = &unkill_observed {
                                    log_info!(
                                        "native-host",
                                        "kill switch released; handing the transition \
                                         to the control-plane loop"
                                    );
                                    flag.store(true, Ordering::Release);
                                }
                            }
                        }
                        // ADR-0032: an out-of-band policy or language change
                        // (a CLI/app edit, or a second browser's host) moves
                        // its epoch; push the fresh state on the same tick.
                        if prev.policy != cur.policy {
                            push_policy_current(&out);
                        }
                        if prev.lang != cur.lang {
                            push_lang_current(&out);
                        }
                    } else {
                        // Recovered from an unreadable record: re-run the
                        // startup posture. Every watched state (host-key
                        // revocation, kill, policy, language) was
                        // unobservable across the gap, so a change made
                        // during it would otherwise be silently absorbed
                        // into the rebuilt baseline and stay unannounced
                        // until the next connect.
                        if rev.host_key_epoch > 0 && enrollment_key_is_gone() {
                            push_revoked(&out);
                        }
                        push_kill_status(&out);
                        push_policy_current(&out);
                        push_lang_current(&out);
                    }
                    last = Some(cur);
                }
                Err(e) => {
                    // Log (and push the unknown state) on the transition to
                    // unreadable once, not every tick.
                    if last.is_some() {
                        log_warn!("native-host", "revocation record unreadable: {e}");
                        push_kill_status(&out);
                        last = None;
                    }
                }
            }
        }
    });
}

// ---- ADR-0031: per-action user-presence signing ------------------------------

/// Whether a presence-signing round is already in flight. One at a time by
/// design: the extension's confirmation service serializes its prompts, so a
/// second concurrent `presence_challenge` is a misbehaving (or malicious)
/// sender, and it is refused with `busy` rather than queued - stacking
/// hardware prompts is a tap-phishing primitive, not a feature.
static PRESENCE_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// RAII occupancy of the single presence-signing slot. The ONLY constructor is
/// [`try_acquire`](Self::try_acquire) (the flag's compare-exchange), and the
/// flag is cleared in `Drop`, so "guard exists" and "flag set" are one state:
/// a guard for a slot that was never won, or a path that clears the flag
/// without dropping the guard, is unrepresentable. Even if the worker thread
/// unwound (the no-panic-core lints forbid that in this crate, but a
/// dependency could still panic), the slot is released so the host never
/// wedges into a permanent `busy`.
struct PresenceSlotGuard {
    /// Constructor gate: keeps `PresenceSlotGuard { .. }` unbuildable outside
    /// [`try_acquire`](Self::try_acquire).
    _priv: (),
}

impl PresenceSlotGuard {
    /// Win the single in-flight slot, or `None` while another round holds it.
    fn try_acquire() -> Option<Self> {
        PRESENCE_IN_FLIGHT
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| PresenceSlotGuard { _priv: () })
    }
}

impl Drop for PresenceSlotGuard {
    fn drop(&mut self) {
        PRESENCE_IN_FLIGHT.store(false, Ordering::Release);
    }
}

/// Handle a `presence_challenge` (ADR-0031): sign the per-action presence statement with the Enclave key,
/// raising the Touch ID prompt. Unlike the enrollment challenge the signing runs on its OWN thread: presence
/// rounds happen in steady state, and holding the stdin->socket pump for a tap would head-of-line block every
/// other in-flight op. `Err` means the immediate promptless reply could not be written; worker-thread write
/// failures are only logged, and the pump notices stdout going away on its next frame.
///
/// ```text
/// kill switch engaged or unreadable  -> `bridge_killed`: no op can proceed anyway, and a killed bridge that
///                                       still raises Touch ID sheets would train the user to tap unexplained prompts
/// another round in flight            -> `busy` (see PRESENCE_IN_FLIGHT)
/// ```
fn handle_presence_challenge(
    nonce: String,
    context: Option<String>,
    out: &Arc<Mutex<BufWriter<io::Stdout>>>,
) -> io::Result<()> {
    let refuse = |out: &Mutex<BufWriter<io::Stdout>>, reason: &str| {
        write_control_reply(
            out,
            &EnclaveControl::PresenceError {
                reason: reason.into(),
            },
        )
    };
    if !matches!(crate::kill::is_killed(), Ok(false)) {
        log_warn!(
            "native-host",
            "refusing presence_challenge while the kill switch is engaged or unreadable"
        );
        return refuse(out, "bridge_killed");
    }
    let Some(slot) = PresenceSlotGuard::try_acquire() else {
        log_warn!(
            "native-host",
            "refusing presence_challenge while another round is in flight"
        );
        return refuse(out, "busy");
    };
    let worker_out = Arc::clone(out);
    let spawned = thread::Builder::new()
        .name("presence-sign".into())
        .spawn(move || {
            // Held for the whole round; Drop clears PRESENCE_IN_FLIGHT even on
            // an unexpected unwind, so a wedged `busy` is structurally
            // impossible.
            let _slot = slot;
            let reply = crate::enclave::respond_to_presence_challenge(&nonce, context.as_deref());
            // Log-after-decide (ADR-0030): the sign already happened (or
            // refused); record which, host-side, so a hardware approval is
            // never conflated with a window confirmation in the trail.
            let outcome = match &reply {
                EnclaveControl::PresenceProof { .. } => "ok",
                _ => "refused",
            };
            let mut rec = crate::audit::AuditRecord::new(crate::audit::AuditKind::PresenceSign)
                .surface(crate::audit::Surface::Host)
                .outcome(outcome);
            if let Some(ctx) = context.as_deref() {
                rec = rec.detail(ctx);
            }
            crate::audit::record(rec);
            if let Err(e) = write_control_reply(&worker_out, &reply) {
                log_warn!("native-host", "could not write the presence reply: {e}");
            }
        });
    if spawned.is_err() {
        // No thread, no prompt: refuse, fail closed. The guard moved into the
        // never-run closure, which `spawn` dropped on failure -- releasing
        // the slot through the same Drop path as every other exit.
        log_warn!("native-host", "could not spawn the presence-sign thread");
        return refuse(out, "signing_failed");
    }
    Ok(())
}

/// Handle one `legacy_settings` receipt (ADR-0032 decision 8): record the bag
/// as the pending import and audit what the receipt turned into. The audit
/// record (log-after-decide, written outside the runtime lock
/// `record_if_absent` takes and releases) is what keeps a dropped bag visible
/// to the user - the one import this host will ever offer must not vanish
/// into a stderr line. It carries the outcome and the bag's compact byte
/// count, NEVER the bag itself (the user's settings stay out of every log
/// and trail).
fn handle_legacy_settings(bag: Value) {
    let bag_bytes = serde_json::to_vec(&bag).map(|b| b.len()).unwrap_or(0);
    let outcome = match crate::pending_import::record_if_absent(bag) {
        Ok(crate::pending_import::RecordOutcome::Recorded) => {
            log_info!("native-host", "recorded the legacy settings pending import");
            "recorded"
        }
        Ok(crate::pending_import::RecordOutcome::AlreadyPresent) => {
            log_info!(
                "native-host",
                "legacy_settings received but a pending import already exists; dropped \
                 (first-bag-wins)"
            );
            "dropped_already_pending"
        }
        Ok(crate::pending_import::RecordOutcome::AlreadyConsumed) => {
            log_warn!(
                "native-host",
                "legacy_settings received after the import was consumed; dropped \
                 (the import window is closed)"
            );
            "dropped_consumed"
        }
        Ok(crate::pending_import::RecordOutcome::Oversize { bytes }) => {
            log_warn!(
                "native-host",
                "legacy_settings bag is {bytes} bytes, over the pending-import cap; dropped"
            );
            "dropped_oversize"
        }
        Err(e) => {
            log_warn!(
                "native-host",
                "legacy_settings could not be recorded ({e}); dropped"
            );
            "error"
        }
    };
    crate::audit::record(
        crate::audit::AuditRecord::new(crate::audit::AuditKind::LegacyImportReceipt)
            .surface(crate::audit::Surface::Host)
            .outcome(outcome)
            .detail(&format!("{bag_bytes} bytes")),
    );
}

/// What one inbound native-messaging frame turned into.
enum Inbound {
    /// A host-handled control frame: the reply (if any) has been written.
    Handled,
    /// Not a control frame: the caller decides (forward over the bridge in
    /// normal mode; drop in control-plane mode).
    Forward(Value),
}

/// Handle one frame from Chrome against the host-handled control surface
/// (ADR-0021/0025/0030/0031). Shared by the normal stdin->socket pump and the
/// control-plane-only loop, so the two modes cannot drift in what they answer.
/// An `Err` means a control REPLY could not be written (stdout gone), which
/// ends the calling loop.
fn handle_control_frame(
    frame: Value,
    out: &Arc<Mutex<BufWriter<io::Stdout>>>,
) -> io::Result<Inbound> {
    match classify_nm_frame(&frame) {
        FrameDisposition::Forward => Ok(Inbound::Forward(frame)),
        FrameDisposition::Challenge { nonce, context } => {
            log_info!("native-host", "answering enclave challenge locally");
            // Signing blocks this pump until the user answers the
            // presence prompt, so extension->server traffic is
            // head-of-line blocked for the duration (server->extension
            // still flows). Accepted: challenges only occur during the
            // user-present enrollment ceremony, not in steady state (the
            // steady-state presence rounds run on their own thread, see
            // handle_presence_challenge).
            let reply = crate::enclave::respond_to_challenge(&nonce, context.as_deref());
            write_control_reply(out, &reply)?;
            Ok(Inbound::Handled)
        }
        FrameDisposition::PresenceChallenge { nonce, context } => {
            log_info!("native-host", "answering presence challenge locally");
            handle_presence_challenge(nonce, context, out)?;
            Ok(Inbound::Handled)
        }
        FrameDisposition::RevokeHostKey => {
            write_control_reply(out, &revoke_host_key())?;
            Ok(Inbound::Handled)
        }
        FrameDisposition::ClientList => {
            write_control_reply(out, &admin_client_list())?;
            Ok(Inbound::Handled)
        }
        FrameDisposition::ClientRevoke { name } => {
            write_control_reply(out, &admin_client_revoke(&name))?;
            Ok(Inbound::Handled)
        }
        FrameDisposition::KillStatus => {
            write_control_reply(out, &kill_status_reply())?;
            Ok(Inbound::Handled)
        }
        FrameDisposition::KillEngage => {
            write_control_reply(out, &handle_kill_engage())?;
            Ok(Inbound::Handled)
        }
        FrameDisposition::KillRelease => {
            // ADR-0032 decision 6: extension release is retired; refuse it,
            // audited, rather than running the (now removed) extension floor.
            write_control_reply(out, &handle_kill_release_refused())?;
            Ok(Inbound::Handled)
        }
        FrameDisposition::PolicyGet => {
            write_control_reply(out, &policy_current_reply())?;
            Ok(Inbound::Handled)
        }
        FrameDisposition::LegacySettings { bag } => {
            // ADR-0032 decision 8: the snapshotted legacy bag is recorded as a
            // pending import (first-bag-wins), never applied. The frame
            // owes no reply; the write fails closed (an oversize or unwritable
            // receipt is logged and dropped, never crashes, never forwarded).
            handle_legacy_settings(bag);
            Ok(Inbound::Handled)
        }
        FrameDisposition::LangGet => {
            if let Some(reply) = lang_current_frame() {
                write_control_reply(out, &reply)?;
            }
            Ok(Inbound::Handled)
        }
        FrameDisposition::LangSet { value } => {
            if let Some(reply) = handle_lang_set(value) {
                write_control_reply(out, &reply)?;
            }
            Ok(Inbound::Handled)
        }
        FrameDisposition::MalformedPolicy(kind) => {
            log_warn!(
                "native-host",
                "malformed {} frame from browser",
                kind.wire_tag()
            );
            if let Some(reply) = malformed_policy_reply(kind) {
                write_control_reply(out, &reply)?;
            }
            Ok(Inbound::Handled)
        }
        FrameDisposition::MalformedLegacySettings { bytes } => {
            // The one receipt kind whose loss the user can never re-trigger:
            // a frame carrying the legacy_settings type that fails the parse
            // may be a version-skewed legitimate extension spending its ONE
            // migration send, so the drop is audited (size only - the
            // content did not parse and is never quoted), not just logged.
            log_warn!(
                "native-host",
                "malformed legacy_settings frame from browser; dropped"
            );
            crate::audit::record(
                crate::audit::AuditRecord::new(crate::audit::AuditKind::LegacyImportReceipt)
                    .surface(crate::audit::Surface::Host)
                    .outcome("dropped_malformed")
                    .detail(&format!("{bytes} bytes")),
            );
            Ok(Inbound::Handled)
        }
        FrameDisposition::AuditEvent(fields) => {
            // Fire-and-forget by contract: no reply frame.
            handle_audit_event(fields);
            Ok(Inbound::Handled)
        }
        FrameDisposition::DropForeignAuditKind { kind } => {
            // Refused at classification (the kind is host-owned); the
            // offending value is logged here for forensics, nothing recorded.
            log_warn!(
                "native-host",
                "dropping audit_event with a non-extension kind {kind:?}"
            );
            Ok(Inbound::Handled)
        }
        FrameDisposition::MalformedAdmin(kind) => {
            log_warn!(
                "native-host",
                "malformed {} frame from browser",
                kind.wire_tag()
            );
            write_control_reply(out, &malformed_admin_reply(kind))?;
            Ok(Inbound::Handled)
        }
        FrameDisposition::Drop(kind) => {
            log_warn!(
                "native-host",
                "dropping unexpected {kind} frame from browser"
            );
            Ok(Inbound::Handled)
        }
        FrameDisposition::Malformed => {
            log_warn!(
                "native-host",
                "malformed enclave control frame from browser"
            );
            let reply = EnclaveControl::EnclaveError {
                reason: "invalid_challenge".into(),
            };
            write_control_reply(out, &reply)?;
            Ok(Inbound::Handled)
        }
        FrameDisposition::MalformedPresence => {
            log_warn!(
                "native-host",
                "malformed presence control frame from browser"
            );
            let reply = EnclaveControl::PresenceError {
                reason: "invalid_challenge".into(),
            };
            write_control_reply(out, &reply)?;
            Ok(Inbound::Handled)
        }
    }
}

// ---- control-plane-only mode (ADR-0030) --------------------------------------

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

/// Control-plane-only mode (ADR-0030): the bridge is killed or its state is unreadable, so nothing may flow between
/// browser and broker, yet this host must stay up because the extension's SW-only kill mirror is fed by its pushes.
/// stdin is read on its own thread feeding a channel so the loop can interleave frames with the unkill flag
/// (see [`drain_then_decide`]).
/// ```text
/// control frame (kill_engage, kill_status, kill_release)  -> answered; kill_release is the audited refusal
/// bridge frame                                             -> dropped and logged; no socket is dialed
/// release (CLI unkill or the app) seen by the revocation watch -> queued frames drained, then exit if the kill is still
///                                                            released (the extension reconnects into a bridge host);
///                                                            a queued kill_engage or unreadable kill state stays here
/// ```
fn run_control_plane() -> i32 {
    let stdout_writer = Arc::new(Mutex::new(BufWriter::new(io::stdout())));
    // The watch raises this flag on an observed release; leaving this mode
    // is the LOOP's decision, after the drain (see drain_then_decide).
    let unkill_observed = Arc::new(AtomicBool::new(false));
    spawn_revocation_watch(
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
        match handle_control_frame(frame, &stdout_writer)? {
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

pub fn run() -> i32 {
    // Which browser this host fronts (`--label <name>`, baked into the
    // per-browser wrapper by the registration engine). It rides in the signed
    // handshake response so the MCP server can key its connection registry by
    // browser. A malformed label refuses to start: better no bridge than one
    // filed under a mangled identity.
    let argv: Vec<String> = std::env::args().collect();
    let label = match crate::cli::native_host_label(&argv) {
        Ok(l) => l,
        Err(e) => {
            log_error!("native-host", "{e}");
            return 1;
        }
    };

    // Capture our own executable identity before dialing, so attesting the
    // server compares against the genuine binary and we fail fast if we cannot
    // hash our own image. See ADR-0020.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if let Err(e) = ipc::ensure_own_identity() {
        log_error!(
            "native-host",
            "cannot establish own executable identity: {e}"
        );
        return 1;
    }

    // Self-heal a stranded mid-consume pending-import record: a Consuming record whose baseline landed but whose
    // finalize crashed has no other seam left to finish it (revision-2+ writes never revisit the store). Best-effort
    // and idempotent, so a failure must not stop the host: the worst partial outcome is a visible-but-unsynced
    // tombstone over an already-fsynced baseline, where roll-forward and roll-back are both correct states.
    //   runs BEFORE the kill fork below -> the control-plane-only mode heals too
    if let Err(e) = crate::pending_import::reconcile_consuming() {
        log_warn!(
            "native-host",
            "pending-import reconcile failed ({e}); a stranded mid-consume record, \
             if any, stays until the next host start or pending-import read"
        );
    }

    // ADR-0030: while the kill switch is engaged -- or its state cannot be
    // read -- this host bridges NOTHING. It does not even dial the broker
    // (which refuses browser attaches while killed); it drops into the
    // control-plane-only mode instead, which keeps the extension's unkill
    // surface reachable and its kill mirror fed.
    match crate::kill::is_killed() {
        Ok(false) => {}
        Ok(true) => {
            log_error!(
                "native-host",
                "kill switch is engaged; serving the control plane only (no bridge traffic)"
            );
            return run_control_plane();
        }
        Err(e) => {
            log_error!(
                "native-host",
                "kill state unreadable ({e}); failing closed to the control plane only"
            );
            return run_control_plane();
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
    // a hostile same-user process cannot impersonate the MCP server. See
    // ADR-0020.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        if let Err(e) = ipc::attest_peer(&stream) {
            log_error!("native-host", "server attestation failed: {e}");
            return 1;
        }
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

    // ADR-0025/0030: notify the extension when the enrollment key has been
    // revoked out-of-band, and keep its kill mirror fed (at startup and on
    // every observed transition). No unkill flag: in bridge mode an engaged
    // kill ends this process via the broker severing the socket.
    spawn_revocation_watch(Arc::clone(&stdout_writer), None);

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
            // Host-handled control frames (ADR-0021/0025/0030) are addressed
            // to THIS process and must never reach the socket; everything
            // else forwards.
            match handle_control_frame(frame, &ctrl_out) {
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
        // Forwarded frames share stdout with Thread A's enclave control replies,
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
