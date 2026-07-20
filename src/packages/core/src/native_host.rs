//! Native-host mode: the `--native-host` subprocess spawned by Chrome.
//!
//! It is intentionally dumb. Two threads:
//! - stdin -> socket: read native-messaging frames, forward each JSON value as
//!   an NDJSON line over the bridge socket.
//! - socket -> stdout: read NDJSON lines from the bridge socket, frame each as
//!   a native-messaging message on stdout.
//!
//! The exceptions to "forward everything" are the host-handled control frames:
//! the enrollment ceremony (ADR-0021) and the revocation/admin exchange
//! (ADR-0025). Frames whose `type` is one of those control tags are handled
//! HERE - an `enclave_challenge` is answered locally by signing with the
//! Secure Enclave key (raising the user-presence prompt), an `enclave_revoke`
//! deletes the enrollment key, and `client_list`/`client_revoke` manage the
//! trusted-client allowlist - and are never forwarded to the MCP server;
//! symmetrically, a control frame arriving FROM the server is an injection
//! and is dropped, never forwarded to the extension. Everything else forwards
//! byte-for-byte, so all real tool logic stays in the MCP server on the other
//! side of the socket. EOF on stdin (Chrome disconnected) is our shutdown
//! signal.
//!
//! One host-originated push exists (ADR-0025): when the enrollment key has
//! been revoked out-of-band (`chromium-bridge revoke`, `pair --reset`), the
//! host tells the extension with an `enclave_revoked` frame - at startup when
//! the key is already gone, and live when the revocation epoch's host-key
//! marker moves. It is host-originated on purpose: the socket->stdout pump
//! drops any server-injected control frame, so only this process can put that
//! frame in front of the extension.

use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::enclave::{EnrollmentKey, HostConfig};
use crate::ipc;
use crate::protocol::{
    bridge_read, bridge_write, classify_nm_frame, host_control_type, nm_read_frame, nm_write_frame,
    AdminControl, EnclaveControl, FrameDisposition,
};
use crate::revocation::{self, Revocation};
use serde::Serialize;
use serde_json::Value;

/// How often the host re-reads the revocation record to notice an out-of-band
/// host-key revocation while connected (the startup check covers revocations
/// that happened while no host was running).
const REVOCATION_POLL: Duration = Duration::from_secs(1);

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

/// Handle an `enclave_revoke` frame from the extension: delete the enrollment
/// key, clear the recorded policy, and bump the revocation epoch so every
/// other surface (a doctor run, a second browser's host) can observe the
/// change. Replies `enclave_revoked` when the requested end state holds (the
/// key is gone -- including when none existed), or a typed `enclave_error`.
fn revoke_host_key() -> EnclaveControl {
    match EnrollmentKey::revoke() {
        Ok(existed) => {
            HostConfig::remove();
            if let Err(e) = revocation::bump(revocation::Scope::HostKey) {
                // The key is gone (the authoritative act). This host still acks
                // enclave_revoked below, so the requesting extension clears its
                // own pin-pending regardless. What a failed bump loses is the
                // host_key_epoch signal OTHER surfaces watch: a second browser's
                // host will not push a proactive enclave_revoked, and those
                // extensions instead notice only at their next pinned-key
                // verification (an opt-in reverify, or the user's manual
                // "verify now"). Logged, not fatal.
                log_error!(
                    "native-host",
                    "enrollment key deleted but the revocation epoch bump failed ({e}); \
                     other surfaces will not get a proactive revoked push, only detection \
                     at their next key verification"
                );
            }
            log_info!(
                "native-host",
                "extension revoked the enrollment key (existed: {existed})"
            );
            // Log-after-decide (ADR-0030): the key deletion is complete.
            crate::audit::record(
                crate::audit::AuditRecord::new(crate::audit::AuditKind::HostKeyRevoke)
                    .surface(crate::audit::Surface::Extension)
                    .outcome("ok"),
            );
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
    let latched = match Revocation::current() {
        Ok(rev) => rev.clients_enrolled,
        Err(e) => {
            return AdminControl::ClientListResult {
                ok: false,
                enrolled: false,
                clients: Vec::new(),
                error: Some(format!("revocation record unreadable: {e}")),
            };
        }
    };
    match crate::allowlist::load_enforced(latched) {
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

/// The current kill state as a `kill_status_result` frame. `ok: false`
/// carries no `killed` claim at all: the extension must treat an unreadable
/// state as unknown and fail closed, and handing it a boolean would invite
/// trusting it.
fn kill_status_reply() -> AdminControl {
    match crate::kill::is_killed() {
        Ok(killed) => AdminControl::KillStatusResult {
            ok: true,
            killed: Some(killed),
            error: None,
        },
        Err(e) => AdminControl::KillStatusResult {
            ok: false,
            killed: None,
            error: Some(format!("kill state unreadable: {e}")),
        },
    }
}

/// Handle `kill_engage` / `kill_release` from the extension (ADR-0030). The
/// core API performs the latch flip + epoch bump in one critical section and
/// audits it with `surface: extension`. The reply reports the resulting
/// state, which the extension's SW-only mirror adopts.
///
/// Releasing runs the user-presence ladder first ([`crate::presence`]) with
/// the extension floor: this process cannot raise a text prompt of its own
/// (stdin and stdout are the native-messaging protocol), so where no Enclave
/// key exists the options page's explicit confirmation dialog IS the
/// interactive floor, attested by the channel that delivered the frame
/// (`allowed_origins` pins the extension; the #32 sender gate pins its
/// pages). On an enrolled Mac the same call raises a Secure Enclave Touch ID
/// prompt host-side, and a hardware refusal keeps the bridge killed
/// (`ok: false`, audited).
fn handle_kill_transition(engage: bool) -> AdminControl {
    let res = if engage {
        crate::kill::engage(crate::audit::Surface::Extension)
    } else {
        match crate::presence::require_presence(
            "Releasing the kill switch lets MCP clients drive your browser again.",
            crate::presence::Floor::ExtensionConfirm,
        ) {
            Ok(auth) => crate::kill::release(crate::audit::Surface::Extension, auth),
            Err(e) => {
                crate::kill::audit_refused_release(crate::audit::Surface::Extension, &e);
                log_warn!(
                    "native-host",
                    "extension-requested release refused at the presence gate: {e}"
                );
                return AdminControl::KillStatusResult {
                    ok: false,
                    killed: None,
                    error: Some(format!("release refused: {e}")),
                };
            }
        }
    };
    match res {
        Ok(epoch) => {
            log_info!(
                "native-host",
                "extension {} the kill switch (epoch {epoch})",
                if engage { "ENGAGED" } else { "released" }
            );
            AdminControl::KillStatusResult {
                ok: true,
                killed: Some(engage),
                error: None,
            }
        }
        Err(e) => {
            log_warn!(
                "native-host",
                "extension-requested kill transition failed: {e}"
            );
            AdminControl::KillStatusResult {
                ok: false,
                killed: None,
                error: Some(e.to_string()),
            }
        }
    }
}

/// Record one extension-side decision in the audit trail (ADR-0030). Only the
/// extension-owned kinds are accepted ([`crate::audit::extension_kind`]) and
/// the surface is stamped HERE, so the browser leg cannot forge host-side
/// events (an admission, a kill) into the trail. Fire-and-forget: no reply.
fn handle_audit_event(
    kind: String,
    outcome: Option<String>,
    tool: Option<String>,
    name: Option<String>,
    detail: Option<String>,
    cid: Option<String>,
) {
    let Some(kind) = crate::audit::extension_kind(&kind) else {
        log_warn!(
            "native-host",
            "dropping audit_event with a non-extension kind {kind:?}"
        );
        return;
    };
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
/// timing out.
fn malformed_admin_reply(kind: &'static str) -> AdminControl {
    match kind {
        "client_list" => AdminControl::ClientListResult {
            ok: false,
            enrolled: false,
            clients: Vec::new(),
            error: Some("malformed client_list frame".into()),
        },
        "kill_status" | "kill_engage" | "kill_release" => AdminControl::KillStatusResult {
            ok: false,
            killed: None,
            error: Some(format!("malformed {kind} frame")),
        },
        _ => AdminControl::ClientRevokeResult {
            ok: false,
            error: Some(format!("malformed {kind} frame")),
        },
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

/// Push the current kill state to the extension as an unsolicited
/// `kill_status_result` (ADR-0030). Sent when the watch observes a transition,
/// and at startup only when the news is bad (killed, or unreadable): a
/// healthy startup pushes nothing, because the extension itself queries
/// `kill_status` on every port connect (which is what clears a stale killed
/// mirror after a CLI unkill), and an unconditional push would put an
/// unexpected frame in front of every fresh connection. Best-effort: a failed
/// write only delays the mirror to the extension's own query.
fn push_kill_status(out: &Mutex<BufWriter<io::Stdout>>) {
    if let Err(e) = write_control_reply(out, &kill_status_reply()) {
        log_warn!("native-host", "could not push kill_status_result: {e}");
    }
}

/// Watch the revocation record while this host runs, and notify the extension
/// of out-of-band transitions:
///
/// - **host-key revocations** (`chromium-bridge revoke`, `pair --reset`),
///   pushed as `enclave_revoked` - both triggers require a RECORDED revocation
///   (`host_key_epoch > 0`) AND a keychain-confirmed absent key before any
///   frame is sent (see ADR-0025; the keychain check keeps a scribbled-on
///   revocation file from faking one);
/// - **kill-switch transitions** (ADR-0030), pushed as `kill_status_result`
///   whenever `kill_epoch` moves - plus once at startup when the state is
///   already killed or unreadable - so the extension's SW-only mirror tracks
///   CLI-driven kills without polling (the alive direction is pulled by the
///   extension's own on-connect query).
///
/// With `unkill_observed` (the control-plane mode of a killed bridge), an
/// observed release is pushed and then HANDED to the control-plane loop via
/// the flag instead of exiting the process from this thread: exiting here
/// would drop whatever control frames are still buffered on stdin with the
/// process - including a `kill_engage` the extension was already told was
/// sent - so the loop drains those and re-checks the state before deciding
/// to leave killed mode (see [`drain_then_decide`]). The released state is
/// pushed BEFORE the flag is raised, so the mirror is not left engaged
/// across the respawn gap.
///
/// An unreadable record is pushed once (as `ok: false`, which the extension
/// treats as unknown and fails closed on) and logged once, not every tick.
fn spawn_revocation_watch(
    out: Arc<Mutex<BufWriter<io::Stdout>>>,
    unkill_observed: Option<Arc<AtomicBool>>,
) {
    thread::spawn(move || {
        // Startup posture: bad news is announced now (a key revoked or a kill
        // engaged while no host was running); a healthy state stays quiet.
        let mut last: Option<(u64, u64)> = match Revocation::current() {
            Ok(rev) => {
                if rev.host_key_epoch > 0 && enrollment_key_is_gone() {
                    push_revoked(&out);
                }
                if rev.killed {
                    push_kill_status(&out);
                }
                Some((rev.host_key_epoch, rev.kill_epoch))
            }
            Err(e) => {
                log_warn!("native-host", "revocation record unreadable: {e}");
                push_kill_status(&out); // pushes ok:false (unknown, fail closed)
                None
            }
        };
        loop {
            thread::sleep(REVOCATION_POLL);
            match Revocation::current() {
                Ok(rev) => {
                    let cur = (rev.host_key_epoch, rev.kill_epoch);
                    if let Some((last_host_key, last_kill)) = last {
                        if last_host_key != rev.host_key_epoch
                            && rev.host_key_epoch > 0
                            && enrollment_key_is_gone()
                        {
                            push_revoked(&out);
                        }
                        if last_kill != rev.kill_epoch {
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
                    } else {
                        // Recovered from an unreadable record: re-announce.
                        push_kill_status(&out);
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

/// RAII reset for [`PRESENCE_IN_FLIGHT`]: clearing the flag in `Drop` makes the
/// single-flight invariant structural. Even if the worker thread unwound
/// (the no-panic-core lints forbid that in this crate, but a dependency could
/// still abort/panic), the slot is released so the host never wedges into a
/// permanent `busy`. The success path drops it after the reply is written; the
/// spawn-failure path drops it explicitly.
struct PresenceSlotGuard;

impl Drop for PresenceSlotGuard {
    fn drop(&mut self) {
        PRESENCE_IN_FLIGHT.store(false, Ordering::Release);
    }
}

/// Handle a `presence_challenge` frame (ADR-0031): sign the per-action
/// presence statement with the Enclave key, raising the Touch ID prompt.
///
/// Two promptless refusals come first, fail closed:
/// - while the kill switch is engaged (or unreadable) nothing may prompt -
///   no op can proceed anyway, and a killed bridge that still raises Touch ID
///   sheets would train the user to tap unexplained prompts;
/// - while another round is in flight (`busy`, above).
///
/// The signing itself runs on its OWN thread, unlike the enrollment
/// challenge: enrollment blocks the pump only during the user-present
/// ceremony, but presence rounds happen in steady state, and holding the
/// stdin->socket pump for the duration of a tap would head-of-line block
/// every other in-flight op's traffic behind the prompt. The reply is
/// written through the shared stdout mutex, so frames stay whole. An `Err`
/// from this function means the immediate (promptless) reply could not be
/// written; worker-thread write failures are logged, and the pump notices
/// stdout going away on its next frame.
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
    if PRESENCE_IN_FLIGHT
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        log_warn!(
            "native-host",
            "refusing presence_challenge while another round is in flight"
        );
        return refuse(out, "busy");
    }
    let worker_out = Arc::clone(out);
    let spawned = thread::Builder::new()
        .name("presence-sign".into())
        .spawn(move || {
            // Held for the whole round; Drop clears PRESENCE_IN_FLIGHT even on
            // an unexpected unwind, so a wedged `busy` is structurally
            // impossible.
            let _slot = PresenceSlotGuard;
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
        // No thread, no prompt: release the slot and refuse, fail closed. The
        // guard lives only inside the worker, so on a spawn failure the flag
        // is cleared here.
        PRESENCE_IN_FLIGHT.store(false, Ordering::Release);
        log_warn!("native-host", "could not spawn the presence-sign thread");
        return refuse(out, "signing_failed");
    }
    Ok(())
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
            write_control_reply(out, &handle_kill_transition(true))?;
            Ok(Inbound::Handled)
        }
        FrameDisposition::KillRelease => {
            write_control_reply(out, &handle_kill_transition(false))?;
            Ok(Inbound::Handled)
        }
        FrameDisposition::AuditEvent {
            kind,
            outcome,
            tool,
            name,
            detail,
            cid,
        } => {
            // Fire-and-forget by contract: no reply frame.
            handle_audit_event(kind, outcome, tool, name, detail, cid);
            Ok(Inbound::Handled)
        }
        FrameDisposition::MalformedAdmin(kind) => {
            log_warn!("native-host", "malformed {kind} frame from browser");
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

/// The unkill transition, taken only by the control-plane loop: before
/// leaving killed mode, DRAIN the control frames already buffered on stdin,
/// then re-read the kill state and exit only on an authoritative alive.
///
/// This is what keeps an acknowledged engage from being lost across the
/// transition: the extension's panic path is told ok:true the moment the
/// `kill_engage` frame is accepted for the pipe, so a frame that raced an
/// in-flight release may still be sitting in our stdin when the watch
/// observes the released state. Draining hands it to the normal control
/// handler (re-engaging the switch and answering the extension), and the
/// re-check then keeps this host in control-plane mode. An unreadable state
/// after the drain also stays: leaving killed mode on ambiguity would fail
/// open. The settle window is a best-effort fast path, not the guarantee: a
/// frame Chrome accepts but which reaches our stdin only after the window
/// elapses dies with the process, and what makes that loss non-silent is
/// the EXTENSION side - its panic latch stays engaged (no refusing frame
/// ever arrived) and it re-posts the unconfirmed engage on the reconnect
/// into the fresh host (at-least-once; the engage is idempotent here).
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

/// Control-plane-only mode (ADR-0030): the bridge is killed (or its state is
/// unreadable), so NOTHING may flow between the browser and a broker -- but
/// this host must stay up, because the extension's unkill rides a control
/// frame through this very process, and the SW-only kill mirror is fed by
/// this host's pushes. So: no socket, no forwarding; host-handled control
/// frames (kill status/engage/release, enclave ceremony, client admin, audit
/// events) keep working; a bridge frame that arrives anyway is dropped and
/// logged. When the watch observes the switch released, the LOOP (never the
/// watch thread) drains any control frames already buffered on stdin and
/// re-checks the state before exiting so the extension's reconnect spawns a
/// normal bridge-mode host -- an exit that raced a buffered, extension-
/// acknowledged `kill_engage` would silently drop the brake.
///
/// stdin is read on a dedicated thread feeding a channel, so the loop can
/// interleave frame handling with the unkill flag without blocking forever
/// in a read.
fn run_control_plane() -> i32 {
    let stdout_writer = Arc::new(Mutex::new(BufWriter::new(io::stdout())));
    // The watch raises this flag on an observed release; leaving this mode
    // is the LOOP's decision, after the drain (see drain_then_decide).
    let unkill_observed = Arc::new(AtomicBool::new(false));
    spawn_revocation_watch(
        Arc::clone(&stdout_writer),
        Some(Arc::clone(&unkill_observed)),
    );
    // Bounded on purpose: the old synchronous loop applied backpressure by
    // construction (a frame was read only when the previous one was fully
    // handled), and an unbounded queue would let a faulty or hostile
    // extension stack multi-megabyte frames in memory while the loop is
    // blocked on a presence prompt. A full channel simply parks the reader
    // thread, which parks Chrome's pipe - exactly the old behavior. Bound 1,
    // not more: native-messaging frames can reach tens of MB each, so the
    // peak held is about three frames (one being handled by the loop, one
    // queued, one parsed in the reader blocked on send) - enough for the
    // reader to stay a frame ahead during the unkill drain, and nothing
    // like a buffer.
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
        label.as_deref().unwrap_or("default")
    );

    // Shutdown policy: the native host has no useful work to do if EITHER
    // direction of the bridge breaks. When Chrome closes the port (stdin EOF)
    // we must exit; when the MCP server drops our connection (e.g. a new
    // server instance supplanted the old one) we ALSO must exit promptly, so
    // that Chrome observes the port closing and the extension reconnects
    // against the freshly-written lock file.
    //
    // Earlier code tried to coordinate the two threads with a channel and
    // joined both handles. That deadlocks when the socket side dies: the stdin
    // thread is blocked inside nm_read_frame waiting for a frame that Chrome
    // (still alive) will never send, so the join never returns. The process
    // lingers as a zombie holding an open stdin/stdout pair, which means the
    // extension's onDisconnect never fires and it never reconnects - the
    // MCP server's tool calls then report "extension not connected".
    //
    // Fix: let whichever thread finishes first terminate the whole process.
    // process::exit runs no destructors, but our writers flush after every
    // frame, so no buffered data is lost on the normal close paths.

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

/// Pump NDJSON lines from the bridge socket to stdout as native-messaging
/// frames. Reads through [`bridge_read`], so every line is bounded by
/// `BRIDGE_MAX_LINE`: the server passed attestation, but zero trust means even
/// an attested peer must not be able to exhaust memory with one newline-less
/// line. Any read error - an over-cap line included - fails closed: the pump
/// ends, the process exits, and Chrome tears the port down.
///
/// Enclave and admin control frames (ADR-0021/0025) are filtered out here:
/// they legitimately originate only in the extension and in this host itself,
/// never in the server, so one arriving on the socket leg is an injection
/// attempt - e.g. a spurious `enclave_error` to burn the extension's
/// outstanding nonce, an `enclave_revoked` to provoke a false "compromised"
/// mark, or a forged `client_list_result`. Dropped and logged, and the pump
/// keeps going: unlike a malformed line this is a recognized, bounded frame,
/// so discarding it fully contains the harm without taking the bridge down.
///
/// `out` is the stdout writer shared with the stdin->socket thread (which
/// writes enclave control replies). The lock is taken per frame, never across
/// the blocking `bridge_read`, so a control reply can be interleaved while this
/// pump is waiting on the socket.
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
mod tests {
    use super::*;
    use crate::protocol::BRIDGE_MAX_LINE;
    use std::io::Cursor;

    #[test]
    fn over_cap_line_on_receive_leg_is_rejected() {
        // One line just past the cap, followed by a perfectly valid frame: the
        // pump must fail closed at the over-cap line (stop, emit nothing, not
        // even the later valid frame). The old `reader.lines()` pump buffered
        // the giant line unbounded (the OOM path), skipped it as malformed,
        // and would have emitted the trailing frame - so this pins both the
        // cap and the fail-closed stop.
        let mut input = Vec::with_capacity(BRIDGE_MAX_LINE + 32);
        input.resize(BRIDGE_MAX_LINE + 1, b'x');
        input.extend_from_slice(b"\n{\"after\":true}\n");
        let out = Mutex::new(Vec::new());
        pump_socket_to_stdout(&mut Cursor::new(input), &out);
        assert!(out.into_inner().unwrap().is_empty());
    }

    #[test]
    fn valid_lines_are_framed_until_the_over_cap_line() {
        // A legal frame, then an over-cap line, then another legal frame: the
        // first goes out as native messaging, and the pump stops at the
        // poisoned line - the frame after it must never be emitted.
        let mut input = b"{\"ok\":true}\n".to_vec();
        input.resize(input.len() + BRIDGE_MAX_LINE + 1, b'x');
        input.extend_from_slice(b"\n{\"after\":true}\n");
        let out = Mutex::new(Vec::new());
        pump_socket_to_stdout(&mut Cursor::new(input), &out);

        let mut cur = Cursor::new(out.into_inner().unwrap());
        let frame = nm_read_frame(&mut cur).unwrap().unwrap();
        assert_eq!(frame, serde_json::json!({ "ok": true }));
        // Nothing after the first frame: the over-cap line was rejected.
        assert!(nm_read_frame(&mut cur).unwrap().is_none());
    }

    #[test]
    fn malformed_json_fails_closed() {
        // Malformed JSON used to be skip-and-continue; it now ends the pump
        // (fail closed against an attested-but-hostile peer), so the valid
        // frame after it must not be emitted.
        let out = Mutex::new(Vec::new());
        pump_socket_to_stdout(&mut Cursor::new(b"not-json\n{\"id\":2}\n".to_vec()), &out);
        assert!(out.into_inner().unwrap().is_empty());
    }

    #[test]
    fn blank_lines_are_skipped_and_eof_ends_the_pump() {
        let out = Mutex::new(Vec::new());
        pump_socket_to_stdout(&mut Cursor::new(b"\n\n{\"id\":1}\n".to_vec()), &out);
        let mut cur = Cursor::new(out.into_inner().unwrap());
        let frame = nm_read_frame(&mut cur).unwrap().unwrap();
        assert_eq!(frame, serde_json::json!({ "id": 1 }));
        assert!(nm_read_frame(&mut cur).unwrap().is_none());
    }

    #[test]
    fn server_injected_control_frames_are_dropped_not_forwarded() {
        // The server leg never legitimately carries host-handled control
        // frames (the ceremony and the admin exchange run extension <-> host
        // only), so injected frames - the nonce-burning enclave_error, the
        // false-compromise enclave_revoked, a forged client_list_result - must
        // be dropped while the pump keeps forwarding real traffic around them.
        let input = concat!(
            "{\"type\":\"enclave_error\",\"reason\":\"key_invalid\"}\n",
            "{\"type\":\"enclave_challenge\",\"nonce\":\"n\"}\n",
            "{\"type\":\"enclave_proof\",\"sig\":\"s\",\"key_id\":\"k\",\"pubkey\":\"p\"}\n",
            "{\"type\":\"enclave_revoke\"}\n",
            "{\"type\":\"enclave_revoked\"}\n",
            "{\"type\":\"presence_challenge\",\"nonce\":\"n\"}\n",
            "{\"type\":\"presence_proof\",\"sig\":\"s\",\"key_id\":\"k\",\"pubkey\":\"p\"}\n",
            "{\"type\":\"presence_error\",\"reason\":\"busy\"}\n",
            "{\"type\":\"client_list\"}\n",
            "{\"type\":\"client_list_result\",\"ok\":true,\"enrolled\":true,\"clients\":[]}\n",
            "{\"type\":\"client_revoke\",\"name\":\"codex\"}\n",
            "{\"type\":\"client_revoke_result\",\"ok\":true}\n",
            "{\"type\":\"kill_status\"}\n",
            "{\"type\":\"kill_engage\"}\n",
            "{\"type\":\"kill_release\"}\n",
            "{\"type\":\"kill_status_result\",\"ok\":true,\"killed\":false}\n",
            "{\"type\":\"audit_event\",\"kind\":\"confirm_allowed\"}\n",
            "{\"id\":7,\"op\":\"tab_list\"}\n",
        );
        let out = Mutex::new(Vec::new());
        pump_socket_to_stdout(&mut Cursor::new(input.as_bytes().to_vec()), &out);

        let mut cur = Cursor::new(out.into_inner().unwrap());
        let frame = nm_read_frame(&mut cur).unwrap().unwrap();
        assert_eq!(frame, serde_json::json!({ "id": 7, "op": "tab_list" }));
        assert!(nm_read_frame(&mut cur).unwrap().is_none());
    }

    #[test]
    fn malformed_admin_frames_get_a_matching_ok_false_reply() {
        // The reply frame type must match the request so the extension's
        // pending request resolves instead of timing out.
        match malformed_admin_reply("client_list") {
            AdminControl::ClientListResult {
                ok: false,
                error: Some(_),
                ..
            } => {}
            other => panic!("expected a failed client_list_result, got {other:?}"),
        }
        match malformed_admin_reply("client_revoke") {
            AdminControl::ClientRevokeResult {
                ok: false,
                error: Some(_),
            } => {}
            other => panic!("expected a failed client_revoke_result, got {other:?}"),
        }
        // The kill frames all resolve to a kill_status_result whose ok:false
        // carries NO killed claim (unknown fails closed on the extension side).
        for kind in ["kill_status", "kill_engage", "kill_release"] {
            match malformed_admin_reply(kind) {
                AdminControl::KillStatusResult {
                    ok: false,
                    killed: None,
                    error: Some(_),
                } => {}
                other => panic!("expected a failed kill_status_result for {kind}, got {other:?}"),
            }
        }
    }

    #[test]
    fn kill_status_reply_never_claims_a_state_it_cannot_read() {
        // On a machine whose revocation record is absent (the unit-test
        // environment), the reply is ok with an explicit killed flag; the
        // ok:false shape is pinned by the malformed test above and the
        // adversarial suite (corrupt record).
        match kill_status_reply() {
            AdminControl::KillStatusResult {
                ok: true,
                killed: Some(_),
                error: None,
            } => {}
            AdminControl::KillStatusResult {
                ok: false,
                killed: None,
                error: Some(_),
            } => {}
            other => {
                panic!("kill_status_result must never pair ok:false with a killed claim: {other:?}")
            }
        }
    }

    #[test]
    fn audit_events_with_host_side_kinds_are_dropped() {
        // handle_audit_event must refuse to stamp host-side kinds from the
        // browser leg. Success here is the absence of a panic plus the
        // whitelist test in audit.rs; this exercises the wiring.
        handle_audit_event("kill_engage".into(), None, None, None, None, None);
        handle_audit_event("harness_admit".into(), None, None, None, None, None);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn revoke_on_an_unsupported_platform_reports_the_stable_reason() {
        // Non-macOS: EnrollmentKey::revoke fails closed with Unsupported and
        // the reply carries the stable reason code, never a panic.
        match revoke_host_key() {
            EnclaveControl::EnclaveError { reason } => {
                assert_eq!(reason, "unsupported_platform");
            }
            other => panic!("expected enclave_error, got {other:?}"),
        }
    }

    // ---- ADR-0030: the control-plane unkill drain -----------------------------

    #[test]
    fn a_buffered_engage_across_unkill_is_drained_and_keeps_the_host_killed() {
        // The gap this pins: the extension is told ok:true for a kill_engage
        // the moment the frame is accepted for the pipe, so one can still be
        // buffered on stdin when the watch observes an in-flight release
        // landing. Exiting at that point (the old watch-thread process::exit)
        // dropped the acknowledged brake on the floor. The drain must hand
        // the frame to the control handler FIRST, and the re-engaged state it
        // produces must keep the host in control-plane mode.
        let (tx, rx) = mpsc::channel();
        tx.send(PlaneEvent::Frame(
            serde_json::json!({"type": "kill_engage"}),
        ))
        .unwrap();
        let _keep_stdin_open = tx;
        let killed = std::cell::Cell::new(false);
        let mut handled = Vec::new();
        let mut handle = |frame: Value| {
            killed.set(true); // the engage applies to the record
            handled.push(frame);
            Ok(())
        };
        let decision = drain_then_decide(&rx, &mut handle, &|| Ok(killed.get()));
        assert!(matches!(decision, UnkillDecision::Stay));
        assert_eq!(handled, vec![serde_json::json!({"type": "kill_engage"})]);
    }

    #[test]
    fn a_quiet_pipe_with_an_alive_state_exits_for_the_bridge_mode_respawn() {
        let (tx, rx) = mpsc::channel::<PlaneEvent>();
        let _keep_stdin_open = tx;
        let decision = drain_then_decide(&rx, &mut |_| Ok(()), &|| Ok(false));
        assert!(matches!(
            decision,
            UnkillDecision::Exit(PlaneExit::Unkilled)
        ));
    }

    #[test]
    fn an_unreadable_state_after_the_drain_stays_in_control_plane_mode() {
        // Leaving killed mode on an unreadable record would fail open: the
        // fresh host would dial the broker before anyone re-proved "alive".
        let (tx, rx) = mpsc::channel::<PlaneEvent>();
        let _keep_stdin_open = tx;
        let decision = drain_then_decide(&rx, &mut |_| Ok(()), &|| {
            Err(io::Error::other("corrupt record"))
        });
        assert!(matches!(decision, UnkillDecision::Stay));
    }

    #[test]
    fn eof_during_the_drain_ends_the_host() {
        let (tx, rx) = mpsc::channel();
        tx.send(PlaneEvent::Eof).unwrap();
        let decision = drain_then_decide(&rx, &mut |_| Ok(()), &|| Ok(false));
        assert!(matches!(
            decision,
            UnkillDecision::Exit(PlaneExit::StdinClosed)
        ));
    }

    #[test]
    fn the_loop_handles_buffered_frames_before_exiting_on_unkill() {
        // Loop-level wiring: with the watch's flag already raised and a frame
        // buffered, the loop must run the drain (handling the frame) before
        // its exit decision - never exit with the frame unread.
        let (tx, rx) = mpsc::channel();
        tx.send(PlaneEvent::Frame(
            serde_json::json!({"type": "kill_status"}),
        ))
        .unwrap();
        let _keep_stdin_open = tx;
        let flag = AtomicBool::new(true);
        let mut handled = Vec::new();
        let exit = control_plane_loop(
            &rx,
            &flag,
            &mut |frame| {
                handled.push(frame);
                Ok(())
            },
            &|| Ok(false),
        );
        assert_eq!(exit, PlaneExit::Unkilled);
        assert_eq!(handled, vec![serde_json::json!({"type": "kill_status"})]);
    }
}
