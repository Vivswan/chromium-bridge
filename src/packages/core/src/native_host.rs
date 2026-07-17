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
//! HERE — an `enclave_challenge` is answered locally by signing with the
//! Secure Enclave key (raising the user-presence prompt), an `enclave_revoke`
//! deletes the enrollment key, and `client_list`/`client_revoke` manage the
//! trusted-client allowlist — and are never forwarded to the MCP server;
//! symmetrically, a control frame arriving FROM the server is an injection
//! and is dropped, never forwarded to the extension. Everything else forwards
//! byte-for-byte, so all real tool logic stays in the MCP server on the other
//! side of the socket. EOF on stdin (Chrome disconnected) is our shutdown
//! signal.
//!
//! One host-originated push exists (ADR-0025): when the enrollment key has
//! been revoked out-of-band (`chromium-bridge revoke`, `pair --reset`), the
//! host tells the extension with an `enclave_revoked` frame — at startup when
//! the key is already gone, and live when the revocation epoch's host-key
//! marker moves. It is host-originated on purpose: the socket->stdout pump
//! drops any server-injected control frame, so only this process can put that
//! frame in front of the extension.

use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::sync::{Arc, Mutex};
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
    match crate::allowlist::Allowlist::revoke(name) {
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

/// The reply for a malformed admin request frame: the matching result frame
/// with `ok: false`, so the extension's pending request resolves instead of
/// timing out.
fn malformed_admin_reply(kind: &'static str) -> AdminControl {
    if kind == "client_list" {
        AdminControl::ClientListResult {
            ok: false,
            enrolled: false,
            clients: Vec::new(),
            error: Some("malformed client_list frame".into()),
        }
    } else {
        AdminControl::ClientRevokeResult {
            ok: false,
            error: Some(format!("malformed {kind} frame")),
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

/// Watch for an out-of-band host-key revocation (`chromium-bridge revoke`,
/// `pair --reset`) while this host is connected, and notify the extension.
/// Two triggers, both requiring a RECORDED revocation (`host_key_epoch > 0`)
/// AND a keychain-confirmed absent key before any frame is sent:
/// - at startup, covering a revocation that happened while no host was
///   running (MV3 kills the host with the service worker; the pinned state
///   survives in the extension's durable storage, so the push on the next
///   spawn is what flips it without waiting for an opt-in reverify);
/// - while running, a change of the record's host-key marker triggers a
///   fresh keychain check.
///
/// Requiring the recorded marker keeps a never-enrolled machine quiet (no
/// push on every spawn) and keeps the trigger tied to a revocation act; the
/// keychain check keeps a scribbled-on revocation file from faking one. A key
/// deleted directly out of the keychain with no record leaves no push -- the
/// pinned extension catches that at its next verification, and the deletion
/// only ever reduced capability.
fn spawn_host_key_revocation_watch(out: Arc<Mutex<BufWriter<io::Stdout>>>) {
    thread::spawn(move || {
        let mut last = match Revocation::current() {
            Ok(rev) => {
                if rev.host_key_epoch > 0 && enrollment_key_is_gone() {
                    push_revoked(&out);
                }
                Some(rev.host_key_epoch)
            }
            Err(e) => {
                log_warn!("native-host", "revocation record unreadable: {e}");
                None
            }
        };
        loop {
            thread::sleep(REVOCATION_POLL);
            match Revocation::current() {
                Ok(rev) => {
                    if last != Some(rev.host_key_epoch) {
                        last = Some(rev.host_key_epoch);
                        if rev.host_key_epoch > 0 && enrollment_key_is_gone() {
                            push_revoked(&out);
                        }
                    }
                }
                Err(e) => {
                    // Log the transition to unreadable once, not every tick.
                    if last.is_some() {
                        log_warn!("native-host", "revocation record unreadable: {e}");
                        last = None;
                    }
                }
            }
        }
    });
}

pub fn run() -> i32 {
    // Which browser this host fronts (`--label <name>`, written into the
    // per-browser wrapper by the installer). It rides in the signed handshake
    // response so the MCP server can key its connection registry by browser.
    // A malformed label refuses to start: better no bridge than one filed
    // under a mangled identity.
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
    // extension's onDisconnect never fires and it never reconnects — the
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

    // ADR-0025: notify the extension when the enrollment key has been revoked
    // out-of-band (at startup if it is already gone; live on an epoch bump).
    spawn_host_key_revocation_watch(Arc::clone(&stdout_writer));

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
            // Host-handled control frames (ADR-0021/0025) are addressed to
            // THIS process and must never reach the socket; everything else
            // forwards.
            match classify_nm_frame(&frame) {
                FrameDisposition::Forward => {}
                FrameDisposition::Challenge { nonce, context } => {
                    log_info!("native-host", "answering enclave challenge locally");
                    // Signing blocks this pump until the user answers the
                    // presence prompt, so extension->server traffic is
                    // head-of-line blocked for the duration (server->extension
                    // still flows). Accepted: challenges only occur during the
                    // user-present enrollment ceremony, not in steady state.
                    let reply = crate::enclave::respond_to_challenge(&nonce, context.as_deref());
                    if let Err(e) = write_control_reply(&ctrl_out, &reply) {
                        log_warn!("native-host", "control reply write error: {e}");
                        break;
                    }
                    continue;
                }
                FrameDisposition::RevokeHostKey => {
                    let reply = revoke_host_key();
                    if let Err(e) = write_control_reply(&ctrl_out, &reply) {
                        log_warn!("native-host", "control reply write error: {e}");
                        break;
                    }
                    continue;
                }
                FrameDisposition::ClientList => {
                    let reply = admin_client_list();
                    if let Err(e) = write_control_reply(&ctrl_out, &reply) {
                        log_warn!("native-host", "control reply write error: {e}");
                        break;
                    }
                    continue;
                }
                FrameDisposition::ClientRevoke { name } => {
                    let reply = admin_client_revoke(&name);
                    if let Err(e) = write_control_reply(&ctrl_out, &reply) {
                        log_warn!("native-host", "control reply write error: {e}");
                        break;
                    }
                    continue;
                }
                FrameDisposition::MalformedAdmin(kind) => {
                    log_warn!("native-host", "malformed {kind} frame from browser");
                    let reply = malformed_admin_reply(kind);
                    if let Err(e) = write_control_reply(&ctrl_out, &reply) {
                        log_warn!("native-host", "control reply write error: {e}");
                        break;
                    }
                    continue;
                }
                FrameDisposition::Drop(kind) => {
                    log_warn!(
                        "native-host",
                        "dropping unexpected {kind} frame from browser"
                    );
                    continue;
                }
                FrameDisposition::Malformed => {
                    log_warn!(
                        "native-host",
                        "malformed enclave control frame from browser"
                    );
                    let reply = EnclaveControl::EnclaveError {
                        reason: "invalid_challenge".into(),
                    };
                    if let Err(e) = write_control_reply(&ctrl_out, &reply) {
                        log_warn!("native-host", "control reply write error: {e}");
                        break;
                    }
                    continue;
                }
            }
            if let Err(e) = bridge_write(&mut sock, &frame) {
                log_warn!("native-host", "bridge write error: {e}");
                break;
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
        // blocking socket read) — otherwise a challenge reply could not be
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
/// line. Any read error — an over-cap line included — fails closed: the pump
/// ends, the process exits, and Chrome tears the port down.
///
/// Enclave and admin control frames (ADR-0021/0025) are filtered out here:
/// they legitimately originate only in the extension and in this host itself,
/// never in the server, so one arriving on the socket leg is an injection
/// attempt — e.g. a spurious `enclave_error` to burn the extension's
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
        // and would have emitted the trailing frame — so this pins both the
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
        // poisoned line — the frame after it must never be emitted.
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
        // only), so injected frames — the nonce-burning enclave_error, the
        // false-compromise enclave_revoked, a forged client_list_result — must
        // be dropped while the pump keeps forwarding real traffic around them.
        let input = concat!(
            "{\"type\":\"enclave_error\",\"reason\":\"key_invalid\"}\n",
            "{\"type\":\"enclave_challenge\",\"nonce\":\"n\"}\n",
            "{\"type\":\"enclave_proof\",\"sig\":\"s\",\"key_id\":\"k\",\"pubkey\":\"p\"}\n",
            "{\"type\":\"enclave_revoke\"}\n",
            "{\"type\":\"enclave_revoked\"}\n",
            "{\"type\":\"client_list\"}\n",
            "{\"type\":\"client_list_result\",\"ok\":true,\"enrolled\":true,\"clients\":[]}\n",
            "{\"type\":\"client_revoke\",\"name\":\"codex\"}\n",
            "{\"type\":\"client_revoke_result\",\"ok\":true}\n",
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
}
