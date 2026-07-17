//! Native-host mode: the `--native-host` subprocess spawned by Chrome.
//!
//! It is intentionally dumb. Two threads:
//! - stdin -> socket: read native-messaging frames, forward each JSON value as
//!   an NDJSON line over the bridge socket.
//! - socket -> stdout: read NDJSON lines from the bridge socket, frame each as
//!   a native-messaging message on stdout.
//!
//! The one exception to "forward everything" is the enrollment ceremony
//! (ADR-0021): frames whose `type` is one of the enclave control tags are
//! handled HERE — an `enclave_challenge` is answered locally by signing with
//! the Secure Enclave key (raising the user-presence prompt) — and are never
//! forwarded to the MCP server. Everything else forwards byte-for-byte, so
//! all real tool logic stays in the MCP server on the other side of the
//! socket. EOF on stdin (Chrome disconnected) is our shutdown signal.

use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::ipc;
use crate::protocol::{
    bridge_read, bridge_write, classify_nm_frame, nm_read_frame, nm_write_frame, EnclaveControl,
    FrameDisposition,
};
use serde_json::Value;

/// Serialize an enclave control frame and write it to Chrome via the shared
/// stdout writer. `nm_write_frame` flushes per frame, so taking the lock per
/// frame keeps replies atomic with respect to the socket->stdout pump.
fn write_control_reply(
    out: &Mutex<BufWriter<io::Stdout>>,
    reply: &EnclaveControl,
) -> io::Result<()> {
    let value = serde_json::to_value(reply)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("encode reply: {e}")))?;
    let mut out = out
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    nm_write_frame(&mut *out, &value)
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
    // the stdin->socket thread borrows it briefly to answer enclave control
    // frames (which reply toward Chrome, not toward the socket). A mutex
    // around one buffered writer keeps frames whole; every write flushes.
    let stdout_writer = Arc::new(Mutex::new(BufWriter::new(io::stdout())));

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
            // Enclave control frames (ADR-0021) are addressed to THIS process
            // and must never reach the socket; everything else forwards.
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
}
