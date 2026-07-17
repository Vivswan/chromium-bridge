//! Native-host mode: the `--native-host` subprocess spawned by Chrome.
//!
//! It is intentionally dumb. Two threads:
//! - stdin -> socket: read native-messaging frames, forward each JSON value as
//!   an NDJSON line over the bridge socket.
//! - socket -> stdout: read NDJSON lines from the bridge socket, frame each as
//!   a native-messaging message on stdout.
//!
//! All real logic lives in the MCP server on the other side of the socket.
//! EOF on stdin (Chrome disconnected) is our shutdown signal.

use std::io::{self, BufRead, BufReader, BufWriter};
use std::thread;

use crate::ipc;
use crate::protocol::{bridge_write, nm_read_frame, nm_write_frame};
use serde_json::Value;

pub fn run() -> i32 {
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
    if let Err(e) = ipc::client_handshake(&mut reader, &mut writer, None) {
        log_error!("native-host", "bridge handshake failed: {e}");
        return 1;
    }
    log_info!("native-host", "bridge handshake complete");

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

    // Thread A: stdin -> socket
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
    let stdout = io::stdout();
    let out_handle = thread::spawn(move || {
        let mut lines = reader.lines();
        // stdout must be flushed after every frame; acquire a single locked,
        // buffered writer for the whole thread (single-writer discipline).
        let mut out = BufWriter::new(stdout.lock());
        loop {
            let line = match lines.next() {
                Some(Ok(l)) => l,
                Some(Err(e)) => {
                    log_warn!("native-host", "bridge read error: {e}");
                    break;
                }
                None => {
                    log_info!("native-host", "bridge EOF");
                    break;
                }
            };
            if line.trim().is_empty() {
                continue;
            }
            let value: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(e) => {
                    log_warn!("native-host", "bridge line not json: {e}");
                    continue;
                }
            };
            if let Err(e) = nm_write_frame(&mut out, &value) {
                log_warn!("native-host", "stdout write error: {e}");
                break;
            }
        }
        log_debug!("native-host", "socket->stdout thread ending");
    });

    // Block until the socket->stdout thread ends. The stdin->socket thread will
    // have already called process::exit(0) on its own close path; if it
    // hasn't, we exit here once the socket side closes.
    let _ = out_handle.join();
    log_debug!("native-host", "exit");
    std::process::exit(0);
}
