//! Native-host mode: the `--native-host` subprocess spawned by Chrome.
//!
//! It is intentionally dumb. Two threads:
//!   - stdin  -> TCP  : read native-messaging frames, forward each JSON value
//!                      as an NDJSON line over the bridge socket.
//!   - TCP    -> stdout: read NDJSON lines from the bridge socket, frame each
//!                      as a native-messaging message on stdout.
//!
//! All real logic lives in the MCP server on the other side of the socket.
//! EOF on stdin (Chrome disconnected) is our shutdown signal.

use std::io::{self, BufRead, BufReader, BufWriter};
use std::sync::mpsc;
use std::thread;

use crate::ipc;
use crate::protocol::{bridge_write, nm_read_frame, nm_write_frame};
use serde_json::Value;

pub fn run() -> i32 {
    // Connect to the MCP server's localhost TCP socket (reads the lock file).
    let stream = match ipc::connect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[native-host] cannot connect to MCP server: {e}");
            // No way to talk to Chrome usefully without the server; exit so
            // the extension sees onDisconnect and can surface the error.
            return 1;
        }
    };
    eprintln!("[native-host] connected to MCP server bridge socket");

    let stream_clone = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[native-host] clone stream: {e}");
            return 1;
        }
    };

    // We need a shutdown signal between the two threads so that when one side
    // closes the other doesn't block forever. A channel whose receiver is
    // dropped on shutdown acts as a "kick".
    let (stop_tx, stop_rx) = mpsc::channel::<()>();

    // Thread A: stdin -> TCP
    let tcp_out = stream;
    let stop_tx_a = stop_tx.clone();
    let in_handle = thread::spawn(move || {
        let mut stdin = io::stdin();
        let mut tcp = BufWriter::new(tcp_out);
        loop {
            // stop_rx.recv_timeout would block reading stdin anyway; just
            // check between frames.
            if stop_rx.try_recv().is_ok() {
                break;
            }
            let frame: Option<Value> = match nm_read_frame(&mut stdin) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[native-host] stdin read error: {e}");
                    break;
                }
            };
            let frame = match frame {
                Some(v) => v,
                None => {
                    // EOF on stdin: Chrome disconnected. Canonical shutdown.
                    eprintln!("[native-host] stdin EOF, shutting down");
                    break;
                }
            };
            if let Err(e) = bridge_write(&mut tcp, &frame) {
                eprintln!("[native-host] tcp write error: {e}");
                break;
            }
        }
        let _ = stop_tx_a.send(());
    });

    // Thread B: TCP -> stdout
    let stdout = io::stdout();
    let stop_tx_b = stop_tx.clone();
    let out_handle = thread::spawn(move || {
        let tcp_in = BufReader::new(stream_clone);
        let mut lines = tcp_in.lines();
        // stdout must be flushed after every frame; acquire a single locked,
        // buffered writer for the whole thread (single-writer discipline).
        let mut out = BufWriter::new(stdout.lock());
        loop {
            // The first line is the hello/auth. Bridge the rest verbatim,
            // since the MCP server only cares about JSON values.
            let line = match lines.next() {
                Some(Ok(l)) => l,
                Some(Err(e)) => {
                    eprintln!("[native-host] tcp read error: {e}");
                    break;
                }
                None => {
                    eprintln!("[native-host] tcp EOF");
                    break;
                }
            };
            if line.trim().is_empty() {
                continue;
            }
            let value: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[native-host] tcp line not json: {e}");
                    continue;
                }
            };
            // Skip the hello line (auth) — it never goes to Chrome.
            if value.get("hello").is_some() {
                continue;
            }
            if let Err(e) = nm_write_frame(&mut out, &value) {
                eprintln!("[native-host] stdout write error: {e}");
                break;
            }
        }
        let _ = stop_tx_b.send(());
    });

    // Wait for either side to finish; the other thread will see the stop
    // signal and exit on its next iteration.
    let _ = in_handle.join();
    let _ = out_handle.join();
    let _ = stop_tx.send(());
    eprintln!("[native-host] exit");
    0
}
