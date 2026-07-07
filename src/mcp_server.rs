//! MCP server mode: the default (no args) mode. Speaks JSON-RPC 2.0 over
//! stdio with ZCode, and accepts inbound bridge connections from the native
//! host over a localhost TCP socket.

use std::io::{self, BufReader, BufWriter};
use std::thread;

use serde_json::{json, Value};

use crate::ipc;
use crate::protocol::{mcp_read, mcp_write, install_stderr_panic_hook, JsonRpc};
use crate::session::Session;
use crate::tools;

pub fn run() -> i32 {
    install_stderr_panic_hook();
    crate::protocol::ignore_sigpipe();

    // 1. Bind the bridge socket and publish the lock file.
    let (listener, lock) = match ipc::listen() {
        Ok(x) => x,
        Err(e) => {
            eprintln!("[mcp] failed to bind bridge socket: {e}");
            return 1;
        }
    };
    if let Err(e) = lock.write() {
        eprintln!("[mcp] failed to write lock file: {e}");
        return 1;
    }
    eprintln!(
        "[mcp] bridge listening on 127.0.0.1:{} (pid {})",
        lock.port, lock.pid
    );

    let session = Session::new();

    // 2. Background thread: accept the native host's connection(s).
    {
        let session = session.clone();
        thread::spawn(move || loop {
            match listener.accept() {
                Ok((stream, _addr)) => {
                    if let Err(e) = session.attach_connection(stream) {
                        eprintln!("[mcp] accept handler error: {e}");
                    }
                }
                Err(e) => {
                    eprintln!("[mcp] accept failed: {e}");
                    break;
                }
            }
        });
    }

    // 3. Main loop: read NDJSON JSON-RPC from stdin, respond on stdout.
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());

    // Install a shutdown hook to remove the lock file so it doesn't go stale.
    let lock_path = ipc::LockFile::path();
    let cleanup = move || {
        let _ = std::fs::remove_file(&lock_path);
    };
    // Best-effort cleanup on Ctrl-C / SIGTERM (Rust default handler aborts).
    install_signal_cleanup(cleanup);

    loop {
        let msg = match mcp_read(&mut reader) {
            Ok(Some(m)) => m,
            Ok(None) => break, // stdin EOF
            Err(e) => {
                eprintln!("[mcp] stdin parse error: {e}");
                // Send a parse-error with null id; keep going if possible.
                let err = JsonRpc::err(Value::Null, -32700, format!("parse error: {e}"));
                let _ = mcp_write(&mut writer, &err);
                continue;
            }
        };
        let resp = handle(&session, &msg);
        if let Some(r) = resp {
            if let Err(e) = mcp_write(&mut writer, &r) {
                eprintln!("[mcp] stdout write failed: {e}");
                break;
            }
        }
        // None means notification (no response).
    }

    // stdin EOF: ZCode disconnected. Remove lock file.
    ipc::LockFile::remove();
    0
}

fn handle(session: &Session, msg: &JsonRpc) -> Option<JsonRpc> {
    // Notifications have no id and expect no response.
    let id = match &msg.id {
        Some(i) => i.clone(),
        None => {
            // Notification: the only one we care about is
            // notifications/initialized — no reply needed. Swallow the rest.
            return None;
        }
    };

    let method = msg.method.as_deref().unwrap_or("");
    match method {
        "initialize" => Some(JsonRpc::ok(
            id,
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": { "tools": {} },
                "serverInfo": {
                    "name": "browser-bridge",
                    "version": env!("CARGO_PKG_VERSION"),
                }
            }),
        )),
        "notifications/initialized" => {
            // Client signals ready; no reply.
            None
        }
        "ping" => Some(JsonRpc::ok(id, json!({}))),
        "tools/list" => {
            let list: Vec<Value> = tools::all()
                .iter()
                .map(|t| {
                    json!({
                        "name": t.name,
                        "description": t.description,
                        "inputSchema": t.input_schema,
                    })
                })
                .collect();
            Some(JsonRpc::ok(id, json!({ "tools": list })))
        }
        "tools/call" => {
            let params = msg.params.clone().unwrap_or(Value::Null);
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(Value::Null);
            // Tool errors are returned as a *successful* RPC with isError=true
            // in the result (per MCP spec); only protocol errors use the
            // error field.
            let (content, is_error) = tools::dispatch(session, name, &args);
            let result = json!({ "content": content, "isError": is_error });
            Some(JsonRpc::ok(id, result))
        }
        // Unknown method → JSON-RPC method-not-found.
        _ => Some(JsonRpc::err(id, -32601, format!("method not found: {method}"))),
    }
}

fn install_signal_cleanup<F: Fn() + Send + 'static>(_f: F) {
    // We avoid pulling in a signal-handling crate. The lock file is also
    // removed on the normal stdin-EOF exit path, which covers clean shutdown.
    // A stale lock file is harmless: the native host tolerates a failed
    // connect (it surfaces an error to the extension). Keeping this hook
    // point for a future minimal signal handler.
}
