//! MCP server mode: the default (no args) mode. Speaks JSON-RPC 2.0 over
//! stdio with the MCP client, and accepts inbound bridge connections from the
//! native host over the bridge socket.

use std::io::{self, BufReader, BufWriter};
use std::thread;

use serde_json::{json, Value};

use crate::ipc;
use crate::protocol::{install_stderr_panic_hook, mcp_read, mcp_write, JsonRpc};
use crate::session::Session;
use crate::tools;

pub fn run() -> i32 {
    install_stderr_panic_hook();
    crate::protocol::ignore_sigpipe();

    // Handle termination signals gracefully so we always remove the lock file
    // on the way out (a stale lock is harmless but confuses diagnostics, and a
    // supplanted server should clean up after itself). Ownership-guarded: if a
    // successor has already taken over, the lock and socket on disk are the
    // NEW server's, and removing them would take the working bridge down. This
    // must run BEFORE we spawn any worker threads: it blocks SIGTERM/SIGINT
    // process-wide, and only threads created afterwards inherit that blocked
    // mask — otherwise the kernel could deliver the signal to an unmasked
    // worker and terminate us before the handler thread runs.
    install_signal_cleanup(|| {
        ipc::LockFile::remove_if_owned();
    });

    // Capture our own executable identity up front, before binding or accepting,
    // so peer attestation compares against the genuine binary rather than one an
    // attacker might swap onto disk later. Refuse to run if we cannot hash our
    // own image. See ADR-0020.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    match ipc::ensure_own_identity() {
        Ok(hash) => log_info!(
            "mcp",
            "bridge peer attestation active (self id {})",
            &hash[..12]
        ),
        Err(e) => {
            log_error!("mcp", "cannot establish own executable identity: {e}");
            return 1;
        }
    }

    // Windows has none of the mechanisms above (all cfg unix/macos), so say so
    // loudly at every startup rather than let the platform difference pass
    // silently. Error level, not warn: BB_LOG=error must not silence it.
    // See SECURITY.md "Platform support".
    #[cfg(target_os = "windows")]
    {
        log_error!(
            "mcp",
            "SECURITY: Windows support is BEST-EFFORT. The same-user and \
             local-process protections enforced on macOS/Linux do NOT hold \
             here: there is no peer-UID check and no executable attestation, \
             and the bridge listens on loopback TCP, reachable by ANY process \
             on this machine. Access control reduces to the confidentiality \
             of the per-run secret in the lock file, which relies only on the \
             default permissions of the per-user runtime directory (normally \
             under LOCALAPPDATA). Treat any local process as able to attempt \
             a connection; do not use this bridge on a Windows machine where \
             that risk is unacceptable. See SECURITY.md (Platform support) \
             for details."
        );
    }

    // 1. Take over from any prior MCP server instance, then bind and publish.
    // The MCP client may spawn a fresh server per session; if the previous one
    // is still alive, the native host keeps talking to IT (it doesn't follow
    // lock-file changes), so the new server's tool calls would report
    // "extension not connected". Kill the old instance so the native host's
    // connection drops and the extension reconnects against our lock.
    //
    // The sequencing is load-bearing: the dying server's cleanup unlinks the
    // socket path, so the takeover must fully complete before we bind. An
    // earlier version bound first and then supplanted, which left the new
    // listener bound to an already-unlinked inode — the reconnecting native
    // host got ENOENT and the bridge stayed down until both processes were
    // restarted by hand. The SIGTERM-and-wait runs OUTSIDE the runtime mutex
    // (the dying server's own cleanup needs that mutex to finish);
    // listen_and_publish then re-checks under the mutex and reports LostRace
    // if yet another server published meanwhile, in which case we supplant
    // that one too (newest server wins, bounded retries).
    let mut lost_races = 0;
    let (listener, lock) = loop {
        if let Ok(Some(prev)) = ipc::LockFile::read() {
            if prev.pid != std::process::id() && ipc::pid_is_alive(prev.pid) {
                log_info!("mcp", "supplanting prior MCP server pid {}", prev.pid);
                // SIGTERM -> old server cleans up its own lock and socket and
                // exits -> its listener closes -> native host gets EOF -> SW
                // onDisconnect -> reconnect spawns a fresh host -> reads OUR
                // lock. Give it a moment to die and clean up.
                terminate_process(prev.pid);
                for _ in 0..50 {
                    if !ipc::pid_is_alive(prev.pid) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                if ipc::pid_is_alive(prev.pid) {
                    // Proceed anyway: listen_and_publish clears its files and
                    // binds over them, and its exit cleanup is ownership-
                    // guarded, so it cannot remove what will by then be OUR
                    // lock and socket.
                    log_warn!(
                        "mcp",
                        "prior MCP server pid {} did not exit in time; proceeding",
                        prev.pid
                    );
                }
            }
        }
        match ipc::listen_and_publish() {
            Ok(ipc::PublishOutcome::Published(listener, lock)) => break (listener, lock),
            Ok(ipc::PublishOutcome::LostRace(cur)) => {
                lost_races += 1;
                if lost_races > 3 {
                    log_error!(
                        "mcp",
                        "another MCP server (pid {}) keeps publishing concurrently; giving up",
                        cur.pid
                    );
                    return 1;
                }
                log_info!(
                    "mcp",
                    "another MCP server (pid {}) published concurrently; supplanting it",
                    cur.pid
                );
            }
            Err(e) => {
                log_error!("mcp", "failed to bind and publish bridge socket: {e}");
                return 1;
            }
        }
    };
    log_info!(
        "mcp",
        "bridge listening at {} (pid {}) lock at {}",
        lock.endpoint,
        lock.pid,
        ipc::LockFile::path().display()
    );

    let session = Session::new();

    // 2. Background thread: accept the native host's connection(s).
    {
        let session = session.clone();
        thread::spawn(move || loop {
            match listener.accept() {
                Ok((stream, _addr)) => {
                    // Single chokepoint: reject any peer that is not this same
                    // user before the connection is authenticated or trusted.
                    #[cfg(unix)]
                    {
                        let want = unsafe { libc::geteuid() };
                        match ipc::peer_uid(&stream) {
                            Ok(uid) if uid == want => {}
                            Ok(uid) => {
                                log_warn!(
                                    "mcp",
                                    "rejected bridge connection from uid {uid} (server euid {want})"
                                );
                                continue;
                            }
                            Err(e) => {
                                log_warn!(
                                    "mcp",
                                    "rejected bridge connection: peer uid unknown: {e}"
                                );
                                continue;
                            }
                        }
                    }
                    // Kernel-attest the peer's executable identity: only another
                    // instance of THIS binary may drive the bridge, so a
                    // different same-user program is rejected here, before the
                    // HMAC handshake. See ADR-0020.
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    {
                        if let Err(e) = ipc::attest_peer(&stream) {
                            log_warn!("mcp", "rejected bridge connection: {e}");
                            continue;
                        }
                    }
                    if let Err(e) = session.attach_connection(stream) {
                        log_warn!("mcp", "accept handler error: {e}");
                    }
                }
                Err(e) => {
                    log_error!("mcp", "accept failed: {e}");
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

    loop {
        let msg = match mcp_read(&mut reader) {
            Ok(Some(m)) => m,
            Ok(None) => break, // stdin EOF
            Err(e) => {
                log_warn!("mcp", "stdin parse error: {e}");
                // Send a parse-error with null id; keep going if possible.
                let err = JsonRpc::err(Value::Null, -32700, format!("parse error: {e}"));
                let _ = mcp_write(&mut writer, &err);
                continue;
            }
        };
        let resp = handle(&session, &msg);
        if let Some(r) = resp {
            if let Err(e) = mcp_write(&mut writer, &r) {
                log_error!("mcp", "stdout write failed: {e}");
                break;
            }
        }
        // None means notification (no response).
    }

    // stdin EOF: the MCP client disconnected. Remove the lock file — unless a
    // successor has already replaced it (ownership-guarded, see above).
    ipc::LockFile::remove_if_owned();
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
            // Correlate every invocation with a per-call request id and record a
            // structured audit event (tool, outcome, taxonomy code, duration).
            let req_id = next_request_id();
            let started = std::time::Instant::now();
            // Capture where this call would be routed (browser label +
            // connection generation), so the audit line can be correlated
            // with a specific browser and native-host connection across
            // reconnects. Best-effort diagnostics, not enforcement: the
            // snapshot is taken outside the routing lock, so a reconnect
            // racing the call can leave it one generation stale. The
            // post-dispatch retry covers the common miss (a host that
            // attached during the call's startup wait); `"-"` when still
            // unroutable.
            let browser_arg = args.get("browser").and_then(|v| v.as_str());
            let route = session.route_info(browser_arg);
            // Tool errors are returned as a *successful* RPC with isError=true
            // in the result (per MCP spec); only protocol errors use the
            // error field.
            let out = tools::dispatch(session, name, &args);
            let route = route.or_else(|| session.route_info(browser_arg));
            let conn_s = route
                .as_ref()
                .map_or_else(|| "-".to_string(), |(_, g)| g.to_string());
            let browser_s = route
                .as_ref()
                .map_or_else(|| "-".to_string(), |(l, _)| l.clone());
            let req_s = req_id.to_string();
            let dur_s = started.elapsed().as_millis().to_string();
            crate::log::audit(&[
                ("req", req_s.as_str()),
                ("conn", conn_s.as_str()),
                ("browser", browser_s.as_str()),
                ("tool", name),
                ("outcome", if out.is_error { "error" } else { "ok" }),
                ("code", out.error_code.unwrap_or("-")),
                ("dur_ms", dur_s.as_str()),
            ]);
            let result = json!({ "content": out.content, "isError": out.is_error });
            Some(JsonRpc::ok(id, result))
        }
        // Unknown method → JSON-RPC method-not-found.
        _ => Some(JsonRpc::err(
            id,
            -32601,
            format!("method not found: {method}"),
        )),
    }
}

/// Block SIGTERM/SIGINT process-wide and run `f` on a dedicated thread when
/// one arrives, then exit. Blocking the signals here (and letting a single
/// thread `sigwait` for them) sidesteps async-signal-safety limits: the
/// cleanup runs in ordinary thread context, so it may touch the filesystem
/// freely. Callers MUST invoke this before spawning worker threads so those
/// threads inherit the blocked mask.
fn install_signal_cleanup<F: Fn() + Send + 'static>(f: F) {
    #[cfg(unix)]
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGINT);
        // Block in the current (main) thread; threads spawned later inherit it.
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());

        thread::spawn(move || {
            let mut sig: std::os::raw::c_int = 0;
            // Wait until one of the blocked signals is delivered.
            let _ = libc::sigwait(&set, &mut sig);
            log_info!("mcp", "received signal {sig}, cleaning up and exiting");
            f();
            std::process::exit(0);
        });
    }
    #[cfg(not(unix))]
    {
        let _ = f;
    }
}

/// A monotonic per-call request id, used to correlate audit lines with the
/// tool invocation they describe. Process-wide; starts at 1.
fn next_request_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn terminate_process(pid: u32) {
    #[cfg(unix)]
    if let Some(pid) = ipc::checked_pid(pid) {
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
    #[cfg(windows)]
    ipc::windows_process::terminate(pid);
    #[cfg(all(not(unix), not(windows)))]
    let _ = pid;
}
