//! MCP server mode: the default (no args) mode. Speaks JSON-RPC 2.0 over
//! stdio with the MCP client (the "harness"), and either becomes the broker
//! that owns the browser-facing bridge socket or, if a broker already owns it,
//! attaches to that broker as a relay. See [`crate::broker`] and ADR-0024.

use serde_json::{json, Value};

use crate::allowlist::{self, Decision};
use crate::broker::{self, RelayOutcome};
use crate::ipc;
use crate::protocol::{install_stderr_panic_hook, HarnessId, JsonRpc};
use crate::session::Session;
use crate::tools;

/// The environment variable a harness may set to name itself
/// (claude-code/copilot/codex/...). Self-asserted and used for logs and the
/// audit surface only; it is NEVER the authorization key -- admission keys on
/// the harness's attested code identity (see [`crate::allowlist`]).
const CLIENT_NAME_ENV: &str = "CHROMIUM_BRIDGE_CLIENT_NAME";

pub fn run() -> i32 {
    install_stderr_panic_hook();
    crate::protocol::ignore_sigpipe();

    // Handle termination signals gracefully so we always remove the lock file
    // on the way out (a stale lock is harmless but confuses diagnostics, and a
    // broker that exits should clean up after itself). Ownership-guarded: if a
    // successor has already taken over, the lock and socket on disk are the
    // NEW broker's, and removing them would take the working bridge down. This
    // must run BEFORE we spawn any worker threads: it blocks SIGTERM/SIGINT
    // process-wide, and only threads created afterwards inherit that blocked
    // mask -- otherwise the kernel could deliver the signal to an unmasked
    // worker and terminate us before the handler thread runs.
    install_signal_cleanup(|| {
        ipc::LockFile::remove_if_owned();
    });

    // Capture our own executable identity up front, before binding or dialing,
    // so peer attestation compares against the genuine binary rather than one
    // an attacker might swap onto disk later. Refuse to run if we cannot hash
    // our own image. See ADR-0020.
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

    // Windows has none of the peer/attestation mechanisms (all cfg unix/macos),
    // so say so loudly at every startup rather than let the platform difference
    // pass silently. Error level, not warn: BB_LOG=error must not silence it.
    // See SECURITY.md "Platform support".
    #[cfg(target_os = "windows")]
    {
        log_error!(
            "mcp",
            "SECURITY: Windows support is BEST-EFFORT. The same-user and \
             local-process protections enforced on macOS/Linux do NOT hold \
             here: there is no peer-UID check, no executable attestation, and \
             no harness attestation, and the bridge listens on loopback TCP, \
             reachable by ANY process on this machine. Access control reduces \
             to the confidentiality of the per-run secret in the lock file. \
             See SECURITY.md (Platform support) for details."
        );
    }

    // Attest our own harness (the process that spawned us over stdio) and
    // decide admission against the trusted-client allowlist BEFORE serving any
    // tool call. A refusal here is fail-closed: we do not become a broker or a
    // relay. Returns the harness identity to report if we end up a relay.
    let harness = match admit_own_harness() {
        Some(h) => h,
        None => return 1, // fail closed, already logged
    };

    let session = Session::new();

    // Become the broker, or attach to an existing one as a relay. Newest-wins
    // takeover is gone (ADR-0024): a live, attested broker is coexisted with,
    // not SIGTERMed. Bounded retries cover the races -- a broker exiting as we
    // dial, or several instances starting at once.
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        if attempts > 6 {
            log_error!(
                "mcp",
                "could not become the broker or attach to one after several tries; giving up"
            );
            return 1;
        }
        match ipc::listen_and_publish() {
            Ok(ipc::PublishOutcome::Published(listener, lock)) => {
                log_info!(
                    "mcp",
                    "this instance is the broker; bridge listening at {} (pid {}) lock at {}",
                    lock.endpoint,
                    lock.pid,
                    ipc::LockFile::path().display()
                );
                return broker::run_broker(
                    listener,
                    session,
                    broker::OwnHarness {
                        identity: harness.client_identity(),
                        epoch: harness.epoch,
                    },
                );
            }
            Ok(ipc::PublishOutcome::LostRace(cur)) => {
                log_info!(
                    "mcp",
                    "a broker (pid {}) already owns the bridge; attaching to it as a relay",
                    cur.pid
                );
                match broker::run_relay(harness.identity()) {
                    // A relay that attached and served ends by exiting the
                    // process directly (see run_relay), so it never returns
                    // here; only the pre-serve outcomes come back.
                    RelayOutcome::Denied => return 1,
                    RelayOutcome::Retry => {
                        std::thread::sleep(std::time::Duration::from_millis(150));
                        continue;
                    }
                }
            }
            Err(e) => {
                log_error!("mcp", "failed to bind and publish the bridge socket: {e}");
                return 1;
            }
        }
    }
}

/// The result of admitting our own spawning harness. `None` from
/// [`admit_own_harness`] means refused (the caller exits non-zero); an
/// admitted harness whose `identity` is `None` could not be measured but
/// admission was permitted (unenrolled / Windows). `epoch` is the revocation
/// epoch the admission was decided under (ADR-0025): the broker's own-harness
/// epoch guard starts from it, and re-decides on any bump.
struct Harness {
    id: Option<HarnessId>,
    epoch: u64,
}

impl Harness {
    fn identity(&self) -> Option<HarnessId> {
        self.id.clone()
    }

    /// The measured identity in the allowlist's input shape, for the broker's
    /// own-harness revocation rechecks.
    fn client_identity(&self) -> Option<ipc::ClientIdentity> {
        self.id.as_ref().map(|h| ipc::ClientIdentity {
            hash: h.hash.clone(),
            team_id: h.team_id.clone(),
        })
    }
}

/// Measure and admit the harness that spawned this MCP-server instance over
/// stdio. Returns `Some(Harness)` when serving is permitted (with the harness
/// identity to report if we become a relay), or `None` when it is refused (the
/// caller fails closed). On an unreadable allowlist or revocation record this
/// fails closed via `process::exit(1)` rather than degrading to unenrolled.
fn admit_own_harness() -> Option<Harness> {
    let name = client_name_from_env();

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let identity = match ipc::attest_parent() {
        Ok(id) => Some(id),
        Err(e) => {
            log_warn!(
                "mcp",
                "could not attest the spawning harness (getppid): {e}"
            );
            None
        }
    };
    // Windows has no harness attestation; admission degrades to unenrolled /
    // secret-only along with the rest of the IPC layer.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let identity: Option<ipc::ClientIdentity> = None;

    // Read order is load-bearing (ADR-0025): the revocation record FIRST,
    // then the allowlist, so a concurrent revoke can never be observed as a
    // new epoch paired with a stale list. Both reads fail closed.
    let rev = match crate::revocation::Revocation::current() {
        Ok(rev) => rev,
        Err(e) => {
            log_error!(
                "mcp",
                "cannot read the revocation record ({e}); refusing to serve (fail closed)"
            );
            std::process::exit(1);
        }
    };
    let list = match allowlist::load_enforced(rev.clients_enrolled) {
        Ok(l) => l,
        Err(e) => {
            log_error!(
                "mcp",
                "cannot read the trusted-client allowlist ({e}); refusing to serve (fail closed)"
            );
            std::process::exit(1);
        }
    };

    match allowlist::decide(list.as_ref(), identity.as_ref()) {
        Decision::Refuse => {
            log_error!(
                "mcp",
                "this harness is not in the trusted-client allowlist; refusing to serve \
                 (fail closed). Pair it first: `chromium-bridge pair-client --name <label>`."
            );
            return None;
        }
        Decision::AdmitUnenrolled => {
            log_error!(
                "mcp",
                "SECURITY: harness admission is NOT enforced -- no trusted-client allowlist \
                 exists yet (unenrolled). Any same-user process that runs our binary can drive \
                 the browser. Run `chromium-bridge pair-client` to enroll trusted clients and \
                 turn on enforcement. See SECURITY.md."
            );
        }
        Decision::Admit { name } => {
            log_info!("mcp", "harness admitted as trusted client '{name}'");
        }
    }

    let id = identity.map(|id| HarnessId {
        hash: id.hash,
        team_id: id.team_id,
        name,
    });
    Some(Harness {
        id,
        epoch: rev.epoch,
    })
}

/// The self-asserted client name from [`CLIENT_NAME_ENV`], validated like a
/// browser label, or `None`. Never used for authorization.
fn client_name_from_env() -> Option<String> {
    std::env::var(CLIENT_NAME_ENV)
        .ok()
        .filter(|n| ipc::validate_label(n))
}

/// Handle one JSON-RPC message against the shared session and return the
/// response (or `None` for a notification). Called by both the broker's own
/// stdio loop and every relay's serve loop, so all harnesses share one
/// dispatcher over one [`Session`].
pub(crate) fn handle(session: &Session, msg: &JsonRpc) -> Option<JsonRpc> {
    // Notifications have no id and expect no response.
    let id = match &msg.id {
        Some(i) => i.clone(),
        None => {
            // Notification: the only one we care about is
            // notifications/initialized -- no reply needed. Swallow the rest.
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
                    "name": "chromium-bridge",
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
            // reconnects. Best-effort diagnostics, not enforcement.
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
        // Unknown method -> JSON-RPC method-not-found.
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

        std::thread::spawn(move || {
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
