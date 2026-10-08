//! MCP server mode: the default (no args) mode. Attests and admits the
//! spawning harness, then either becomes the broker that owns the
//! browser-facing bridge socket or, if a broker already owns it, attaches to
//! that broker as a relay. See [`crate::broker`]. The MCP
//! protocol itself (JSON-RPC over stdio with the harness) is served by the
//! rmcp-based layer in [`crate::mcp`], one service per harness
//! connection, all sharing one [`Session`].

use crate::broker::{self, RelayOutcome};
use crate::ipc;
use crate::protocol::{install_stderr_panic_hook, HarnessId};
use crate::session::Session;
use crate::trust::{Admission, AdmittingSurface, Posture, TrustState};

/// The environment variable a harness may set to name itself
/// (claude-code/copilot/codex/...). Self-asserted and used for logs and the
/// audit surface only; it is NEVER the authorization key -- admission keys on
/// the harness's attested code identity (see [`crate::allowlist`]).
pub const CLIENT_NAME_ENV: &str = "GENKAN_CLIENT_NAME";

pub fn run() -> i32 {
    install_stderr_panic_hook();
    crate::sys::ignore_sigpipe();

    // Installed before anything is bound or published: a signal that lands earlier takes the default
    // disposition and leaves nothing behind. The remove is ownership-guarded, so a successor's files survive.
    if let Err(e) = install_signal_cleanup(|| {
        ipc::LockFile::remove_if_owned();
    }) {
        log_error!("mcp", "cannot install the SIGTERM/SIGINT cleanup: {e}");
        return 1;
    }

    match ipc::ensure_own_identity() {
        Ok(hash) => log_info!(
            "mcp",
            "bridge peer attestation active (self id {})",
            hash.get(..12).unwrap_or(hash)
        ),
        Err(e) => {
            log_error!("mcp", "cannot establish own executable identity: {e}");
            return 1;
        }
    }

    let harness = match admit_own_harness() {
        Some(h) => h,
        None => return 1,
    };

    let session = Session::new();

    // A live, attested broker is never SIGTERMed: other harnesses may be relaying through it. The retries
    // cover a broker exiting as we dial, or several instances starting at once.
    for _ in 0..6 {
        match ipc::listen_and_publish() {
            Ok(ipc::PublishOutcome::Published(listener, lock)) => {
                log_info!(
                    "mcp",
                    "this instance is the broker; bridge listening at {} (pid {})",
                    lock.endpoint,
                    lock.pid
                );
                return broker::run_broker(
                    listener,
                    session,
                    harness.client_identity(),
                    harness.posture,
                );
            }
            Ok(ipc::PublishOutcome::LostRace(cur)) => {
                log_info!(
                    "mcp",
                    "a broker (pid {}) already owns the bridge; attaching to it as a relay",
                    cur.pid
                );
                match broker::run_relay(harness.identity()) {
                    RelayOutcome::Denied => return 1,
                    RelayOutcome::Retry => {
                        std::thread::sleep(std::time::Duration::from_millis(150));
                    }
                }
            }
            Err(e) => {
                log_error!("mcp", "failed to bind and publish the bridge socket: {e}");
                return 1;
            }
        }
    }
    log_error!(
        "mcp",
        "could not become the broker or attach to one after several tries; giving up"
    );
    1
}

/// The result of admitting our own spawning harness. `None` from
/// [`admit_own_harness`] means refused (the caller exits non-zero); an
/// admitted harness whose `id` is `None` could not be measured but
/// admission was permitted (unenrolled / Windows).
struct Harness {
    id: Option<HarnessId>,
    /// The posture it was admitted under; the broker never serves it under a weaker one.
    posture: Posture,
}

impl Harness {
    fn identity(&self) -> Option<HarnessId> {
        self.id.clone()
    }

    /// The measured identity in the admission decision's input shape, for the broker's per-request re-decide.
    fn client_identity(&self) -> Option<ipc::ClientIdentity> {
        self.id.as_ref().map(ipc::ClientIdentity::from)
    }
}

/// Measure and admit the harness that spawned this MCP-server-mode instance over stdio. Returns
/// `Some(Harness)` when serving is permitted (with the harness identity to report if we become a relay), or
/// `None` when it is refused (the caller fails closed). On an unreadable trust record this fails closed via
/// `process::exit(1)` rather than degrading to unenrolled.
fn admit_own_harness() -> Option<Harness> {
    let name = client_name_from_env();

    let identity = match ipc::attest_parent() {
        Ok(id) => Some(id),
        Err(e) => {
            log_warn!("mcp", "could not attest the harness process: {e}");
            None
        }
    };

    let trust = match TrustState::current() {
        Ok(trust) => trust,
        Err(e) => {
            log_error!(
                "mcp",
                "cannot read the trust record ({e}); refusing to serve (fail closed)"
            );
            std::process::exit(1);
        }
    };

    let admission = trust.decide(identity.as_ref());
    if admission == Admission::Refused {
        log_error!(
            "mcp",
            "this harness is not in the trusted-client allowlist; refusing to serve \
             (fail closed). Pair it first: `genkan pair-client --name <label>`."
        );
    }
    admission.announce(AdmittingSurface::Stdio, name.as_deref(), identity.as_ref());
    let Admission::Admit(posture) = admission else {
        return None;
    };

    let id = identity.map(|id| HarnessId {
        hash: id.hash,
        signer: id.signer,
        name,
    });
    Some(Harness { id, posture })
}

/// The self-asserted client name from [`CLIENT_NAME_ENV`], validated like a
/// browser label, or `None`. Never used for authorization.
fn client_name_from_env() -> Option<String> {
    std::env::var(CLIENT_NAME_ENV)
        .ok()
        .filter(|n| ipc::validate_label(n))
}

/// Run `f` on a dedicated thread when SIGTERM or SIGINT arrives, then exit
/// ([`crate::sys::spawn_signal_cleanup`]). Windows has no equivalent here;
/// the next server start clears a stale lock.
fn install_signal_cleanup<F: Fn() + Send + 'static>(f: F) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        crate::sys::spawn_signal_cleanup(f)
    }
    #[cfg(not(unix))]
    {
        let _ = f;
        Ok(())
    }
}
