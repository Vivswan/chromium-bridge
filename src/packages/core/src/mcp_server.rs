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
use crate::trust::{Admission, Posture, TrustState};

/// The environment variable a harness may set to name itself
/// (claude-code/copilot/codex/...). Self-asserted and used for logs and the
/// audit surface only; it is NEVER the authorization key -- admission keys on
/// the harness's attested code identity (see [`crate::allowlist`]).
pub const CLIENT_NAME_ENV: &str = "CHROMIUM_BRIDGE_CLIENT_NAME";

pub fn run() -> i32 {
    install_stderr_panic_hook();
    crate::protocol::ignore_sigpipe();

    // Handle termination signals gracefully so we always remove the lock file
    // on the way out (a stale lock is harmless but confuses diagnostics, and a
    // broker that exits should clean up after itself). Ownership-guarded: if a
    // successor has already taken over, the lock and socket on disk are the
    // NEW broker's, and removing them would take the working bridge down.
    // Installed first, before anything is bound or published: a signal that
    // lands earlier takes the default disposition and leaves nothing behind.
    if let Err(e) = install_signal_cleanup(|| {
        ipc::LockFile::remove_if_owned();
    }) {
        log_error!("mcp", "cannot install the SIGTERM/SIGINT cleanup: {e}");
        return 1;
    }

    // Capture our own executable identity up front, before binding or dialing,
    // so peer attestation compares against the genuine binary rather than one
    // an attacker might swap onto disk later. Refuse to run if we cannot hash
    // our own image.
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

    // Attest our own harness (the process that spawned us over stdio) and
    // decide admission against the trusted-client allowlist BEFORE serving any
    // tool call. A refusal here is fail-closed: we do not become a broker or a
    // relay. Returns the harness identity to report if we end up a relay.
    let harness = match admit_own_harness() {
        Some(h) => h,
        None => return 1, // fail closed, already logged
    };

    let session = Session::new();

    // Become the broker, or attach to an existing one as a relay. A live,
    // attested broker is coexisted with, never SIGTERMed: other harnesses may
    // be relaying through it. Bounded retries cover the races -- a broker exiting as we
    // dial, or several instances starting at once.
    for _ in 0..6 {
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
                    // A relay that attached and served ends by exiting the
                    // process directly (see run_relay), so it never returns
                    // here; only the pre-serve outcomes come back.
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

    let posture = match trust.decide(identity.as_ref()) {
        Admission::Refused => {
            log_error!(
                "mcp",
                "this harness is not in the trusted-client allowlist; refusing to serve \
                 (fail closed). Pair it first: `chromium-bridge pair-client --name <label>`."
            );
            crate::audit::record(
                crate::audit::AuditRecord::new(crate::audit::AuditKind::HarnessRefuse)
                    .surface(crate::audit::Surface::Host)
                    .name(name.as_deref().unwrap_or("-"))
                    .outcome("refused")
                    .detail("not in the trusted-client allowlist"),
            );
            return None;
        }
        Admission::Admit(Posture::Unenrolled) => {
            log_error!(
                "mcp",
                "SECURITY: harness admission is NOT enforced -- no trusted client has been \
                 paired yet (unenrolled). Any same-user process that runs our binary can drive \
                 the browser. Run `chromium-bridge pair-client` to enroll trusted clients and \
                 turn on enforcement. See SECURITY.md."
            );
            // The measured anchors, so the operator can pair this harness with
            // `--hash` or `--signer` where `--this-parent` cannot measure it
            // (Windows, or any harness that spawns the server over a pipe).
            // The subject is printed bare, not as a shell argument: an X.500
            // subject can carry quotes and commas, and quoting differs per shell.
            if let Some(id) = &identity {
                let signer = id
                    .signer
                    .as_ref()
                    .map(|s| format!(", signer [{s}]"))
                    .unwrap_or_default();
                log_error!(
                    "mcp",
                    "this harness measured as hash {}{signer}; pair it with `pair-client --hash {}`{}",
                    id.hash,
                    id.hash,
                    if id.signer.is_some() {
                        " or `--signer` with that value, quoted for your shell"
                    } else {
                        ""
                    }
                );
            }
            crate::audit::record(
                crate::audit::AuditRecord::new(crate::audit::AuditKind::HarnessAdmit)
                    .surface(crate::audit::Surface::Host)
                    .name(name.as_deref().unwrap_or("-"))
                    .outcome("unenrolled"),
            );
            Posture::Unenrolled
        }
        Admission::Admit(Posture::Trusted { name: matched }) => {
            log_info!("mcp", "harness admitted as trusted client '{matched}'");
            crate::audit::record(
                crate::audit::AuditRecord::new(crate::audit::AuditKind::HarnessAdmit)
                    .surface(crate::audit::Surface::Host)
                    .name(&matched)
                    .outcome("ok"),
            );
            Posture::Trusted { name: matched }
        }
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
