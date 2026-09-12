//! IPC between the MCP server (long-lived) and the native-host subprocess (spawned fresh by Chrome on each
//! connectNative). The public API is re-exported here so callers keep using `ipc::...`; each submodule's own
//! doc describes its concern.
//!
//! ```text
//! Unix     -> 0600 Unix-domain socket in a private 0700 runtime dir: no port to reach, other users kept out
//! Windows  -> loopback TCP on an ephemeral port (no std Unix-domain sockets)
//! both     -> endpoint (socket path, or 127.0.0.1:port) + per-run secret published in the lock file the host reads on startup
//! ```
//!
//! Before the handshake, on Linux and macOS, each end kernel-attests the other ([`attest_peer`], ADR-0020): the
//! peer must run the same executable image, so a different same-user program is rejected at accept. Windows
//! has no image attestation (see SECURITY.md "Platform support") and relies on the handshake alone.
//! ```text
//! Linux  -> SHA256 of `/proc/<pid>/exe`
//! macOS  -> code-directory hash of the running image via its kernel audit token (survives a re-open TOCTOU)
//! ```
//!
//! The handshake is an HMAC-SHA256 challenge-response ([`server_handshake`] / [`client_handshake`]): a random
//! nonce per connection, answered with HMAC(secret, nonce), so the secret never travels and a captured reply
//! cannot replay.

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod attest;
mod handshake;
mod lockfile;
mod peercred;
mod platform;
mod rand;
mod socket;

/// A harness's kernel-attested code identity, the input to the trusted-client
/// allowlist decision ([`crate::allowlist`]). `hash` is the attested image
/// hash (macOS `cdhash`, Linux `/proc/<pid>/exe` SHA256), always present.
/// `team_id` is the macOS signing Team ID, present only for a Team-ID-signed
/// image (always `None` on Linux and for ad-hoc / unsigned builds). Defined
/// here (not in the Unix-only `attest` module) so it is nameable on every
/// platform, including the Windows build where no attestation exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIdentity {
    pub hash: String,
    pub team_id: Option<String>,
}

impl From<&crate::protocol::HarnessId> for ClientIdentity {
    /// The allowlist-input projection of an attested harness identity. Drops
    /// `name` deliberately: it is a self-asserted log label, never an
    /// authorization key (ADR-0024).
    fn from(h: &crate::protocol::HarnessId) -> Self {
        ClientIdentity {
            hash: h.hash.clone(),
            team_id: h.team_id.clone(),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use attest::attest_parent;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use attest::{attest_peer, attest_pid, ensure_own_identity};
#[cfg(feature = "fuzzing")]
pub use handshake::fuzz_api as handshake_fuzz;
pub use handshake::{
    client_handshake, server_handshake, validate_label, BrowserLabel, DEFAULT_LABEL,
};
pub use lockfile::{listen_and_publish, LockFile, PublishOutcome};
#[cfg(unix)]
pub use peercred::checked_pid;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use peercred::peer_pid;
#[cfg(unix)]
pub use peercred::peer_uid;
pub use peercred::pid_is_alive;
#[cfg(windows)]
pub use platform::windows::windows_process;
pub use socket::{connect, BridgeListener, BridgeStream};

pub(crate) use lockfile::{
    read_capped, runtime_dir, with_runtime_lock, write_private_atomic, RuntimeLockToken,
};
pub(crate) use rand::{generate_secret, hex_encode};
