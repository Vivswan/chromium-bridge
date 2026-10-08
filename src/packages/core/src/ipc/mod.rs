//! IPC between the long-lived MCP server and the native host Chrome spawns per connectNative. Every
//! connection passes the same-user gate, image attestation ([`attest_peer`]), then the HMAC handshake
//! ([`server_handshake`]); each submodule's doc owns its mechanism.

mod attest;
mod handshake;
mod identity;
mod lockfile;
mod peercred;
mod platform;
mod rand;
mod runtime_dir;
mod socket;

pub use attest::{attest_parent, attest_peer, attest_pid, ensure_own_identity};
#[cfg(feature = "fuzzing")]
pub use handshake::fuzz_api as handshake_fuzz;
pub use handshake::{
    client_handshake, server_handshake, validate_label, BrowserLabel, DEFAULT_LABEL,
};
pub use identity::{ClientIdentity, HashDigest, SignerId};
pub use lockfile::{listen_and_publish, LockFile, PublishOutcome, LOCK_FILENAME};
#[cfg(unix)]
pub use peercred::checked_pid;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use peercred::peer_pid;
#[cfg(unix)]
pub use peercred::peer_uid;
pub use peercred::pid_is_alive;
pub use socket::{connect, probe_endpoint, BridgeListener, BridgeStream};

pub(crate) use lockfile::{with_runtime_lock, RuntimeLockToken};
pub(crate) use runtime_dir::RuntimeDir;
#[cfg(test)]
pub(crate) use runtime_dir::RUNTIME_DIR_VAR;
