//! IPC between the MCP server (long-lived) and the native-host subprocess
//! (spawned fresh by Chrome on each connectNative).
//!
//! - On Unix the MCP server listens on a 0600 Unix-domain socket inside a
//!   private 0700 runtime directory, and writes the socket path + a per-run
//!   secret to a lock file next to it. A filesystem socket has no listening
//!   port for other processes to reach, and its 0600 mode plus the private
//!   directory keep other users out.
//! - On Windows (no std Unix-domain sockets) the server keeps a loopback TCP
//!   socket on an ephemeral port, published the same way in the lock file.
//! - The native host reads the lock file on startup and connects. Authentication
//!   is an HMAC-SHA256 challenge-response ([`server_handshake`] /
//!   [`client_handshake`]): the server sends a random nonce, the client replies
//!   with HMAC(secret, nonce). The secret never travels on the wire, and a fresh
//!   nonce per connection makes a captured response useless to replay.
//! - Before that handshake, each end kernel-attests the other ([`attest_peer`]):
//!   it asks the kernel who the peer is and requires the peer to be running the
//!   same executable image as itself. On Linux that identity is the SHA256 of
//!   `/proc/<pid>/exe`; on macOS it is the code-directory hash of the peer's
//!   running image, taken from its kernel audit token via the Security framework
//!   (running-image-bound, so it survives a re-open TOCTOU). Only another
//!   instance of this exact binary can drive the bridge; a different same-user
//!   program is rejected at accept, before it can attempt the handshake. See
//!   ADR-0020.
//!
//! Layout (one concern per submodule; the public API is re-exported here so
//! callers keep using `ipc::...`):
//! - [`socket`]: the bridge transport (Unix-domain socket / loopback TCP).
//! - [`lockfile`]: the published runtime state (lock file, runtime dir, the
//!   cross-process [`RuntimeMutex`], bind-and-publish).
//! - [`peercred`]: kernel-reported peer credentials (uid/pid) and process
//!   liveness.
//! - [`attest`]: executable-identity attestation policy (self vs peer vs pid)
//!   and the attested-terminate takeover path.
//! - [`handshake`]: the HMAC challenge-response and browser-label validation.
//! - [`rand`]: OS-CSPRNG secrets and hex encoding.
//! - [`platform`]: the per-OS mechanisms (Linux `/proc` hashing + SO_PEERCRED,
//!   macOS Security-framework code signing + LOCAL_PEERPID, Windows process
//!   handles + BCrypt), kept in one file per OS so the policy modules above
//!   stay free of scattered cfg-gates.

mod attest;
mod handshake;
mod lockfile;
mod peercred;
mod platform;
mod rand;
mod socket;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use attest::{attest_and_terminate, attest_peer, attest_pid, ensure_own_identity};
pub use handshake::{client_handshake, server_handshake, validate_label};
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

pub(crate) use lockfile::runtime_dir;
pub(crate) use rand::{generate_secret, hex_encode};
