//! Every mutation of the published runtime state (lock file, socket) runs under [`RuntimeMutex`];
//! [`LockFile`] is the cross-build on-disk contract.

use std::fs;
use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::peercred::pid_is_alive;
use super::runtime_dir::RuntimeDir;
use super::socket::{listen, BridgeListener};
use crate::fsguard::{read_capped, write_private_atomic};

/// Not `deny_unknown_fields`, unlike the other on-disk records: during an upgrade an older build may read the
/// lock a newer one wrote. Safe because the lock is discovery, not authorization: every connection still
/// passes the same-user gate, attestation, and the HMAC handshake. docs/security/rationale.md records the
/// decision.
///
/// ```text
/// adding a field                         -> old readers must stay correct ignoring it
/// a change old readers must not survive  -> a new filename, so old binaries see no lock and fail closed
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockFile {
    /// Read by the native host: the socket path on Unix, the pipe name on Windows
    /// (`\\.\pipe\chromium-bridge-<hash>-<pid>`).
    pub endpoint: String,
    /// Keys the HMAC handshake; readable by this user alone (0600), so a process that cannot read it cannot
    /// answer.
    pub secret: String,
    /// The owner: liveness, takeover attestation, and the ownership check before any cleanup key on it.
    pub pid: u32,
}

const LOCK_MAX_BYTES: usize = 64 * 1024;

/// The docs state this name; check-docs-literals holds them to it through the generated contract.
pub const LOCK_FILENAME: &str = "run.lock";

impl LockFile {
    /// Path of the lock file in the per-user runtime directory, which is created on the way.
    pub fn path() -> io::Result<PathBuf> {
        Ok(Self::path_in(&RuntimeDir::ensure()?))
    }

    pub(crate) fn path_in(runtime_dir: &RuntimeDir) -> PathBuf {
        runtime_dir.join(LOCK_FILENAME)
    }

    /// Private so no write can happen outside a [`RuntimeMutex`] section; [`cleanup_stale_lock`] exists for
    /// exactly that interleaving.
    fn write(&self) -> io::Result<()> {
        let bytes = serde_json::to_vec(self)?;
        write_private_atomic(&Self::path()?, &bytes)
    }

    pub fn read() -> io::Result<Option<Self>> {
        let Some(bytes) = read_capped(&Self::path()?, LOCK_MAX_BYTES)? else {
            return Ok(None);
        };
        let lf: LockFile = serde_json::from_slice(&bytes).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("lockfile decode: {e}"))
        })?;
        Ok(Some(lf))
    }

    /// Private like [`write`](Self::write): every caller first proves under the [`RuntimeMutex`] that the
    /// on-disk state is its own: an unguarded remove deletes a live server's files.
    fn remove() {
        let Ok(dir) = RuntimeDir::ensure() else {
            return;
        };
        #[cfg(unix)]
        let _ = fs::remove_file(dir.socket_path());
        let _ = fs::remove_file(Self::path_in(&dir));
    }

    /// After a takeover the paths belong to the successor, so an exiting server removes them only while the
    /// lock still names it, checked and removed under the [`RuntimeMutex`]; anything unprovable is left for
    /// the next start to clear.
    pub fn remove_if_owned() {
        let Ok(_guard) = RuntimeMutex::acquire() else {
            return;
        };
        if matches!(Self::read(), Ok(Some(lf)) if lf.pid == std::process::id()) {
            Self::remove();
        }
    }
}

/// Keeps our own processes from clobbering each other during takeovers and reconnects. Not a defense against
/// a hostile same-user process, which can delete the files directly; the boundary against other users is the
/// 0700 directory.
struct RuntimeMutex(
    #[expect(
        dead_code,
        reason = "held only for the kernel lock its Drop releases, never read"
    )]
    fs::File,
);

/// Witness that the [`RuntimeMutex`] is held, minted only by [`with_runtime_lock`] and lent by reference so
/// it cannot outlive the hold. The lock-guarded mutators (`Trust::mutate_locked` and `mutate_locked_with`
/// in trust.rs, `EnrollmentKey::mint` and `revoke` in enclave/key.rs) demand it.
pub struct RuntimeLockToken(());

impl RuntimeMutex {
    fn acquire() -> io::Result<RuntimeMutex> {
        let path = RuntimeDir::ensure()?.join("run.mutex");
        let f = crate::fsguard::open_private_rw(&path)?;
        f.lock()?; // blocks until exclusive; released on drop (close)
        Ok(RuntimeMutex(f))
    }
}

pub enum PublishOutcome {
    Published(BridgeListener, LockFile),
    LostRace(LockFile),
}

/// One critical section under the [`RuntimeMutex`]: if another live server published since the caller last
/// looked, nothing is touched and `LostRace` names it, since binding anyway would unlink that server's fresh
/// socket.
pub fn listen_and_publish() -> io::Result<PublishOutcome> {
    let _guard = RuntimeMutex::acquire()?;
    if let Ok(Some(cur)) = LockFile::read() {
        if cur.pid != std::process::id() && pid_is_alive(cur.pid) {
            // A live pid alone does not make the lock current: after a crash the OS may have reused the pid for an
            // unrelated process. Defer (LostRace) only to a pid PROVEN to run our own binary; any other pid is never
            // signaled and its lock is superseded under this mutex.
            //   PermissionDenied          -> a different binary (a reused pid, or another release of ours after an upgrade)
            //   other attest error        -> unmeasurable, commonly a pid reused by another user's process; deferring
            //                                to it would brick startup for as long as that pid lives
            //   unverifiable live server  -> keeps its connections and merely stops being named; the extension
            //                                converges to the new server on reconnect
            match super::attest::attest_pid(cur.pid) {
                Ok(()) => return Ok(PublishOutcome::LostRace(cur)),
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => log_warn!(
                    "ipc",
                    "lock file names live pid {}, which runs a different binary; \
                     superseding the lock",
                    cur.pid
                ),
                Err(e) => log_warn!(
                    "ipc",
                    "lock file names live pid {} whose identity could not be verified \
                     ({e}); superseding the lock",
                    cur.pid
                ),
            }
        }
    }
    LockFile::remove();
    let (listener, lf) = listen()?;
    lf.write()?;
    Ok(PublishOutcome::Published(listener, lf))
}

/// See [`RuntimeMutex`]; the token lent to `f` proves the hold to the mutators it calls.
pub(crate) fn with_runtime_lock<T>(
    f: impl FnOnce(&RuntimeLockToken) -> io::Result<T>,
) -> io::Result<T> {
    let _guard = RuntimeMutex::acquire()?;
    f(&RuntimeLockToken(()))
}

pub(super) fn read_lock_or_err() -> io::Result<LockFile> {
    LockFile::read()?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "chromium-bridge lock file not found - is the MCP server running?",
        )
    })
}

/// The lock goes only when, re-read under the [`RuntimeMutex`], it is still the one dialed and its owner is
/// dead: an unconditional remove on a transient connect failure deletes a LIVE server's files, and without
/// the re-read a new server could publish between the liveness check and the remove.
pub(super) fn cleanup_stale_lock(dialed: &LockFile) {
    let Ok(_guard) = RuntimeMutex::acquire() else {
        return;
    };
    if matches!(
        LockFile::read(),
        Ok(Some(cur)) if cur.pid == dialed.pid
            && cur.endpoint == dialed.endpoint
            && !pid_is_alive(cur.pid)
    ) {
        LockFile::remove();
    }
}
