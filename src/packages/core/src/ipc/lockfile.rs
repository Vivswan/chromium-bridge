//! The published runtime state: the lock file naming the live server (endpoint + per-run secret + pid), and
//! the cross-process [`RuntimeMutex`] that serializes every mutation of that shared state. The directory both
//! live in is [`RuntimeDir`].

use std::fs;
use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::peercred::pid_is_alive;
use super::runtime_dir::RuntimeDir;
use super::socket::{listen, BridgeListener};
use crate::fsguard::{read_capped, write_private_atomic};

/// Per-process runtime info the MCP server publishes for the native host.
///
/// Deliberately NOT `deny_unknown_fields`, unlike the other on-disk records: an older build still installed
/// during an upgrade reads the lock a newer one wrote, and a strict parser would take the bridge down.
/// Safe because the lock file is DISCOVERY, not authorization: every connection still passes the same-user gate
/// (the peer-UID check on Unix, the pipe's descriptor on Windows), image attestation, and the HMAC handshake, so an
/// unknown field admits nobody.
///
/// ```text
/// adding a field                         -> only such that old readers stay correct ignoring it
/// a change old readers must NOT survive  -> a NEW filename (run.lock -> run.v2.lock); old binaries see no lock
///                                           and fail closed instead of misreading
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockFile {
    /// How the native host reaches the server. On Unix this is the filesystem
    /// path of the 0600 Unix-domain socket; on Windows it is the pipe's name
    /// in the local pipe namespace (`\\.\pipe\chromium-bridge-<hash>-<pid>`).
    pub endpoint: String,
    /// Random token the native host must echo back on connect. The lock file
    /// and (on Unix) the socket are 0600, so this guards against another local
    /// user's stray process connecting.
    pub secret: String,
    /// PID of the MCP server process that owns the socket, for diagnostics.
    pub pid: u32,
}

/// Read cap for the lock file (a few hundred bytes of JSON); see [`read_capped`].
const LOCK_MAX_BYTES: usize = 64 * 1024;

/// The lock file's name under the runtime directory. The docs state it (check-docs-literals holds them to
/// this value through the generated contract), and a wire change old readers must not survive renames it.
pub const LOCK_FILENAME: &str = "run.lock";

impl LockFile {
    /// Path of the lock file in the per-user runtime directory, which is created on the way.
    pub fn path() -> io::Result<PathBuf> {
        Ok(Self::path_in(&RuntimeDir::ensure()?))
    }

    /// The lock's place inside whatever runtime dir it is handed, resolved or created.
    pub(crate) fn path_in(runtime_dir: &RuntimeDir) -> PathBuf {
        runtime_dir.join(LOCK_FILENAME)
    }

    /// Module-private on purpose: the lock file is mutated only inside this module's [`RuntimeMutex`] critical
    /// sections ([`listen_and_publish`]), after ownership is established. A wider visibility would allow lock-free
    /// writes, the interleaving class [`cleanup_stale_lock`] exists to prevent.
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

    /// Remove the lock file and (on Unix) the socket, unconditionally.
    /// Module-private on purpose, like [`write`](Self::write): every caller
    /// must first prove under the [`RuntimeMutex`] that the on-disk state is
    /// its own to clear ([`remove_if_owned`](Self::remove_if_owned),
    /// [`cleanup_stale_lock`], [`listen_and_publish`]); an unguarded remove
    /// once deleted a live server's files.
    fn remove() {
        let Ok(dir) = RuntimeDir::ensure() else {
            return;
        };
        #[cfg(unix)]
        let _ = fs::remove_file(dir.socket_path());
        let _ = fs::remove_file(Self::path_in(&dir));
    }

    /// Remove the lock file (and on Unix the socket) ONLY if the on-disk lock still names this process: after a
    /// takeover the paths belong to the successor, and an exiting server must never clean up its successor's files.
    /// The check-then-remove runs under the [`RuntimeMutex`] so a successor's [`listen_and_publish`] cannot slip
    /// between the read and the remove; anything unprovable (a missing or unreadable lock, an unacquirable mutex) is
    /// left alone for the next server start to clear.
    pub fn remove_if_owned() {
        let Ok(_guard) = RuntimeMutex::acquire() else {
            return;
        };
        if matches!(Self::read(), Ok(Some(lf)) if lf.pid == std::process::id()) {
            Self::remove();
        }
    }
}

/// Cross-process serialization of every mutation of the shared runtime state
/// (lock file + socket): kernel-enforced advisory file locking (`flock` on
/// Unix, `LockFileEx` on Windows via std's `File::lock`), so read-decide-remove
/// sequences in different processes cannot interleave. This protects our own
/// processes from clobbering each other during takeovers and reconnects; it is
/// NOT a defense against a hostile same-user process, which could always
/// delete these files directly (the boundary against other users is the 0700
/// directory).
struct RuntimeMutex(
    #[expect(
        dead_code,
        reason = "held only for the kernel lock its Drop releases, never read"
    )]
    fs::File,
);

/// Witness that the cross-process [`RuntimeMutex`] is held: zero-sized and constructible only in this module, minted
/// by [`with_runtime_lock`] while its guard is alive and lent by reference under a higher-ranked closure signature, so
/// a token cannot outlive the hold it proves. Mutators of lock-guarded trust state (the `*_locked` family in
/// `crate::revocation`, `Allowlist::write`) demand `&RuntimeLockToken`, so "caller must hold the runtime lock" is a
/// compile error to violate, not a comment.
pub struct RuntimeLockToken(());

impl RuntimeMutex {
    fn acquire() -> io::Result<RuntimeMutex> {
        let path = RuntimeDir::ensure()?.join("run.mutex");
        let f = crate::fsguard::open_private_rw(&path)?;
        f.lock()?; // blocks until exclusive; released on drop (close)
        Ok(RuntimeMutex(f))
    }
}

/// Result of [`listen_and_publish`]: either we now own the bridge (listener
/// bound and lock published), or another live server published while we were
/// preparing and the caller must decide whether to supplant it too.
pub enum PublishOutcome {
    Published(BridgeListener, LockFile),
    LostRace(LockFile),
}

/// Bind the bridge socket and publish the lock file as one critical section under the [`RuntimeMutex`], re-checking
/// the on-disk lock first: if another live server published since the caller last looked (two servers starting at
/// once), nothing is touched and `LostRace` names the owner, since binding anyway would unlink that server's
/// freshly-bound socket. Stale state (a dead owner, or a pid reused by an unrelated process) is cleared first.
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

/// Run `f` while holding the cross-process [`RuntimeMutex`], so a
/// read-modify-write of shared runtime state (the lock file, the client
/// allowlist) cannot interleave with another of our processes doing the same.
/// `f` receives a [`RuntimeLockToken`] proving the hold, to pass on to the
/// lock-requiring mutators it calls.
/// Not a defense against a hostile same-user process (it can delete the files
/// directly); the boundary against other users is the 0700 directory.
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

/// After a failed connect: remove the lock (and socket) ONLY when, re-checked under the [`RuntimeMutex`], the on-disk
/// lock is still the one we dialed and its owner is dead; anything ambiguous is left alone for the next server start
/// to clear. An unconditional remove once deleted a LIVE server's files on a transient connect failure, and without
/// the mutex + re-read a new server could publish between the liveness check and the remove.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockfile_serde_roundtrip() {
        let lf = LockFile {
            endpoint: "/tmp/chromium-bridge/run.sock".into(),
            secret: "deadbeef".into(),
            pid: 42,
        };
        let bytes = serde_json::to_vec(&lf).unwrap();
        let back: LockFile = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.endpoint, "/tmp/chromium-bridge/run.sock");
        assert_eq!(back.secret, "deadbeef");
        assert_eq!(back.pid, 42);
    }

    #[test]
    fn runtime_lock_token_is_zero_sized() {
        // The token is a pure compile-time witness; holding or passing one
        // must cost nothing at runtime.
        assert_eq!(std::mem::size_of::<RuntimeLockToken>(), 0);
    }
}
