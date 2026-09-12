//! The published runtime state: the per-user runtime directory, the lock file
//! naming the live server (endpoint + per-run secret + pid), and the
//! cross-process [`RuntimeMutex`] that serializes every mutation of that
//! shared state.

use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::peercred::pid_is_alive;
use super::socket::{listen, BridgeListener};

/// Per-process runtime info the MCP server publishes for the native host.
///
/// Deliberately NOT `deny_unknown_fields`, unlike the other on-disk records (ADR-0025): an older build still
/// installed during an upgrade reads the lock a newer one wrote, and a strict parser would take the bridge down.
/// Safe because the lock file is DISCOVERY, not authorization: every connection still passes the HMAC handshake
/// (and, on Unix, the peer-UID check; on Linux and macOS, image attestation), so an unknown field admits nobody.
///
/// ```text
/// adding a field                         -> only such that old readers stay correct ignoring it
/// a change old readers must NOT survive  -> a NEW filename (run.lock -> run.v2.lock); old binaries see no lock
///                                           and fail closed instead of misreading
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockFile {
    /// How the native host reaches the server. On Unix this is the filesystem
    /// path of the 0600 Unix-domain socket; on Windows it is the loopback
    /// endpoint `127.0.0.1:<port>`.
    pub endpoint: String,
    /// Random token the native host must echo back on connect. The lock file
    /// and (on Unix) the socket are 0600, so this guards against another local
    /// user's stray process connecting.
    pub secret: String,
    /// PID of the MCP server process that owns the socket, for diagnostics.
    pub pid: u32,
}

/// Per-user runtime/data directory holding the lock file and (on Unix) the
/// bridge socket. Created 0700 on Unix so no other user can enter it. Also
/// holds the enrollment policy config (`src/packages/core/src/enclave.rs`).
pub(crate) fn runtime_dir() -> PathBuf {
    #[cfg(windows)]
    {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("USERPROFILE")
                    .map(PathBuf::from)
                    .map(|p| p.join("AppData/Local"))
            })
            .unwrap_or_else(std::env::temp_dir);
        let dir = base.join("chromium-bridge");
        let _ = fs::create_dir_all(&dir);
        dir
    }

    #[cfg(target_os = "macos")]
    {
        let dir = if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
            PathBuf::from(xdg).join("chromium-bridge")
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            PathBuf::from(home).join("Library/Application Support/chromium-bridge")
        };
        harden_runtime_dir(&dir);
        dir
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let dir = if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
            PathBuf::from(xdg).join("chromium-bridge")
        } else if let Some(xdg_cache) = std::env::var_os("XDG_CACHE_HOME") {
            PathBuf::from(xdg_cache).join("chromium-bridge")
        } else if let Some(home) = std::env::var_os("HOME") {
            PathBuf::from(home).join(".cache/chromium-bridge")
        } else {
            std::env::temp_dir().join(format!("chromium-bridge-{}", crate::sys::effective_uid()))
        };
        harden_runtime_dir(&dir);
        dir
    }
}

/// Directory hardening for [`runtime_dir`], which returns a path, not a `Result`: a directory that cannot be created
/// or secured (a pre-planted symlink at the leaf, an unwritable parent) is logged loudly and the path still returned,
/// losing only the directory-level 0700 tightening because every security-bearing file inside guards its own creation
/// (0600 + `O_NOFOLLOW` opens, exclusive creates, see [`crate::fsguard`]) and fails closed on its own error. Chmod
/// through the symlink is NOT attempted: chmodding an attacker-chosen path is the primitive fsguard exists to remove.
#[cfg(unix)]
fn harden_runtime_dir(dir: &std::path::Path) {
    if let Err(e) = crate::fsguard::ensure_private_dir(dir) {
        log_warn!(
            "ipc",
            "could not secure the runtime directory {}: {e}",
            dir.display()
        );
    }
}

/// Upper bound on the lock file's size when reading it back. The file is a
/// few hundred bytes of JSON; anything bigger is not ours (e.g. a same-user
/// process planted a huge file at the path) and is rejected instead of being
/// slurped into memory.
const LOCK_MAX_BYTES: usize = 64 * 1024;

impl LockFile {
    /// Path of the lock file in the per-user runtime directory.
    pub fn path() -> PathBuf {
        runtime_dir().join("run.lock")
    }

    /// Module-private on purpose: the lock file is mutated only inside this module's [`RuntimeMutex`] critical
    /// sections ([`listen_and_publish`]), after ownership is established. A wider visibility would allow lock-free
    /// writes, the interleaving class [`cleanup_stale_lock`] exists to prevent.
    fn write(&self) -> io::Result<()> {
        let bytes = serde_json::to_vec(self)?;
        write_private_atomic(&Self::path(), &bytes)
    }

    pub fn read() -> io::Result<Option<Self>> {
        let Some(bytes) = read_capped(&Self::path(), LOCK_MAX_BYTES)? else {
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
        #[cfg(unix)]
        let _ = fs::remove_file(super::socket::socket_path());
        let _ = fs::remove_file(Self::path());
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
struct RuntimeMutex(#[allow(dead_code)] fs::File);

/// Witness that the cross-process [`RuntimeMutex`] is held: zero-sized and constructible only in this module, minted
/// by [`with_runtime_lock`] while its guard is alive and lent by reference under a higher-ranked closure signature, so
/// a token cannot outlive the hold it proves. Mutators of lock-guarded trust state (the `*_locked` family in
/// `crate::revocation`, `Allowlist::write`) demand `&RuntimeLockToken`, so "caller must hold the runtime lock" is a
/// compile error to violate, not a comment.
pub struct RuntimeLockToken(());

impl RuntimeMutex {
    fn acquire() -> io::Result<RuntimeMutex> {
        let path = runtime_dir().join("run.mutex");
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
            //   Windows                   -> no attestation (SECURITY.md "Platform support"); liveness-only
            #[cfg(any(target_os = "linux", target_os = "macos"))]
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
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            return Ok(PublishOutcome::LostRace(cur));
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

/// Read a small file in full, bounded by `max` bytes. Returns `Ok(None)` when
/// the file does not exist; fails with `InvalidData` when it exceeds the cap,
/// reading at most `max + 1` bytes rather than the whole oversized file.
pub(crate) fn read_capped(path: &std::path::Path, max: usize) -> io::Result<Option<Vec<u8>>> {
    let f = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    // Read up to max+1 bytes so an over-cap file is distinguishable from one
    // of exactly max bytes. An unrepresentable limit fails closed.
    let cap = u64::try_from(max)
        .ok()
        .and_then(|c| c.checked_add(1))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "size cap out of range"))?;
    let mut bytes = Vec::new();
    f.take(cap).read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "lock file exceeds the size cap",
        ));
    }
    Ok(Some(bytes))
}

/// Write `bytes` to `path` atomically via a same-directory temp file. On Unix
/// the temp file is created exclusively (O_EXCL) with mode 0600: any
/// pre-planted file at the temp path is removed first and never reused, so a
/// looser mode on a planted file can never carry over to the secret-bearing
/// lock. If the removal races with a re-plant, `create_new` fails closed
/// instead of adopting the foreign file.
pub(crate) fn write_private_atomic(path: &std::path::Path, bytes: &[u8]) -> io::Result<()> {
    let mut tmp = path.to_path_buf();
    tmp.set_extension("lock.tmp");
    #[cfg(unix)]
    {
        let _ = fs::remove_file(&tmp);
        let mut f = crate::fsguard::create_private_excl(&tmp)?;
        f.write_all(bytes)?;
        f.flush()?;
    }
    #[cfg(windows)]
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.flush()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
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
    fn lock_path_has_expected_filename() {
        assert_eq!(LockFile::path().file_name().unwrap(), "run.lock");
    }

    #[test]
    fn runtime_lock_token_is_zero_sized() {
        // The token is a pure compile-time witness; holding or passing one
        // must cost nothing at runtime.
        assert_eq!(std::mem::size_of::<RuntimeLockToken>(), 0);
    }

    /// A scratch directory for filesystem tests, unique per test so parallel
    /// tests never collide, removed on drop.
    struct ScratchDir(PathBuf);

    impl ScratchDir {
        fn new(test: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "chromium-bridge-test-{}-{test}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).unwrap();
            ScratchDir(dir)
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn read_capped_rejects_an_oversized_file_and_passes_a_small_one() {
        let dir = ScratchDir::new("read-capped");
        let path = dir.0.join("run.lock");

        // Missing file is a clean None, not an error.
        assert!(read_capped(&path, LOCK_MAX_BYTES).unwrap().is_none());

        // A file over the cap is rejected without being read in full.
        fs::write(&path, vec![b'x'; LOCK_MAX_BYTES + 1]).unwrap();
        let err = read_capped(&path, LOCK_MAX_BYTES).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // A normal-sized file reads back verbatim.
        fs::write(&path, b"{\"pid\":1}").unwrap();
        assert_eq!(
            read_capped(&path, LOCK_MAX_BYTES).unwrap().unwrap(),
            b"{\"pid\":1}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn lock_write_never_reuses_a_preplanted_loose_tmp() {
        use std::os::unix::fs::PermissionsExt;

        let dir = ScratchDir::new("preplanted-tmp");
        let path = dir.0.join("run.lock");
        let mut tmp = path.clone();
        tmp.set_extension("lock.tmp");

        // An attacker pre-plants a world-readable temp file at our temp path.
        // The old open(create=true) would reuse it, keeping its 0644 mode on
        // the secret-bearing lock after the rename.
        fs::write(&tmp, b"planted").unwrap();
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644)).unwrap();

        write_private_atomic(&path, b"{\"secret\":\"s\"}").unwrap();

        // The planted file was replaced, not adopted: content is ours and no
        // group/other bits survive.
        assert_eq!(fs::read(&path).unwrap(), b"{\"secret\":\"s\"}");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o077, 0, "lock mode {mode:o} leaks group/other bits");
        assert!(!tmp.exists());
    }
}
