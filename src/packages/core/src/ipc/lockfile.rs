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
/// Deliberately NOT `deny_unknown_fields`, unlike the other on-disk records
/// (decided in ADR-0025): the lock file is the one file read across BINARY
/// VERSIONS at the same instant — during an upgrade, a still-installed older
/// build (Chrome keeps spawning the manifest's host; a harness keeps spawning
/// its configured server) reads the lock a newer broker wrote, and a strict
/// parser would take the whole bridge down for the upgrade window if a field
/// were ever added. Leniency is safe here because the lock file is DISCOVERY,
/// not authorization: whatever it says, every connection still passes the
/// peer-UID check, mutual attestation, and the HMAC handshake, so an unknown
/// field can admit nobody. Forward-compat rule: fields may only be added such
/// that old readers stay correct ignoring them; a change old readers must NOT
/// survive gets a NEW FILENAME (`run.lock` -> `run.v2.lock`), so old binaries
/// see "no lock" and fail closed to no-bridge instead of misreading.
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
        ensure_private_dir(&dir);
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
        ensure_private_dir(&dir);
        dir
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

    pub fn write(&self) -> io::Result<()> {
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

    pub fn remove() {
        #[cfg(unix)]
        let _ = fs::remove_file(super::socket::socket_path());
        let _ = fs::remove_file(Self::path());
    }

    /// Remove the lock file (and on Unix the socket) ONLY if the on-disk lock
    /// still names this process as the owner. An exiting server must never
    /// clean up its successor's files: after a takeover the lock and socket
    /// path belong to the new server, so an instance that cannot prove
    /// ownership leaves them alone. The check-then-remove runs under the
    /// [`RuntimeMutex`], so it cannot interleave with a successor's
    /// [`listen_and_publish`] (without the mutex, a successor could publish
    /// between our read and our remove and we would delete its files).
    /// Missing or unreadable lock, or an unacquirable mutex: do nothing (fail
    /// safe - never delete what we cannot prove is ours; a stale file is
    /// cleared by the next server start).
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

impl RuntimeMutex {
    fn acquire() -> io::Result<RuntimeMutex> {
        let path = runtime_dir().join("run.mutex");
        let mut opts = fs::OpenOptions::new();
        opts.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let f = opts.open(&path)?;
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

/// Bind the bridge socket and publish the lock file as one critical section
/// under the [`RuntimeMutex`]. Re-checks the on-disk lock first: if another
/// live server published since the caller last looked (two servers starting
/// at once), nothing is touched and `LostRace` reports the current owner -
/// binding anyway would unlink that server's freshly-bound socket, the exact
/// takeover bug this serialization exists to prevent. "Another live server"
/// means a pid that both is alive and attests as our own binary
/// ([`super::attest::attest_pid`]); stale state - a dead owner, or a lock
/// whose pid was reused by some unrelated process - is cleared before binding.
pub fn listen_and_publish() -> io::Result<PublishOutcome> {
    let _guard = RuntimeMutex::acquire()?;
    if let Ok(Some(cur)) = LockFile::read() {
        if cur.pid != std::process::id() && pid_is_alive(cur.pid) {
            // A live pid alone does not make the lock current: the pid is a
            // number read from disk, and after a crash the OS may have reused
            // it for an unrelated process. Defer (LostRace) only to a pid
            // PROVEN to be running our own binary. A pid that does not attest
            // is never signaled and its lock is superseded (removed below,
            // under this mutex) rather than obeyed. That covers both a
            // mismatch (a reused pid, or a different release of this binary
            // after an upgrade) and an unmeasurable target (commonly a pid
            // reused by another user's process, whose image we cannot read -
            // deferring to it would brick startup for as long as that pid
            // lives). If the owner really was a live server we could not
            // verify, it is not taken down: it keeps its existing connections
            // and merely stops being named by the lock, and the extension
            // converges to the new server on its next reconnect. Windows has
            // no attestation (see SECURITY.md "Platform support") and keeps
            // the liveness-only behavior.
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
/// Not a defense against a hostile same-user process (it can delete the files
/// directly); the boundary against other users is the 0700 directory.
pub(crate) fn with_runtime_lock<T>(f: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    let _guard = RuntimeMutex::acquire()?;
    f()
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
    let mut bytes = Vec::new();
    f.take(max as u64 + 1).read_to_end(&mut bytes)?;
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
        use std::os::unix::fs::OpenOptionsExt;
        let _ = fs::remove_file(&tmp);
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
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
    // Unix rename atomically replaces an existing destination. Windows'
    // std::fs::rename does not, so remove a stale destination first. That
    // creates a tiny not-found window, but the extension's reconnect loop
    // retries after 2 seconds and can never observe a half-written JSON
    // file because all bytes were flushed to the temporary file first.
    #[cfg(windows)]
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(unix)]
fn ensure_private_dir(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;

    if fs::create_dir_all(path).is_ok() {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }
}

pub(super) fn read_lock_or_err() -> io::Result<LockFile> {
    LockFile::read()?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "chromium-bridge lock file not found — is the MCP server running?",
        )
    })
}

/// After a failed connect: remove the lock (and socket) ONLY when, re-checked
/// under the [`RuntimeMutex`], the on-disk lock is still the one we dialed and
/// its recorded owner is dead. An unconditional remove here used to delete a
/// LIVE server's lock and socket on any transient connect failure, taking the
/// bridge down for good; and without the mutex + re-read, a new server could
/// publish between our liveness check and the remove, losing its files the
/// same way. Anything ambiguous is left alone - a truly stale lock is also
/// cleared by the next server start.
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
