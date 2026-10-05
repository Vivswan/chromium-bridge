//! Test-only support shared across the crate's unit-test modules.
//!
//! The scratch runtime-dir guard lives HERE, once, because the resource it guards is process-global:
//! [`crate::ipc::RuntimeDir`] resolves from the [`RUNTIME_DIR_VAR`] environment variable on every call, and
//! `std::env::set_var` mutates the whole process. One crate-wide lock, held for the guard's whole lifetime, is
//! the honest guard for a process-global variable.
//!
//! ```text
//! cargo-nextest, one process per test       -> any lock is a no-op
//! plain `cargo test`, parallel threads      -> real serialization needed (the coverage job's mode)
//! a per-module lock                         -> two modules' guards race, one re-pointing the variable mid-test
//! ```

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

use tempfile::TempDir;

use crate::ipc::RUNTIME_DIR_VAR;

/// The one crate-wide lock over the runtime-dir environment variable.
fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Points [`crate::ipc::RuntimeDir`] at a fresh scratch directory for one test, restoring the previous
/// environment and removing the directory on drop, so no test reads or writes the user's real runtime state.
/// Holds the crate-wide env lock for its whole lifetime (module docs above).
pub(crate) struct RuntimeDirGuard {
    dir: TempDir,
    prev: Option<OsString>,
    _serial: MutexGuard<'static, ()>,
}

/// A fresh [`RuntimeDirGuard`]. The directory sits directly under the OS temp dir under a short name: the
/// bridge socket path beneath it must fit `sun_path`, and [`crate::ipc::RuntimeDir`] refuses one that does not.
pub(crate) fn scratch_runtime_dir() -> RuntimeDirGuard {
    let serial = env_lock().lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::Builder::new().prefix("bbt-").tempdir().unwrap();
    let prev = std::env::var_os(RUNTIME_DIR_VAR);
    std::env::set_var(RUNTIME_DIR_VAR, dir.path());
    RuntimeDirGuard {
        dir,
        prev,
        _serial: serial,
    }
}

impl RuntimeDirGuard {
    /// The scratch root, which [`point_at_absent`](Self::point_at_absent) leaves in place while it re-points the
    /// variable beneath it. Unix only, like its one caller, the `sun_path` guard test in `ipc/runtime_dir.rs`.
    #[cfg(unix)]
    pub(crate) fn root(&self) -> &std::path::Path {
        self.dir.path()
    }

    /// Re-point the runtime dir at `name` under the scratch dir WITHOUT creating it, for a test proving that a
    /// resolver leaves an absent dir absent, or staging a path of a chosen length. Drop still restores the
    /// environment and removes the scratch dir.
    pub(crate) fn point_at_absent(&self, name: &str) -> PathBuf {
        let absent = self.dir.path().join(name);
        std::env::set_var(RUNTIME_DIR_VAR, &absent);
        absent
    }
}

impl Drop for RuntimeDirGuard {
    fn drop(&mut self) {
        match &self.prev {
            Some(v) => std::env::set_var(RUNTIME_DIR_VAR, v),
            None => std::env::remove_var(RUNTIME_DIR_VAR),
        }
    }
}
