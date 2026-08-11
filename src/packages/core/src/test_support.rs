//! Test-only support shared across the crate's unit-test modules.
//!
//! The scratch runtime-dir guard lives HERE, once, because the resource it
//! guards is process-global: [`crate::ipc::runtime_dir`] resolves from the
//! `XDG_RUNTIME_DIR` / `LOCALAPPDATA` environment variable on every call,
//! and `std::env::set_var` mutates the whole process. cargo-nextest runs
//! each test in its own process, where any lock is a no-op; plain
//! `cargo test` (one process, parallel threads - the coverage job's mode)
//! needs real serialization, and a per-module lock only serializes that
//! module's own tests: two modules' guards race, one re-pointing the env
//! var (or deleting its scratch directory) in the middle of the other's
//! test. One crate-wide lock, held for the guard's whole lifetime, is the
//! honest guard for a process-global variable.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

#[cfg(unix)]
const RUNTIME_ENV: &str = "XDG_RUNTIME_DIR";
#[cfg(windows)]
const RUNTIME_ENV: &str = "LOCALAPPDATA";

/// The one crate-wide lock over the runtime-dir environment variable.
fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Points [`crate::ipc::runtime_dir`] at a fresh scratch directory for one
/// test, restoring the previous environment and removing the directory on
/// drop, so no test reads or writes the user's real runtime state. Holds
/// the crate-wide env lock for its whole lifetime (module docs above).
pub(crate) struct RuntimeDirGuard {
    _serial: MutexGuard<'static, ()>,
    dir: PathBuf,
    prev: Option<OsString>,
}

/// A fresh [`RuntimeDirGuard`] for `name`. Callers tag the name with their
/// module (`pending-import-first-bag-wins`, `policy-set-signed`, ...) so a
/// leftover directory from a crashed run is attributable.
pub(crate) fn scratch_runtime_dir(name: &str) -> RuntimeDirGuard {
    let serial = env_lock().lock().unwrap_or_else(|e| e.into_inner());
    let dir = std::env::temp_dir().join(format!(
        "chromium-bridge-test-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let prev = std::env::var_os(RUNTIME_ENV);
    std::env::set_var(RUNTIME_ENV, &dir);
    RuntimeDirGuard {
        _serial: serial,
        dir,
        prev,
    }
}

impl Drop for RuntimeDirGuard {
    fn drop(&mut self) {
        match &self.prev {
            Some(v) => std::env::set_var(RUNTIME_ENV, v),
            None => std::env::remove_var(RUNTIME_ENV),
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
