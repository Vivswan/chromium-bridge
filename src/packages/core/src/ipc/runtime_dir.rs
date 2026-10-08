//! [`RuntimeDir`] is the one place the per-user runtime directory is resolved, so every path under it
//! inherits the socket-length check.

use std::io;
use std::path::{Path, PathBuf};

/// `crate::test_support` points tests at it, and tests/protocol/harness.py mirrors the name by hand
/// (`runtime_dir_var`).
#[cfg(unix)]
pub(crate) const RUNTIME_DIR_VAR: &str = "XDG_RUNTIME_DIR";
#[cfg(windows)]
pub(crate) const RUNTIME_DIR_VAR: &str = "LOCALAPPDATA";

/// The bridge socket's name under the runtime dir. Unix only: Windows binds a named pipe whose name hashes the
/// directory (`PipeName::for_broker`), so no path length applies there.
#[cfg(unix)]
const SOCKET_FILENAME: &str = "run.sock";

/// The longest socket path `bind` accepts: `sun_path` less the terminator std keeps. `sun_path` is the last
/// field of `sockaddr_un` on every Unix this crate builds for, so its capacity is what follows its offset.
#[cfg(unix)]
pub(crate) const SOCKET_PATH_MAX: usize = std::mem::size_of::<libc::sockaddr_un>()
    - std::mem::offset_of!(libc::sockaddr_un, sun_path)
    - 1;

/// On Unix, a directory whose socket path fits `sun_path`: the check runs at resolution, so no path derived
/// from a `RuntimeDir` fails `bind` on length, and every consumer refuses with one error naming the path, its
/// length, and the limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeDir(PathBuf);

impl RuntimeDir {
    /// Nothing is created or hardened here: `doctor --paths` prints this alone, so the protocol harness can
    /// refuse a misrouted binary before it touches the real runtime dir. Every writer goes through
    /// [`ensure`](Self::ensure).
    pub(crate) fn resolve() -> io::Result<RuntimeDir> {
        let dir = resolve_from_env();
        #[cfg(unix)]
        refuse_unbindable_socket(&dir)?;
        Ok(RuntimeDir(dir))
    }

    /// [`resolve`](Self::resolve), then created, 0700 on Unix so no other user can enter it. A directory that
    /// cannot be created or secured is refused: nothing is written beside a planted symlink or into a parent we
    /// cannot own.
    pub(crate) fn ensure() -> io::Result<RuntimeDir> {
        let dir = Self::resolve()?;
        #[cfg(windows)]
        let created = std::fs::create_dir_all(&dir.0);
        #[cfg(unix)]
        let created = crate::fsguard::ensure_private_dir(&dir.0);
        created.map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "runtime dir refused: {} could not be created and secured ({e}); point \
                     {RUNTIME_DIR_VAR} at a directory this user can own",
                    dir.0.display()
                ),
            )
        })?;
        Ok(dir)
    }

    pub(crate) fn as_path(&self) -> &Path {
        &self.0
    }

    pub(crate) fn join(&self, file: &str) -> PathBuf {
        self.0.join(file)
    }

    #[cfg(unix)]
    pub(crate) fn socket_path(&self) -> PathBuf {
        self.join(SOCKET_FILENAME)
    }
}

fn resolve_from_env() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var_os(RUNTIME_DIR_VAR)
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join("AppData/Local"))
            })
            .unwrap_or_else(std::env::temp_dir)
            .join("genkan")
    }

    #[cfg(target_os = "macos")]
    {
        match std::env::var_os(RUNTIME_DIR_VAR) {
            Some(xdg) => PathBuf::from(xdg).join("genkan"),
            None => {
                let home = std::env::var_os("HOME").unwrap_or_else(|| "/tmp".into());
                PathBuf::from(home).join("Library/Application Support/genkan")
            }
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(xdg) = std::env::var_os(RUNTIME_DIR_VAR) {
            PathBuf::from(xdg).join("genkan")
        } else if let Some(xdg_cache) = std::env::var_os("XDG_CACHE_HOME") {
            PathBuf::from(xdg_cache).join("genkan")
        } else if let Some(home) = std::env::var_os("HOME") {
            PathBuf::from(home).join(".cache/genkan")
        } else {
            std::env::temp_dir().join(format!("genkan-{}", crate::sys::effective_uid()))
        }
    }
}

#[cfg(unix)]
fn refuse_unbindable_socket(dir: &Path) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let sock = dir.join(SOCKET_FILENAME);
    let len = sock.as_os_str().as_bytes().len();
    if len > SOCKET_PATH_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "runtime dir refused: the bridge socket path {} is {len} bytes, over the \
                 {SOCKET_PATH_MAX}-byte sun_path limit; point {RUNTIME_DIR_VAR} at a shorter directory",
                sock.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::UnixListener;

    use super::*;
    use crate::test_support::scratch_runtime_dir;

    /// External fact: the kernel takes a socket path of exactly [`SOCKET_PATH_MAX`] bytes and refuses one byte
    /// more, so the refusal is neither looser nor stricter than `bind`, and the limit it names is the real one.
    /// The over-long case is the harness incident: a `TMPDIR` deep enough that `run.sock` no longer fits.
    #[test]
    fn a_runtime_dir_whose_socket_path_overruns_sun_path_is_refused_by_name() {
        let guard = scratch_runtime_dir();
        let fixed = guard.root().join("x").join("genkan").join(SOCKET_FILENAME);
        let pad_to_fit = SOCKET_PATH_MAX
            .checked_sub(fixed.as_os_str().as_bytes().len())
            .and_then(|room| room.checked_add(1))
            .expect("the scratch root leaves no room to stage a socket path at the limit");

        let at_limit = guard.point_at_absent(&"x".repeat(pad_to_fit));
        let dir = RuntimeDir::ensure().expect("a socket path at the limit resolves");
        assert_eq!(
            dir.as_path(),
            at_limit.join("genkan"),
            "the resolved dir hangs off the variable"
        );
        assert_eq!(
            dir.socket_path().as_os_str().as_bytes().len(),
            SOCKET_PATH_MAX,
            "the staged socket path sits exactly at the limit"
        );
        UnixListener::bind(dir.socket_path()).expect("bind takes a path at the limit");

        let over = guard.point_at_absent(&"x".repeat(pad_to_fit.checked_add(1).unwrap()));
        let sock = over.join("genkan").join(SOCKET_FILENAME);
        let err = RuntimeDir::resolve().expect_err("one byte over the limit is refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
        let text = err.to_string();
        for needle in [
            sock.display().to_string(),
            format!("is {} bytes", SOCKET_PATH_MAX.checked_add(1).unwrap()),
            format!("{SOCKET_PATH_MAX}-byte sun_path limit"),
            RUNTIME_DIR_VAR.to_string(),
        ] {
            assert!(text.contains(&needle), "{text:?} does not name {needle:?}");
        }
        std::fs::create_dir_all(sock.parent().unwrap()).unwrap();
        UnixListener::bind(&sock)
            .expect_err("bind refuses the same path, so the limit is the kernel's");
    }
}
