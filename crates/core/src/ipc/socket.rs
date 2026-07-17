//! The bridge transport, unified across platforms so the rest of the crate is
//! transport-agnostic: a Unix-domain socket on Unix, a loopback TCP socket on
//! Windows. Binding goes through [`super::lockfile::listen_and_publish`], which
//! serializes the unlink-bind-publish sequence against other instances.

use std::io;
#[cfg(unix)]
use std::path::PathBuf;

#[cfg(windows)]
use std::net::{TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(windows)]
use std::time::Duration;

use super::lockfile::{cleanup_stale_lock, read_lock_or_err, LockFile};
use super::rand::generate_secret;

/// The bridge listener and stream types, unified across platforms so the rest
/// of the crate is transport-agnostic: a Unix-domain socket on Unix, a loopback
/// TCP socket on Windows.
#[cfg(unix)]
pub type BridgeListener = UnixListener;
#[cfg(unix)]
pub type BridgeStream = UnixStream;
#[cfg(windows)]
pub type BridgeListener = TcpListener;
#[cfg(windows)]
pub type BridgeStream = TcpStream;

/// Path of the Unix-domain socket the server binds. Unix-only: Windows uses TCP.
#[cfg(unix)]
pub(super) fn socket_path() -> PathBuf {
    super::lockfile::runtime_dir().join("run.sock")
}

/// Server side: bind the bridge socket and return the listener plus the
/// lock-file contents to publish. Private to the ipc module: callers go through
/// [`super::lockfile::listen_and_publish`], which serializes the
/// unlink-bind-publish sequence against other instances.
#[cfg(unix)]
pub(super) fn listen() -> io::Result<(BridgeListener, LockFile)> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let sock = socket_path();
    // A leftover socket from a crashed server makes bind fail with EADDRINUSE;
    // unlink it first. Binding recreates it fresh.
    let _ = fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock)?;
    fs::set_permissions(&sock, fs::Permissions::from_mode(0o600))?;
    let lf = LockFile {
        endpoint: sock.to_string_lossy().into_owned(),
        secret: generate_secret()?,
        pid: std::process::id(),
    };
    Ok((listener, lf))
}

#[cfg(windows)]
pub(super) fn listen() -> io::Result<(BridgeListener, LockFile)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let lf = LockFile {
        endpoint: format!("127.0.0.1:{port}"),
        secret: generate_secret()?,
        pid: std::process::id(),
    };
    Ok((listener, lf))
}

/// Client side (native host): read the lock file and connect. Authentication
/// happens afterwards via [`super::handshake::client_handshake`]. On a stale
/// lock (server crashed) the connect fails fast and the lock is removed so the
/// next server start wins cleanly - see
/// [`super::lockfile::cleanup_stale_lock`] for the conditions.
#[cfg(unix)]
pub fn connect() -> io::Result<BridgeStream> {
    let lf = read_lock_or_err()?;
    UnixStream::connect(&lf.endpoint).inspect_err(|_| {
        cleanup_stale_lock(&lf);
    })
}

#[cfg(windows)]
pub fn connect() -> io::Result<BridgeStream> {
    let lf = read_lock_or_err()?;
    let addr = lf
        .endpoint
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("addr parse: {e}")))?;
    TcpStream::connect_timeout(&addr, Duration::from_secs(2)).inspect_err(|_| {
        cleanup_stale_lock(&lf);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn socket_path_sits_beside_the_lock_file() {
        assert_eq!(socket_path().file_name().unwrap(), "run.sock");
        assert_eq!(socket_path().parent(), LockFile::path().parent());
    }
}
