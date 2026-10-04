//! The bridge transport, unified across platforms so the rest of the crate is
//! transport-agnostic: a Unix-domain socket on Unix, a named pipe on Windows.
//! Binding goes through [`super::lockfile::listen_and_publish`], which
//! serializes the unlink-bind-publish sequence against other instances.

use std::io;
#[cfg(unix)]
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(windows)]
use std::time::Duration;

use super::lockfile::{cleanup_stale_lock, read_lock_or_err, LockFile};
#[cfg(windows)]
use super::platform::windows::{pipe, PipeName};
use super::rand::generate_secret;

/// The bridge listener and stream types, unified across platforms so the rest
/// of the crate is transport-agnostic: a Unix-domain socket on Unix, a named
/// pipe on Windows.
#[cfg(unix)]
pub type BridgeListener = UnixListener;
#[cfg(unix)]
pub type BridgeStream = UnixStream;
#[cfg(windows)]
pub type BridgeListener = pipe::PipeListener;
#[cfg(windows)]
pub type BridgeStream = pipe::PipeStream;

/// How long a connecting client waits for the server to offer a free pipe
/// instance (the server is briefly between `accept`s after each connection).
#[cfg(windows)]
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Path of the Unix-domain socket the server binds. Unix-only: Windows uses a
/// named pipe, whose name `PipeName::for_broker` derives.
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

    let sock = socket_path();
    // A leftover socket from a crashed server makes bind fail with EADDRINUSE;
    // unlink it first. Binding recreates it fresh.
    let _ = fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock)?;
    crate::fsguard::set_private_mode(&sock)?;
    let lf = LockFile {
        endpoint: sock.to_string_lossy().into_owned(),
        secret: generate_secret()?,
        pid: std::process::id(),
    };
    Ok((listener, lf))
}

/// Windows: a named pipe whose every instance admits the current user alone;
/// no leftover to unlink, since a pipe name vanishes with its last instance.
#[cfg(windows)]
pub(super) fn listen() -> io::Result<(BridgeListener, LockFile)> {
    let name = PipeName::for_broker(&super::lockfile::runtime_dir(), std::process::id());
    let listener = pipe::PipeListener::bind(&name)?;
    let lf = LockFile {
        endpoint: name.into(),
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

/// Windows: the lock's endpoint is parsed as a [`PipeName`] before it is
/// opened, so a planted lock cannot point the host at a file or a remote pipe.
#[cfg(windows)]
pub fn connect() -> io::Result<BridgeStream> {
    let lf = read_lock_or_err()?;
    let name = PipeName::try_from(lf.endpoint.as_str())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("lock endpoint: {e}")))?;
    pipe::PipeStream::connect(&name, CONNECT_TIMEOUT).inspect_err(|_| {
        cleanup_stale_lock(&lf);
    })
}

/// Whether a server answers at `endpoint` (a lock file's endpoint field):
/// connect and drop, sending nothing. The `doctor` reachability probe.
pub fn probe_endpoint(endpoint: &str) -> bool {
    #[cfg(unix)]
    {
        UnixStream::connect(endpoint).is_ok()
    }
    #[cfg(windows)]
    {
        PipeName::try_from(endpoint)
            .is_ok_and(|name| pipe::PipeStream::connect(&name, Duration::from_millis(500)).is_ok())
    }
}

/// A connected pair of bridge streams, both ends in this process, for tests of
/// the peer-keyed mechanisms (credentials, attestation, handshake).
#[cfg(test)]
pub(super) fn loopback_pair() -> (BridgeStream, BridgeStream) {
    #[cfg(unix)]
    {
        UnixStream::pair().expect("socketpair")
    }
    #[cfg(windows)]
    {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let name = PipeName::for_broker(
            &std::env::temp_dir().join(format!("chromium-bridge-pair-{serial}")),
            std::process::id(),
        );
        let listener = pipe::PipeListener::bind(&name).expect("bind a test pipe");
        let client = std::thread::spawn({
            let name = name.clone();
            move || pipe::PipeStream::connect(&name, Duration::from_secs(5))
        });
        let (server, ()) = listener.accept().expect("accept the test client");
        (
            server,
            client.join().expect("client thread").expect("connect"),
        )
    }
}

// The only test here exercises the Unix socket path; on Windows the module
// would be empty, so it is gated out entirely.
#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn socket_path_sits_beside_the_lock_file() {
        assert_eq!(socket_path().file_name().unwrap(), "run.sock");
        assert_eq!(socket_path().parent(), LockFile::path().parent());
    }
}
