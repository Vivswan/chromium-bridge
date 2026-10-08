//! Binding is reached only through [`super::lockfile::listen_and_publish`], which serializes
//! unlink-bind-publish against other instances.

use std::io;

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(windows)]
use std::time::Duration;

use super::lockfile::{cleanup_stale_lock, read_lock_or_err, LockFile};
#[cfg(windows)]
use super::platform::windows::{pipe, PipeName};
use super::rand::generate_secret;
use super::runtime_dir::RuntimeDir;

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

#[cfg(unix)]
pub(super) fn listen() -> io::Result<(BridgeListener, LockFile)> {
    use std::fs;

    let sock = RuntimeDir::ensure()?.socket_path();
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
    let name = PipeName::for_broker(RuntimeDir::ensure()?.as_path(), std::process::id());
    let listener = pipe::PipeListener::bind(&name)?;
    let lf = LockFile {
        endpoint: name.into(),
        secret: generate_secret()?,
        pid: std::process::id(),
    };
    Ok((listener, lf))
}

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
    let name = PipeName::try_from(lf.endpoint.as_str())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("lock endpoint: {e}")))?;
    pipe::PipeStream::connect(&name, CONNECT_TIMEOUT).inspect_err(|_| {
        cleanup_stale_lock(&lf);
    })
}

/// Connects and drops without a byte; the pipe listener's ERROR_NO_DATA path exists for exactly this.
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
            &std::env::temp_dir().join(format!("genkan-pair-{serial}")),
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
