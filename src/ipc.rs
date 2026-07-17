//! IPC between the MCP server (long-lived) and the native-host subprocess
//! (spawned fresh by Chrome on each connectNative).
//!
//! - On Unix the MCP server listens on a 0600 Unix-domain socket inside a
//!   private 0700 runtime directory, and writes the socket path + a per-run
//!   secret to a lock file next to it. A filesystem socket has no listening
//!   port for other processes to reach, and its 0600 mode plus the private
//!   directory keep other users out.
//! - On Windows (no std Unix-domain sockets) the server keeps a loopback TCP
//!   socket on an ephemeral port, published the same way in the lock file.
//! - The native host reads the lock file on startup and connects; it presents
//!   the secret as the first NDJSON line ("hello").

use std::fs;
#[cfg(unix)]
use std::io::Read;
use std::io::{self, Write};
use std::path::PathBuf;

#[cfg(windows)]
use std::net::{TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(windows)]
use std::time::Duration;

use serde::{Deserialize, Serialize};

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

/// Per-process runtime info the MCP server publishes for the native host.
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
/// bridge socket. Created 0700 on Unix so no other user can enter it.
fn runtime_dir() -> PathBuf {
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
        let dir = base.join("browser-bridge");
        let _ = fs::create_dir_all(&dir);
        dir
    }

    #[cfg(target_os = "macos")]
    {
        let dir = if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
            PathBuf::from(xdg).join("browser-bridge")
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            PathBuf::from(home).join("Library/Application Support/browser-bridge")
        };
        ensure_private_dir(&dir);
        dir
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let dir = if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
            PathBuf::from(xdg).join("browser-bridge")
        } else if let Some(xdg_cache) = std::env::var_os("XDG_CACHE_HOME") {
            PathBuf::from(xdg_cache).join("browser-bridge")
        } else if let Some(home) = std::env::var_os("HOME") {
            PathBuf::from(home).join(".cache/browser-bridge")
        } else {
            std::env::temp_dir().join(format!("browser-bridge-{}", unsafe { libc::geteuid() }))
        };
        ensure_private_dir(&dir);
        dir
    }
}

/// Path of the Unix-domain socket the server binds. Unix-only: Windows uses TCP.
#[cfg(unix)]
fn socket_path() -> PathBuf {
    runtime_dir().join("run.sock")
}

impl LockFile {
    /// Path of the lock file in the per-user runtime directory.
    pub fn path() -> PathBuf {
        runtime_dir().join("run.lock")
    }

    pub fn write(&self) -> io::Result<()> {
        let path = Self::path();
        let mut tmp = path.clone();
        tmp.set_extension("lock.tmp");
        let bytes = serde_json::to_vec(self)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.flush()?;
        }
        #[cfg(windows)]
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.flush()?;
        }
        // Unix rename atomically replaces an existing destination. Windows'
        // std::fs::rename does not, so remove a stale destination first. That
        // creates a tiny not-found window, but the extension's reconnect loop
        // retries after 2 seconds and can never observe a half-written JSON
        // file because all bytes were flushed to the temporary file first.
        #[cfg(windows)]
        if path.exists() {
            fs::remove_file(&path)?;
        }
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    pub fn read() -> io::Result<Option<Self>> {
        match fs::read(Self::path()) {
            Ok(bytes) => {
                let lf: LockFile = serde_json::from_slice(&bytes).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("lockfile decode: {e}"))
                })?;
                Ok(Some(lf))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn remove() {
        #[cfg(unix)]
        let _ = fs::remove_file(socket_path());
        let _ = fs::remove_file(Self::path());
    }
}

#[cfg(unix)]
fn ensure_private_dir(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;

    if fs::create_dir_all(path).is_ok() {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }
}

/// Server side: bind the bridge socket and return the listener plus the
/// lock-file contents to publish. The caller `write()`s the lock file and
/// removes it on shutdown.
#[cfg(unix)]
pub fn listen() -> io::Result<(BridgeListener, LockFile)> {
    use std::os::unix::fs::PermissionsExt;

    let sock = socket_path();
    // A leftover socket from a crashed server makes bind fail with EADDRINUSE;
    // unlink it first. Binding recreates it fresh.
    let _ = fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock)?;
    fs::set_permissions(&sock, fs::Permissions::from_mode(0o600))?;
    let lf = LockFile {
        endpoint: sock.to_string_lossy().into_owned(),
        secret: generate_secret(),
        pid: std::process::id(),
    };
    Ok((listener, lf))
}

#[cfg(windows)]
pub fn listen() -> io::Result<(BridgeListener, LockFile)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let lf = LockFile {
        endpoint: format!("127.0.0.1:{port}"),
        secret: generate_secret(),
        pid: std::process::id(),
    };
    Ok((listener, lf))
}

/// The effective UID of the process on the other end of a freshly-accepted
/// Unix-domain connection. The server compares this against its own euid to
/// reject connections from other local users before authenticating them.
#[cfg(unix)]
pub fn peer_uid(stream: &BridgeStream) -> io::Result<u32> {
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();

    #[cfg(target_os = "linux")]
    {
        let mut cred = std::mem::MaybeUninit::<libc::ucred>::uninit();
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                cred.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { cred.assume_init() }.uid)
    }

    #[cfg(not(target_os = "linux"))]
    {
        // macOS and the BSDs: getpeereid yields the effective uid/gid of the
        // peer that opened the socket.
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(uid)
    }
}

fn generate_secret() -> String {
    #[cfg(windows)]
    {
        let mut buf = [0u8; 16];
        // BCRYPT_USE_SYSTEM_PREFERRED_RNG lets BCryptGenRandom use the system
        // RNG without opening and managing an algorithm-provider handle.
        let status = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                0x0000_0002,
            )
        };
        if status >= 0 {
            return hex_encode(&buf);
        }
    }

    #[cfg(unix)]
    {
        // 128 bits of entropy from the OS RNG. We avoid pulling in `rand` by
        // reading /dev/urandom directly (macOS and Linux both expose it).
        let mut buf = [0u8; 16];
        if let Ok(mut f) = fs::File::open("/dev/urandom") {
            if f.read_exact(&mut buf).is_ok() {
                return hex_encode(&buf);
            }
        }
    }
    // Fallback: mix in time + pid + a stack address. Not cryptographic, but
    // this is only the connect-back token for a per-user lock file on a
    // single-user machine.
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id() as u128;
    let stack = &t as *const _ as u128;
    hex_encode(&t.wrapping_add(pid).wrapping_add(stack).to_le_bytes())
        .chars()
        .take(32)
        .collect::<String>()
}

#[cfg(windows)]
#[link(name = "bcrypt")]
extern "system" {
    fn BCryptGenRandom(
        algorithm: *mut std::ffi::c_void,
        buffer: *mut u8,
        buffer_len: u32,
        flags: u32,
    ) -> i32;
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn read_lock_or_err() -> io::Result<LockFile> {
    LockFile::read()?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "browser-bridge lock file not found — is the MCP server running?",
        )
    })
}

/// Send the hello line (the secret) as the first NDJSON frame on a freshly
/// connected client stream.
fn send_hello(stream: &BridgeStream, secret: &str) {
    let hello = serde_json::json!({ "hello": secret });
    let mut line = serde_json::to_vec(&hello).unwrap();
    line.push(b'\n');
    let mut s = stream;
    let _ = s.write_all(&line);
    let _ = s.flush();
}

/// Client side (native host): read the lock file and connect. On a stale lock
/// (server crashed) the connect fails fast and the lock is removed so the next
/// server start wins cleanly.
#[cfg(unix)]
pub fn connect() -> io::Result<BridgeStream> {
    let lf = read_lock_or_err()?;
    let stream = match UnixStream::connect(&lf.endpoint) {
        Ok(s) => s,
        Err(e) => {
            LockFile::remove();
            return Err(e);
        }
    };
    send_hello(&stream, &lf.secret);
    Ok(stream)
}

#[cfg(windows)]
pub fn connect() -> io::Result<BridgeStream> {
    let lf = read_lock_or_err()?;
    let addr = lf
        .endpoint
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("addr parse: {e}")))?;
    let stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
        Ok(s) => s,
        Err(e) => {
            LockFile::remove();
            return Err(e);
        }
    };
    send_hello(&stream, &lf.secret);
    Ok(stream)
}

/// Validate an inbound hello line received on a freshly-accepted server
/// connection. Returns true if the secret matches the lock file.
pub fn validate_hello(hello_value: &serde_json::Value) -> bool {
    let want = match LockFile::read() {
        Ok(Some(lf)) => lf.secret,
        _ => return false,
    };
    hello_value
        .get("hello")
        .and_then(|v| v.as_str())
        .map(|s| s == want)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockfile_serde_roundtrip() {
        let lf = LockFile {
            endpoint: "/tmp/browser-bridge/run.sock".into(),
            secret: "deadbeef".into(),
            pid: 42,
        };
        let bytes = serde_json::to_vec(&lf).unwrap();
        let back: LockFile = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.endpoint, "/tmp/browser-bridge/run.sock");
        assert_eq!(back.secret, "deadbeef");
        assert_eq!(back.pid, 42);
    }

    #[test]
    fn secret_is_32_hex_chars() {
        let s = generate_secret();
        assert_eq!(s.len(), 32);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn validate_hello_rejects_missing_key() {
        // No "hello" key can never match, regardless of any on-disk lock file.
        assert!(!validate_hello(&serde_json::json!({ "nothello": "x" })));
    }

    #[test]
    fn lock_path_has_expected_filename() {
        assert_eq!(LockFile::path().file_name().unwrap(), "run.lock");
    }

    #[cfg(unix)]
    #[test]
    fn socket_path_sits_beside_the_lock_file() {
        assert_eq!(socket_path().file_name().unwrap(), "run.sock");
        assert_eq!(socket_path().parent(), LockFile::path().parent());
    }

    #[cfg(unix)]
    #[test]
    fn peer_uid_of_local_socketpair_is_current_euid() {
        // Both ends of a socketpair live in this process, so the peer's uid is
        // our own euid -- exactly what the accept-loop check requires to pass.
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&a).unwrap(), unsafe { libc::geteuid() });
    }
}
