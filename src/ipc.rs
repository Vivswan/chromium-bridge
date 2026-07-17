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
//! - The native host reads the lock file on startup and connects. Authentication
//!   is an HMAC-SHA256 challenge-response ([`server_handshake`] /
//!   [`client_handshake`]): the server sends a random nonce, the client replies
//!   with HMAC(secret, nonce). The secret never travels on the wire, and a fresh
//!   nonce per connection makes a captured response useless to replay.
//! - Before that handshake, each end kernel-attests the other ([`attest_peer`]):
//!   it asks the kernel who the peer is and requires the peer to be running the
//!   same executable image as itself. On Linux that identity is the SHA256 of
//!   `/proc/<pid>/exe`; on macOS it is the code-directory hash of the peer's
//!   running image, taken from its kernel audit token via the Security framework
//!   (running-image-bound, so it survives a re-open TOCTOU). Only another
//!   instance of this exact binary can drive the bridge; a different same-user
//!   program is rejected at accept, before it can attempt the handshake. See
//!   ADR-0020.

use std::fs;
#[cfg(unix)]
use std::io::Read;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

#[cfg(windows)]
use std::net::{TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(windows)]
use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::protocol::{bridge_read, bridge_write, Handshake};

type HmacSha256 = Hmac<Sha256>;

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
        secret: generate_secret()?,
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
        secret: generate_secret()?,
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

/// The PID of the process on the other end of a connected Unix-domain socket.
/// On Linux [`attest_peer`] uses it to resolve the peer's on-disk executable; on
/// macOS it is only the fallback identity source when the kernel audit token is
/// unavailable (see [`codesign`]).
///
/// The kernel records this pid for the process that opened the peer end; it is
/// stable for the connection even if that process later exits. Resolving the
/// pid to an executable afterwards, however, is a separate step that can race
/// with pid reuse if the peer exits mid-connection (e.g. after passing the
/// descriptor to another process). ADR-0020 records that residual.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn peer_pid(stream: &BridgeStream) -> io::Result<u32> {
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
        if len as usize != std::mem::size_of::<libc::ucred>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected peer-credential size from SO_PEERCRED",
            ));
        }
        let pid = unsafe { cred.assume_init() }.pid;
        u32::try_from(pid)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "peer pid out of range"))
    }

    #[cfg(target_os = "macos")]
    {
        // macOS has no SO_PEERCRED pid; LOCAL_PEERPID on the AF_UNIX socket
        // yields the pid of the process that opened the peer end.
        let mut pid: libc::pid_t = 0;
        let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                (&mut pid as *mut libc::pid_t).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        if len as usize != std::mem::size_of::<libc::pid_t>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected peer-pid size from LOCAL_PEERPID",
            ));
        }
        u32::try_from(pid)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "peer pid out of range"))
    }
}

/// SHA256 (lowercase hex) of a running process's on-disk executable, named by
/// pid, on Linux. We hash `/proc/<pid>/exe`, the kernel's magic symlink to the
/// actual executable inode: it follows to the real backing file even if the path
/// was later replaced, so once the pid is resolved the digest reflects the
/// running image (the pid-resolution race is noted on [`peer_pid`]). macOS does
/// not use this: it attests the running image directly through the Security
/// framework (see [`codesign`]), which is bound to the running image and needs no
/// path re-open.
#[cfg(target_os = "linux")]
fn exe_hash_of_pid(pid: u32) -> io::Result<String> {
    hash_file(&PathBuf::from(format!("/proc/{pid}/exe")))
}

/// Stream a file through SHA256 and return the lowercase hex digest.
#[cfg(target_os = "linux")]
fn hash_file(path: &std::path::Path) -> io::Result<String> {
    use sha2::Digest;

    let mut f = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_encode(hasher.finalize().as_slice()))
}

/// This process's own executable identity, computed once and cached. It is the
/// trusted value both ends attest against: a peer is accepted only when its
/// running image yields the same identity, i.e. it is another instance of the
/// same binary. Self and peer are measured by the identical mechanism, so an
/// identical image always yields an identical value.
///
/// On Linux the identity is the SHA256 of the on-disk executable; on macOS it is
/// the code-directory hash (cdhash) of the running image, read from the Security
/// framework. [`ensure_own_identity`] primes the cache at startup, before we
/// accept or dial any connection, so our notion of "self" is fixed from the
/// genuine binary and a later on-disk replacement cannot redefine it.
#[cfg(target_os = "linux")]
fn own_identity() -> io::Result<&'static str> {
    use std::sync::OnceLock;

    static CACHE: OnceLock<Option<String>> = OnceLock::new();
    CACHE
        .get_or_init(|| exe_hash_of_pid(std::process::id()).ok())
        .as_deref()
        .ok_or_else(|| io::Error::other("cannot hash own executable"))
}

#[cfg(target_os = "macos")]
fn own_identity() -> io::Result<&'static str> {
    use std::sync::OnceLock;

    static CACHE: OnceLock<Option<String>> = OnceLock::new();
    CACHE
        .get_or_init(|| codesign::own_cdhash().ok())
        .as_deref()
        .ok_or_else(|| io::Error::other("cannot compute own code-directory hash"))
}

/// The peer's running-image identity, measured the same way as [`own_identity`].
#[cfg(target_os = "linux")]
fn peer_identity(stream: &BridgeStream) -> io::Result<String> {
    exe_hash_of_pid(peer_pid(stream)?)
}

#[cfg(target_os = "macos")]
fn peer_identity(stream: &BridgeStream) -> io::Result<String> {
    codesign::peer_cdhash(stream)
}

/// Prime and validate our own executable identity. Call once at startup, before
/// accepting or dialing the bridge: it fixes the self identity at a known-good
/// time and fails loudly (rather than silently degrading later) if we cannot
/// measure our own image, so the caller can refuse to run. Returns the identity
/// for logging convenience.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn ensure_own_identity() -> io::Result<&'static str> {
    own_identity()
}

/// Verify the peer on `stream` is running the same executable image as us, and
/// fail closed otherwise. Measure the peer's identity from the kernel's view of
/// it and require it to equal our own: a mismatch returns `PermissionDenied`, and
/// an inability to establish the peer's identity propagates that error's own
/// kind. Either way the caller drops the connection. The trusted-identity
/// allowlist is exactly `{our own binary}`.
///
/// Both ends run this: the server attests the native host right after accept, the
/// native host attests the server right after connect. See ADR-0020 for what this
/// proves and what it cannot.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn attest_peer(stream: &BridgeStream) -> io::Result<()> {
    let peer = peer_identity(stream)?;
    let own = own_identity()?;
    if identities_match(&peer, own) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "peer executable identity mismatch",
        ))
    }
}

/// Whether two hex identity digests name the same image. Split out so the
/// accept/reject decision is unit-testable without spawning a second process.
/// The digests are not secrets, so a plain comparison is fine here.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn identities_match(peer_hex: &str, own_hex: &str) -> bool {
    peer_hex == own_hex
}

/// Running-image-bound peer attestation on macOS via the Security framework:
/// identify the peer by its kernel audit token, validate its dynamic code
/// signature, and read its code-directory hash (cdhash). Unlike re-opening a
/// path, the audit token names the running image, so this closes both the path
/// re-open TOCTOU and the pid-reuse race. cdhash works for ad-hoc-signed builds
/// (it is the hash of the code pages), so it is enforceable on unsigned dev and
/// CI binaries too; Team-ID / designated-requirement pinning is the follow-up for
/// when a real signing identity lands. All FFI is hand-declared to avoid adding
/// crates (keeps cargo-deny clean). See ADR-0020.
#[cfg(target_os = "macos")]
mod codesign {
    use std::ffi::c_void;
    use std::io;

    use super::BridgeStream;

    type CFTypeRef = *const c_void;
    type CFAllocatorRef = *const c_void;
    type CFDataRef = *const c_void;
    type CFStringRef = *const c_void;
    type CFNumberRef = *const c_void;
    type CFDictionaryRef = *const c_void;
    type CFIndex = isize;
    type OSStatus = i32;
    type SecCSFlags = u32;
    type SecCodeRef = *mut c_void;
    type SecStaticCodeRef = *mut c_void;

    const DEFAULT_FLAGS: SecCSFlags = 0; // kSecCSDefaultFlags
    const ERR_SEC_SUCCESS: OSStatus = 0;
    const KCF_NUMBER_SINT32: CFIndex = 3; // kCFNumberSInt32Type

    // From <sys/un.h>: getsockopt level/name for the peer's audit token.
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERTOKEN: libc::c_int = 0x006;

    // audit_token_t from <bsm/audit.h> is `unsigned int val[8]`, layout-identical
    // to `[u32; 8]`; we treat it as opaque bytes and never read the fields.
    const AUDIT_TOKEN_LEN: usize = 8;

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        static kCFAllocatorDefault: CFAllocatorRef;
        static kCFTypeDictionaryKeyCallBacks: c_void;
        static kCFTypeDictionaryValueCallBacks: c_void;
        fn CFRelease(cf: CFTypeRef);
        fn CFDataCreate(allocator: CFAllocatorRef, bytes: *const u8, length: CFIndex) -> CFDataRef;
        fn CFDataGetBytePtr(data: CFDataRef) -> *const u8;
        fn CFDataGetLength(data: CFDataRef) -> CFIndex;
        fn CFNumberCreate(
            allocator: CFAllocatorRef,
            the_type: CFIndex,
            value_ptr: *const c_void,
        ) -> CFNumberRef;
        fn CFDictionaryCreate(
            allocator: CFAllocatorRef,
            keys: *const *const c_void,
            values: *const *const c_void,
            num_values: CFIndex,
            key_callbacks: *const c_void,
            value_callbacks: *const c_void,
        ) -> CFDictionaryRef;
        fn CFDictionaryGetValue(dict: CFDictionaryRef, key: *const c_void) -> *const c_void;
    }

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        static kSecGuestAttributeAudit: CFStringRef;
        static kSecGuestAttributePid: CFStringRef;
        static kSecCodeInfoUnique: CFStringRef;
        fn SecCodeCopySelf(flags: SecCSFlags, self_out: *mut SecCodeRef) -> OSStatus;
        fn SecCodeCopyGuestWithAttributes(
            host: SecCodeRef,
            attributes: CFDictionaryRef,
            flags: SecCSFlags,
            guest: *mut SecCodeRef,
        ) -> OSStatus;
        fn SecCodeCopyStaticCode(
            code: SecCodeRef,
            flags: SecCSFlags,
            static_out: *mut SecStaticCodeRef,
        ) -> OSStatus;
        fn SecCodeCheckValidity(
            code: SecCodeRef,
            flags: SecCSFlags,
            requirement: *const c_void,
        ) -> OSStatus;
        fn SecCodeCopySigningInformation(
            code: SecStaticCodeRef,
            flags: SecCSFlags,
            information: *mut CFDictionaryRef,
        ) -> OSStatus;
    }

    /// Owns a +1 Core Foundation reference and releases it on drop, so every early
    /// return on the error paths below still balances its retain.
    struct Cf(CFTypeRef);

    impl Drop for Cf {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CFRelease(self.0) };
            }
        }
    }

    enum GuestKey {
        Audit,
        Pid,
    }

    fn osstatus_err(context: &str, status: OSStatus) -> io::Error {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{context} failed (OSStatus {status})"),
        )
    }

    /// The cdhash of THIS process's running image.
    pub fn own_cdhash() -> io::Result<String> {
        let mut me: SecCodeRef = std::ptr::null_mut();
        let st = unsafe { SecCodeCopySelf(DEFAULT_FLAGS, &mut me) };
        if st != ERR_SEC_SUCCESS {
            return Err(osstatus_err("SecCodeCopySelf", st));
        }
        if me.is_null() {
            return Err(io::Error::other("SecCodeCopySelf returned null on success"));
        }
        let _me = Cf(me as CFTypeRef);
        validate_and_cdhash(me, "self")
    }

    /// The cdhash of the process on the other end of `stream`, identified by its
    /// kernel audit token so the measurement binds to the running image (closing
    /// the path re-open TOCTOU and the pid-reuse race). We fall back to
    /// identifying by pid ONLY when the kernel reports the audit-token option
    /// itself is unsupported (`ENOPROTOOPT`, older systems without
    /// `LOCAL_PEERTOKEN`); the pid path is still running-image-validated by
    /// `SecCodeCheckValidity` but reopens the narrow pid-reuse race (ADR-0020).
    /// Any OTHER audit-token failure (short read, permission error) fails closed
    /// rather than silently downgrading.
    pub fn peer_cdhash(stream: &BridgeStream) -> io::Result<String> {
        use std::os::unix::io::AsRawFd;

        let fd = stream.as_raw_fd();
        match peer_audit_token(fd) {
            Ok(token) => peer_cdhash_via_audit(&token),
            Err(e) if e.raw_os_error() == Some(libc::ENOPROTOOPT) => {
                peer_cdhash_via_pid(super::peer_pid(stream)?)
            }
            Err(e) => Err(e),
        }
    }

    fn peer_audit_token(fd: libc::c_int) -> io::Result<[u32; AUDIT_TOKEN_LEN]> {
        let mut token = [0u32; AUDIT_TOKEN_LEN];
        let mut len = std::mem::size_of_val(&token) as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                SOL_LOCAL,
                LOCAL_PEERTOKEN,
                token.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        if len as usize != std::mem::size_of_val(&token) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected audit-token size from LOCAL_PEERTOKEN",
            ));
        }
        Ok(token)
    }

    fn peer_cdhash_via_audit(token: &[u32; AUDIT_TOKEN_LEN]) -> io::Result<String> {
        let bytes = unsafe {
            std::slice::from_raw_parts(token.as_ptr().cast::<u8>(), std::mem::size_of_val(token))
        };
        let data =
            unsafe { CFDataCreate(kCFAllocatorDefault, bytes.as_ptr(), bytes.len() as CFIndex) };
        if data.is_null() {
            return Err(io::Error::other("CFDataCreate for audit token failed"));
        }
        let _data = Cf(data);
        guest_cdhash(GuestKey::Audit, data)
    }

    fn peer_cdhash_via_pid(pid: u32) -> io::Result<String> {
        let pid = libc::pid_t::try_from(pid)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "pid out of range"))?;
        let num = unsafe {
            CFNumberCreate(
                kCFAllocatorDefault,
                KCF_NUMBER_SINT32,
                (&pid as *const libc::pid_t).cast(),
            )
        };
        if num.is_null() {
            return Err(io::Error::other("CFNumberCreate for pid failed"));
        }
        let _num = Cf(num);
        guest_cdhash(GuestKey::Pid, num)
    }

    /// Build the one-entry guest-attribute dictionary, copy the peer's SecCode,
    /// validate its running signature, and return its cdhash.
    fn guest_cdhash(key: GuestKey, value: CFTypeRef) -> io::Result<String> {
        let key_ref = unsafe {
            match key {
                GuestKey::Audit => kSecGuestAttributeAudit,
                GuestKey::Pid => kSecGuestAttributePid,
            }
        };
        let keys: [*const c_void; 1] = [key_ref];
        let values: [*const c_void; 1] = [value];
        let attrs = unsafe {
            CFDictionaryCreate(
                kCFAllocatorDefault,
                keys.as_ptr(),
                values.as_ptr(),
                1,
                std::ptr::addr_of!(kCFTypeDictionaryKeyCallBacks),
                std::ptr::addr_of!(kCFTypeDictionaryValueCallBacks),
            )
        };
        if attrs.is_null() {
            return Err(io::Error::other(
                "CFDictionaryCreate for guest attributes failed",
            ));
        }
        let _attrs = Cf(attrs);

        let mut guest: SecCodeRef = std::ptr::null_mut();
        let st = unsafe {
            SecCodeCopyGuestWithAttributes(std::ptr::null_mut(), attrs, DEFAULT_FLAGS, &mut guest)
        };
        if st != ERR_SEC_SUCCESS {
            return Err(osstatus_err("SecCodeCopyGuestWithAttributes", st));
        }
        if guest.is_null() {
            return Err(io::Error::other(
                "SecCodeCopyGuestWithAttributes returned null on success",
            ));
        }
        let _guest = Cf(guest as CFTypeRef);

        validate_and_cdhash(guest, "peer")
    }

    /// Validate a dynamic `SecCode`'s running signature, then return its cdhash.
    /// The validity check is the running-image-bound step: it verifies the code
    /// pages match the signature of the process actually executing.
    fn validate_and_cdhash(code: SecCodeRef, what: &str) -> io::Result<String> {
        let st = unsafe { SecCodeCheckValidity(code, DEFAULT_FLAGS, std::ptr::null()) };
        if st != ERR_SEC_SUCCESS {
            return Err(osstatus_err(&format!("SecCodeCheckValidity ({what})"), st));
        }
        cdhash_of_code(code)
    }

    fn cdhash_of_code(code: SecCodeRef) -> io::Result<String> {
        let mut static_code: SecStaticCodeRef = std::ptr::null_mut();
        let st = unsafe { SecCodeCopyStaticCode(code, DEFAULT_FLAGS, &mut static_code) };
        if st != ERR_SEC_SUCCESS {
            return Err(osstatus_err("SecCodeCopyStaticCode", st));
        }
        if static_code.is_null() {
            return Err(io::Error::other(
                "SecCodeCopyStaticCode returned null on success",
            ));
        }
        let _static = Cf(static_code as CFTypeRef);

        let mut info: CFDictionaryRef = std::ptr::null();
        let st = unsafe { SecCodeCopySigningInformation(static_code, DEFAULT_FLAGS, &mut info) };
        if st != ERR_SEC_SUCCESS {
            return Err(osstatus_err("SecCodeCopySigningInformation", st));
        }
        if info.is_null() {
            return Err(io::Error::other(
                "SecCodeCopySigningInformation returned null on success",
            ));
        }
        let _info = Cf(info);

        // Borrowed reference (Get-rule): do not release.
        let cdhash = unsafe { CFDictionaryGetValue(info, kSecCodeInfoUnique) } as CFDataRef;
        if cdhash.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "code has no cdhash (unsigned?)",
            ));
        }
        let len = unsafe { CFDataGetLength(cdhash) };
        let ptr = unsafe { CFDataGetBytePtr(cdhash) };
        if len <= 0 || ptr.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "code-directory hash is empty",
            ));
        }
        let bytes = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
        Ok(super::hex_encode(bytes))
    }
}

/// 128 bits from the OS CSPRNG, hex-encoded. Used for the per-run secret that
/// keys the HMAC handshake and for the per-connection challenge nonces. Fails
/// closed if the CSPRNG is unavailable: a weaker fallback (time, pid, address
/// bits) would be guessable and silently void the authentication guarantee, so
/// the caller must refuse to proceed instead.
fn generate_secret() -> io::Result<String> {
    let mut buf = [0u8; 16];
    fill_os_random(&mut buf)?;
    Ok(hex_encode(&buf))
}

#[cfg(unix)]
fn fill_os_random(buf: &mut [u8]) -> io::Result<()> {
    // We avoid pulling in `rand` by reading /dev/urandom directly (macOS and
    // Linux both expose it).
    let mut f = fs::File::open("/dev/urandom")?;
    f.read_exact(buf)
}

#[cfg(windows)]
fn fill_os_random(buf: &mut [u8]) -> io::Result<()> {
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
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "BCryptGenRandom failed (NTSTATUS {status:#010x})"
        )))
    }
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

/// Client side (native host): read the lock file and connect. Authentication
/// happens afterwards via [`client_handshake`]. On a stale lock (server
/// crashed) the connect fails fast and the lock is removed so the next server
/// start wins cleanly.
#[cfg(unix)]
pub fn connect() -> io::Result<BridgeStream> {
    let lf = read_lock_or_err()?;
    UnixStream::connect(&lf.endpoint).inspect_err(|_| {
        LockFile::remove();
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
        LockFile::remove();
    })
}

/// HMAC-SHA256 of `msg` under `key`, hex-encoded. The key is the per-run
/// secret's bytes and the message is the challenge nonce's bytes.
fn compute_mac(key: &[u8], msg: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(msg);
    hex_encode(&mac.finalize().into_bytes())
}

/// Constant-time verification that `provided_hex` is HMAC-SHA256(key, msg).
/// Uses `Mac::verify_slice`, whose comparison does not short-circuit, so a
/// caller cannot recover the expected tag byte-by-byte via timing.
fn verify_mac(key: &[u8], msg: &[u8], provided_hex: &str) -> io::Result<()> {
    let provided = hex_decode(provided_hex)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "mac is not valid hex"))?;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(msg);
    mac.verify_slice(&provided)
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "hmac mismatch"))
}

/// Decode a hex string to bytes, or `None` on any odd length or non-hex
/// character. Operates on raw bytes via [`slice::chunks_exact`] rather than
/// `str` slicing: the input is an attacker-controlled handshake field, and
/// `&s[i..i + 2]` would panic when a multi-byte UTF-8 character straddles the
/// two-byte boundary. Under `panic = "abort"` that panic would take down the
/// whole MCP server, so this must reject bad input rather than trust it.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| Some(hex_nibble(pair[0])? << 4 | hex_nibble(pair[1])?))
        .collect()
}

/// Value of a single ASCII hex digit, or `None` for any other byte. Notably a
/// leading `+`, which `u8::from_str_radix` accepts (so the old decoder took
/// "+f" as 0x0f), is rejected here: the handshake MAC is strict two-digit hex.
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Server side: run the challenge-response over a freshly-accepted connection,
/// using the same buffered reader/writer the session will keep, so no bytes are
/// consumed past the handshake. Returns `Ok(())` only when the client proved
/// knowledge of the per-run secret.
pub fn server_handshake<R: BufRead, W: Write>(reader: &mut R, writer: &mut W) -> io::Result<()> {
    let secret = read_lock_or_err()?.secret;
    server_handshake_with_secret(reader, writer, &secret)
}

fn server_handshake_with_secret<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    secret: &str,
) -> io::Result<()> {
    let nonce = generate_secret()?;
    bridge_write(
        writer,
        &Handshake::Challenge {
            nonce: nonce.clone(),
        },
    )?;

    match bridge_read::<_, Handshake>(reader)? {
        Some(Handshake::Response { mac, .. }) => {
            verify_mac(secret.as_bytes(), nonce.as_bytes(), &mac)
        }
        Some(Handshake::Challenge { .. }) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected handshake response, got challenge",
        )),
        None => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "connection closed before handshake response",
        )),
    }
}

/// Client side: read the server's challenge and answer it with
/// HMAC(secret, nonce). `label` names the browser this host fronts (carried for
/// a later multi-browser phase; ignored by the server today). Reuses the pump's
/// buffered reader/writer so the handshake never leaks into forwarded frames.
pub fn client_handshake<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    label: Option<String>,
) -> io::Result<()> {
    let secret = read_lock_or_err()?.secret;
    client_handshake_with_secret(reader, writer, &secret, label)
}

fn client_handshake_with_secret<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    secret: &str,
    label: Option<String>,
) -> io::Result<()> {
    match bridge_read::<_, Handshake>(reader)? {
        Some(Handshake::Challenge { nonce }) => {
            let mac = compute_mac(secret.as_bytes(), nonce.as_bytes());
            bridge_write(writer, &Handshake::Response { mac, label })
        }
        Some(Handshake::Response { .. }) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected handshake challenge, got response",
        )),
        None => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "connection closed before handshake challenge",
        )),
    }
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
    fn secret_is_32_hex_chars_and_unique() {
        let s = generate_secret().unwrap();
        assert_eq!(s.len(), 32);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
        // 128 bits from the CSPRNG: two draws colliding means the RNG is
        // broken (or the fail-closed path silently regressed to something
        // deterministic).
        assert_ne!(s, generate_secret().unwrap());
    }

    #[test]
    fn lock_path_has_expected_filename() {
        assert_eq!(LockFile::path().file_name().unwrap(), "run.lock");
    }

    #[test]
    fn hex_decode_roundtrips_and_rejects_bad_input() {
        assert_eq!(hex_decode("00ff10"), Some(vec![0x00, 0xff, 0x10]));
        // Odd length and non-hex digits are rejected, not silently truncated.
        assert_eq!(hex_decode("abc"), None);
        assert_eq!(hex_decode("zz"), None);
        // A signed nibble is not hex: `u8::from_str_radix` would have accepted
        // "+f" as 0x0f, but the handshake MAC is strict two-digit hex only.
        assert_eq!(hex_decode("+f"), None);
        // A multi-byte UTF-8 character makes the byte length even while landing
        // a chunk boundary mid-codepoint. The old `&s[i..i + 2]` slicing
        // panicked here (aborting the server under panic=abort); now it is a
        // clean rejection. "é" is two UTF-8 bytes, so "aé" has byte length 3
        // (odd) and "ééf" (5 bytes) is odd too; use a 4-byte even case.
        assert_eq!(hex_decode("éé"), None); // 4 bytes, none of them ASCII hex
        assert_eq!(hex_decode("aé"), None); // 3 bytes: odd length
        assert_eq!(hex_decode("a\u{00e9}b"), None); // 4 bytes, non-hex middle
                                                    // A 4-byte emoji is even-length but not hex.
        assert_eq!(hex_decode("😀"), None);
    }

    /// Fuzz the handshake MAC decoder. It runs on an attacker-controlled field
    /// in the accept path, so it must reject or decode every input without
    /// panicking -- including multi-byte UTF-8 that lands mid-codepoint on a
    /// two-byte chunk boundary, the abort-the-server bug this guards against.
    /// Arbitrary strings are built from `any::<char>()` to avoid pulling in
    /// proptest's `regex-syntax` feature (see `protocol.rs` proptests).
    mod hex_fuzz {
        use super::super::{hex_decode, hex_encode};
        use proptest::prelude::*;

        fn arb_string() -> impl Strategy<Value = String> {
            prop::collection::vec(any::<char>(), 0..16).prop_map(|cs| cs.into_iter().collect())
        }

        proptest! {
            #[test]
            fn never_panics(s in arb_string()) {
                let _ = hex_decode(&s);
            }

            #[test]
            fn encode_decode_roundtrips(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
                prop_assert_eq!(hex_decode(&hex_encode(&bytes)), Some(bytes));
            }
        }
    }

    #[test]
    fn verify_mac_accepts_correct_and_rejects_wrong() {
        let key = b"per-run-secret";
        let nonce = b"challenge-nonce";
        let mac = compute_mac(key, nonce);
        // The MAC the client would send verifies.
        assert!(verify_mac(key, nonce, &mac).is_ok());
        // A different key (attacker who doesn't know the secret) is rejected.
        assert!(verify_mac(b"wrong-secret", nonce, &mac).is_err());
        // A different nonce (replay against a fresh challenge) is rejected.
        assert!(verify_mac(key, b"other-nonce", &mac).is_err());
        // Non-hex garbage is rejected before any comparison.
        assert!(verify_mac(key, nonce, "not-hex").is_err());
    }

    #[test]
    fn handshake_challenge_response_authenticates_over_a_pipe() {
        // Drive the client half against a known challenge and confirm it emits
        // the exact HMAC response (including the carried label) the server will
        // verify. The server's own accept path is exercised end-to-end in the
        // socketpair test below and in tests/e2e.py.
        use std::io::Cursor;

        let secret = "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4";
        let nonce = "feedface";
        let expected = compute_mac(secret.as_bytes(), nonce.as_bytes());

        let mut challenge = serde_json::to_vec(&Handshake::Challenge {
            nonce: nonce.into(),
        })
        .unwrap();
        challenge.push(b'\n');
        let mut client_in = Cursor::new(challenge);
        let mut client_out = Vec::new();
        client_handshake_with_secret(
            &mut client_in,
            &mut client_out,
            secret,
            Some("chrome".into()),
        )
        .unwrap();

        let sent: Handshake = serde_json::from_slice(&client_out[..client_out.len() - 1]).unwrap();
        match sent {
            Handshake::Response { mac, label } => {
                assert_eq!(mac, expected);
                assert_eq!(label.as_deref(), Some("chrome"));
            }
            _ => panic!("client should send a response"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn handshake_round_trip_over_socketpair() {
        use std::io::{BufReader, BufWriter};

        let secret = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f";

        // Matching secrets on both ends: the server accepts.
        let (srv, cli) = UnixStream::pair().unwrap();
        let cli_secret = secret.to_string();
        let client = std::thread::spawn(move || {
            let mut r = BufReader::new(cli.try_clone().unwrap());
            let mut w = BufWriter::new(cli);
            client_handshake_with_secret(&mut r, &mut w, &cli_secret, None)
        });
        let mut r = BufReader::new(srv.try_clone().unwrap());
        let mut w = BufWriter::new(srv);
        assert!(server_handshake_with_secret(&mut r, &mut w, secret).is_ok());
        assert!(client.join().unwrap().is_ok());

        // A client that does not know the secret is rejected by the server.
        let (srv, cli) = UnixStream::pair().unwrap();
        let client = std::thread::spawn(move || {
            let mut r = BufReader::new(cli.try_clone().unwrap());
            let mut w = BufWriter::new(cli);
            client_handshake_with_secret(&mut r, &mut w, "the-wrong-secret", None)
        });
        let mut r = BufReader::new(srv.try_clone().unwrap());
        let mut w = BufWriter::new(srv);
        let server_res = server_handshake_with_secret(&mut r, &mut w, secret);
        assert_eq!(
            server_res.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let _ = client.join();
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

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn peer_pid_of_local_socketpair_is_current_process() {
        // Both ends of a socketpair belong to this process, so the kernel
        // reports our own pid as the peer -- the basis for self-attestation.
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(peer_pid(&a).unwrap(), std::process::id());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn own_identity_is_a_sha256_hex_digest() {
        let h = own_identity().unwrap();
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        // Cached: a second call yields the same digest.
        assert_eq!(h, own_identity().unwrap());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn own_identity_is_a_stable_cdhash_hex() {
        // On macOS the identity is the running image's cdhash. On Apple Silicon
        // every build is at least ad-hoc signed, so this resolves even for
        // unsigned dev/CI binaries.
        let h = own_identity().unwrap();
        assert!(!h.is_empty());
        assert_eq!(h.len() % 2, 0);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(h, own_identity().unwrap());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cdhash_matches_itself_but_not_a_mutated_one() {
        // The core comparison: our own cdhash accepts itself and rejects a
        // one-nibble-different value (a stand-in for a different binary's cdhash).
        // A real different-but-signed peer (python3) is rejected in tests/e2e.py.
        let own = own_identity().unwrap();
        assert!(identities_match(own, own));
        let mut mutated = String::from(own);
        let last = mutated.pop().unwrap();
        mutated.push(if last == '0' { '1' } else { '0' });
        assert!(!identities_match(&mutated, own));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn peer_identity_of_own_pid_matches_own_identity() {
        // Hashing our own pid by the peer mechanism must equal the cached self
        // identity: self and peer are measured the identical way, so an identical
        // binary produces an identical digest.
        let by_pid = exe_hash_of_pid(std::process::id()).unwrap();
        assert_eq!(by_pid.as_str(), own_identity().unwrap());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn identities_match_only_on_equal_digests() {
        assert!(identities_match("abc123", "abc123"));
        assert!(!identities_match("abc123", "def456"));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn attest_peer_accepts_our_own_process() {
        // The peer of a local socketpair is this very process, so its running
        // image is ours: attestation must accept it. On macOS this exercises the
        // real audit-token -> SecCode -> cdhash path end to end. The
        // foreign-binary rejection path is exercised in tests/e2e.py, which cannot
        // be done from inside a single process (we cannot become a different
        // binary).
        let (a, _b) = UnixStream::pair().unwrap();
        assert!(attest_peer(&a).is_ok());
    }
}
