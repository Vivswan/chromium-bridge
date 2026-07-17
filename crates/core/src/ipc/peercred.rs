//! Kernel-reported peer credentials (uid/pid) for a connected bridge socket,
//! plus process-liveness checks. The per-OS syscalls live in
//! [`super::platform`]; this module holds the cross-platform policy (pid
//! range validation, the EPERM-means-alive convention).

// `io` is only touched on the Unix paths (peer credentials + kill(0)); the
// Windows liveness check goes through platform::windows.
#[cfg(unix)]
use std::io;

#[cfg(unix)]
use super::socket::BridgeStream;

/// The effective UID of the process on the other end of a freshly-accepted
/// Unix-domain connection. The server compares this against its own euid to
/// reject connections from other local users before authenticating them.
#[cfg(unix)]
pub fn peer_uid(stream: &BridgeStream) -> io::Result<u32> {
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();

    #[cfg(target_os = "linux")]
    {
        super::platform::linux::peer_uid(fd)
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
/// On Linux [`super::attest::attest_peer`] uses it to resolve the peer's
/// on-disk executable; on macOS it is only the fallback identity source when
/// the kernel audit token is unavailable (see [`super::platform::macos`]).
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
        super::platform::linux::peer_pid(fd)
    }

    #[cfg(target_os = "macos")]
    {
        super::platform::macos::peer_pid(fd)
    }
}

/// Whether a process with the given pid is alive. Used by the takeover logic
/// and by the stale-lock cleanup on the connect path. On Unix `kill(pid, 0)`
/// checks existence without delivering a signal.
pub fn pid_is_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Some(pid) = checked_pid(pid) else {
            return false;
        };
        let result = unsafe { libc::kill(pid, 0) };
        result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(windows)]
    {
        super::platform::windows::windows_process::is_alive(pid)
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        let _ = pid;
        false
    }
}

/// A pid validated for use with Unix process syscalls. POSIX reserves zero and
/// negative values for process groups or broadcast signalling, so values that
/// cannot be represented as a positive `pid_t` are rejected instead of
/// truncated (`u32::MAX` would otherwise become -1 and signal every process
/// the current user is allowed to terminate).
#[cfg(unix)]
pub fn checked_pid(pid: u32) -> Option<libc::pid_t> {
    libc::pid_t::try_from(pid).ok().filter(|pid| *pid > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn checked_pid_rejects_group_and_overflow_values() {
        assert_eq!(checked_pid(0), None);
        assert_eq!(checked_pid(u32::MAX), None);
        assert_eq!(
            checked_pid(std::process::id()),
            Some(std::process::id() as libc::pid_t)
        );
    }

    #[test]
    fn pid_is_alive_sees_self_and_rejects_pid_zero() {
        assert!(pid_is_alive(std::process::id()));
        // pid 0 is the process-group broadcast value, never a real peer.
        assert!(!pid_is_alive(0));
    }

    #[cfg(unix)]
    #[test]
    fn peer_uid_of_local_socketpair_is_current_euid() {
        use std::os::unix::net::UnixStream;

        // Both ends of a socketpair live in this process, so the peer's uid is
        // our own euid -- exactly what the accept-loop check requires to pass.
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&a).unwrap(), unsafe { libc::geteuid() });
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn peer_pid_of_local_socketpair_is_current_process() {
        use std::os::unix::net::UnixStream;

        // Both ends of a socketpair belong to this process, so the kernel
        // reports our own pid as the peer -- the basis for self-attestation.
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(peer_pid(&a).unwrap(), std::process::id());
    }
}
