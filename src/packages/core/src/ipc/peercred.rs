#![cfg_attr(
    unix,
    expect(
        unsafe_code,
        reason = "audited FFI quarantine: getpeereid and kill(pid, 0), each behind a safe wrapper"
    )
)]

#[cfg(unix)]
use std::io;

#[cfg(unix)]
use super::socket::BridgeStream;

/// The same-user gate's input: the accept loop compares it with its own euid before anything else is read.
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
        // getpeereid yields the EFFECTIVE uid/gid of the peer that opened the socket.
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: uid/gid are live locals the call writes into; an invalid fd
        // is reported through rc, never a wild write.
        let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(uid)
    }
}

/// The pid the kernel recorded for the process that opened the peer end, stable for the connection even after
/// that process exits; resolving it to an executable afterwards can race with pid reuse (the peer passed its
/// descriptor on, then exited). docs/security/trust-boundaries.md carries that residual.
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

/// `kill(pid, 0)` delivers nothing; EPERM means the process exists but belongs to another user, so it counts
/// as alive.
pub fn pid_is_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Some(pid) = checked_pid(pid) else {
            return false;
        };
        // SAFETY: signal 0 delivers nothing, and `pid` is positive by
        // checked_pid, so the call names one process, never a group.
        let result = unsafe { libc::kill(pid, 0) };
        result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(windows)]
    {
        super::platform::windows::process::is_alive(pid)
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
            Some(libc::pid_t::try_from(std::process::id()).expect("own pid fits in pid_t"))
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

        // Both ends live in this process, so the kernel must report our own euid as the peer's.
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&a).unwrap(), crate::sys::effective_uid());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn peer_pid_of_local_socketpair_is_current_process() {
        use std::os::unix::net::UnixStream;

        // Both ends live in this process, so the kernel must report our own pid as the peer's.
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(peer_pid(&a).unwrap(), std::process::id());
    }
}
