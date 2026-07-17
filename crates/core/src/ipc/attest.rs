//! Executable-identity attestation: policy for accepting a peer, a pid, or
//! terminating a prior server instance. The per-OS identity measurement
//! (Linux `/proc/<pid>/exe` SHA256, macOS code-directory hash) lives in
//! [`super::platform`]; this module owns the trust decision - the trusted
//! identity allowlist is exactly `{our own binary}`, and every ambiguity
//! fails closed. See ADR-0020.

use std::io;

use super::platform::os;
use super::socket::BridgeStream;

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
fn own_identity() -> io::Result<&'static str> {
    use std::sync::OnceLock;

    static CACHE: OnceLock<Option<String>> = OnceLock::new();
    CACHE
        .get_or_init(|| os::own_identity().ok())
        .as_deref()
        .ok_or_else(|| io::Error::other(os::OWN_IDENTITY_ERROR))
}

/// The peer's running-image identity, measured the same way as [`own_identity`].
fn peer_identity(stream: &BridgeStream) -> io::Result<String> {
    os::peer_identity(stream)
}

/// The running-image identity of an arbitrary process named by pid, measured
/// the same way as [`own_identity`]. Unlike [`peer_identity`] there is no
/// connected socket to bind the measurement to, so this inherently carries
/// the pid-reuse race noted on [`super::peercred::peer_pid`]: callers must
/// treat a positive match as the only signal that grants trust, and every
/// failure as "not our process".
fn pid_identity(pid: u32) -> io::Result<String> {
    os::pid_identity(pid)
}

/// Prime and validate our own executable identity. Call once at startup, before
/// accepting or dialing the bridge: it fixes the self identity at a known-good
/// time and fails loudly (rather than silently degrading later) if we cannot
/// measure our own image, so the caller can refuse to run. Returns the identity
/// for logging convenience.
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
fn identities_match(peer_hex: &str, own_hex: &str) -> bool {
    peer_hex == own_hex
}

/// Verify the process named by `pid` is running the same executable image as
/// us - [`attest_peer`], but keyed by pid instead of by a connected socket.
/// The takeover path uses this before SIGTERMing the pid recorded in the lock
/// file: that pid is just a number read from disk, and with a stale lock plus
/// OS pid reuse it can name an arbitrary, innocent process. A mismatch
/// returns `PermissionDenied`; an unmeasurable target propagates its own
/// error. Either way the caller must NOT signal the pid (the safety red line:
/// never kill a pid you have not verified).
pub fn attest_pid(pid: u32) -> io::Result<()> {
    let target = pid_identity(pid)?;
    let own = own_identity()?;
    if identities_match(&target, own) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "pid executable identity mismatch",
        ))
    }
}

/// Attest the pid named in the lock file and terminate it, binding the SIGTERM
/// to the exact process instance we attested wherever the platform allows.
///
/// Linux (kernel >= 5.3): `pidfd_open` pins the running instance BEFORE
/// attestation, and `pidfd_send_signal` targets that pinned instance, so a pid
/// the OS reuses after we open the descriptor can never be signaled: the send
/// returns `ESRCH` against the now-dead original instead of hitting the reused
/// pid. The only window left is between reading the pid from the lock file and
/// `pidfd_open`; `attest_pid` runs after the open and fails closed if the pid
/// already names a different binary, so no unverified process is signaled.
/// Kernels without `pidfd_open` (`ENOSYS`, < 5.3) fall back to attest-then-kill.
///
/// macOS has no `pidfd` equivalent, so it attests then signals by pid number;
/// its residual pid-reuse race is now only the interval between attesting our
/// own instance and the `kill` (see `supplant_prior_server` and ADR-0020).
///
/// Returns `Ok(())` once SIGTERM was delivered to an attested instance, or the
/// instance was already gone (`ESRCH`, the safe outcome). Returns the
/// attestation error (fail closed, never signaled) when the pid does not attest
/// as our binary.
#[cfg(target_os = "linux")]
pub fn attest_and_terminate(pid: u32) -> io::Result<()> {
    use super::peercred::checked_pid;

    let Some(cpid) = checked_pid(pid) else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid pid"));
    };
    // Pin the exact process instance before measuring or signaling it.
    let pidfd = unsafe {
        libc::syscall(
            libc::SYS_pidfd_open,
            cpid as libc::c_long,
            0 as libc::c_long,
        )
    };
    if pidfd < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOSYS) {
            // Pre-5.3 kernel: no instance-bound signal available. Fall back to
            // attest-then-kill (the same microsecond residual macOS documents).
            attest_pid(pid)?;
            unsafe { libc::kill(cpid, libc::SIGTERM) };
            return Ok(());
        }
        // pidfd_open failed otherwise (e.g. ESRCH: the pid already exited).
        // Nothing to signal; fail closed without signaling.
        return Err(err);
    }
    let pidfd = pidfd as libc::c_int;
    // Measure AFTER pinning. A pid reused before pidfd_open is caught here (a
    // different binary -> PermissionDenied, no signal). A pid reused after
    // pidfd_open cannot be hit: the descriptor still names the original,
    // now-dead instance, so the send below returns ESRCH.
    let signaled = match attest_pid(pid) {
        Err(e) => Err(e),
        Ok(()) => {
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd as libc::c_long,
                    libc::SIGTERM as libc::c_long,
                    std::ptr::null_mut::<libc::siginfo_t>(),
                    0 as libc::c_long,
                )
            };
            if rc < 0 {
                let e = io::Error::last_os_error();
                // ESRCH: the attested instance already exited (the pid may have
                // been reused by now). Safe outcome: no innocent process was
                // signaled.
                if e.raw_os_error() == Some(libc::ESRCH) {
                    Ok(())
                } else {
                    Err(e)
                }
            } else {
                Ok(())
            }
        }
    };
    unsafe { libc::close(pidfd) };
    signaled
}

/// macOS variant of [`attest_and_terminate`]: no `pidfd`, so attest then signal
/// by pid number. Documented micro-residual, see the function above.
#[cfg(target_os = "macos")]
pub fn attest_and_terminate(pid: u32) -> io::Result<()> {
    attest_pid(pid)?;
    if let Some(cpid) = super::peercred::checked_pid(pid) {
        unsafe { libc::kill(cpid, libc::SIGTERM) };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::pid_is_alive;
    use std::os::unix::net::UnixStream;

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
        let by_pid = pid_identity(std::process::id()).unwrap();
        assert_eq!(by_pid.as_str(), own_identity().unwrap());
    }

    #[test]
    fn identities_match_only_on_equal_digests() {
        assert!(identities_match("abc123", "abc123"));
        assert!(!identities_match("abc123", "def456"));
    }

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

    #[test]
    fn attest_pid_accepts_self_and_rejects_a_foreign_binary() {
        // Self: the pid-keyed measurement of this very process must match the
        // cached self identity.
        assert!(attest_pid(std::process::id()).is_ok());

        // Foreign: a child WE spawned (a specific, verified pid - never a
        // pattern match) running a different binary must be rejected with
        // PermissionDenied, the caller's do-not-signal signal.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let err = attest_pid(child.id()).expect_err("a foreign binary must not attest");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn attest_and_terminate_refuses_a_foreign_binary() {
        // The takeover signal path must not deliver SIGTERM to a pid that does
        // not attest as our binary (the red line: never kill an unverified
        // pid). Spawn a specific, verified child we own, running a different
        // binary, and confirm attest_and_terminate fails closed AND leaves it
        // alive. (Delivery to our OWN instance is exercised end to end by the
        // real two-server takeover in tests/e2e.py, which cannot run inside a
        // unit test without signaling the test process itself.)
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let err =
            attest_and_terminate(child.id()).expect_err("a foreign binary must not be signaled");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        // Not signaled: the foreign child is still alive.
        assert!(pid_is_alive(child.id()));
        let _ = child.kill();
        let _ = child.wait();
    }
}
