//! Executable-identity attestation: policy for accepting a peer or a pid, and
//! for measuring the harness (parent) that spawned an MCP-server instance. The
//! per-OS identity measurement (Linux `/proc/<pid>/exe` SHA256, macOS
//! code-directory hash + Team ID, Windows image-file SHA256 + Authenticode
//! publisher) lives in [`super::platform`]; this module owns the trust
//! decision - the same-binary allowlist is exactly `{our own binary}` for a
//! bridge peer, and every ambiguity fails closed.

use std::io;

use super::identity::{ClientIdentity, HashDigest};
use super::platform::os;
use super::socket::BridgeStream;

/// This process's own executable identity, computed once and cached: a peer is accepted only when its running
/// image yields the same value by the same measurement. [`ensure_own_identity`] primes the cache at startup,
/// before any connection is accepted or dialed, so "self" is fixed from the genuine binary and a later on-disk
/// replacement cannot redefine it.
fn own_identity() -> io::Result<&'static HashDigest> {
    use std::sync::OnceLock;

    static CACHE: OnceLock<Option<HashDigest>> = OnceLock::new();
    CACHE
        .get_or_init(|| os::own_identity().ok())
        .as_ref()
        .ok_or_else(|| io::Error::other(os::OWN_IDENTITY_ERROR))
}

/// The peer's running-image identity, measured the same way as [`own_identity`].
fn peer_identity(stream: &BridgeStream) -> io::Result<HashDigest> {
    os::peer_identity(stream)
}

/// The running-image identity of an arbitrary process named by pid, measured
/// the same way as [`own_identity`]. Unlike [`peer_identity`] there is no
/// connected socket to bind the measurement to, so this inherently carries
/// the pid-reuse race noted on [`super::peercred::peer_pid`]: callers must
/// treat a positive match as the only signal that grants trust, and every
/// failure as "not our process".
fn pid_identity(pid: u32) -> io::Result<HashDigest> {
    os::pid_identity(pid)
}

/// Prime and validate our own executable identity. Call once at startup, before
/// accepting or dialing the bridge: it fixes the self identity at a known-good
/// time and fails loudly (rather than silently degrading later) if we cannot
/// measure our own image, so the caller can refuse to run. Returns the digest's
/// hex for logging convenience.
pub fn ensure_own_identity() -> io::Result<&'static str> {
    own_identity().map(HashDigest::as_str)
}

/// Measure our **harness**, the MCP client that spawned this MCP-server-mode instance: the input to the trusted-client
/// allowlist ([`crate::allowlist`]). stdin is an anonymous pipe with no kernel peer credentials, so on Unix the
/// attestable peer is the spawner `getppid` names; on Windows it is the process that created our stdin pipe, since a
/// Windows launcher can record any process it can open as the parent.
///
/// ```text
/// real parent already dead  -> Unix: measures the reaper (commonly pid 1), refused by an enforced allowlist unless it
///                              names that binary; unenrolled admission ignores the identity (allowlist::decide)
/// who writes our stdin      -> Unix: unproven, the pipe's write end can be inherited or passed on; Windows: the pipe's
///                              creator, unless a same-user process duplicates a harness's pipe end into a child it
///                              launches
/// pid-keyed measurement     -> the same pid-reuse race as attest_pid; on macOS pid_client_identity still validates
///                              the running image via SecCodeCheckValidity
/// ```
pub fn attest_parent() -> io::Result<ClientIdentity> {
    os::pid_client_identity(harness_pid()?)
}

/// The pid of the process measured as our harness: `getppid` (which cannot
/// fail) on Unix, the creator of our stdin pipe on Windows.
fn harness_pid() -> io::Result<u32> {
    #[cfg(unix)]
    {
        u32::try_from(crate::sys::parent_pid())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "parent pid out of range"))
    }
    #[cfg(windows)]
    {
        os::harness_pid()
    }
}

/// Verify the peer on `stream` runs the same executable image as us; the trusted-identity allowlist is exactly
/// `{our own binary}`, and the caller drops the connection on any error. Both ends run it (the server on the native
/// host right after accept, the native host on the server right after connect). The digests are not secrets, so a
/// plain comparison is fine.
pub fn attest_peer(stream: &BridgeStream) -> io::Result<()> {
    if peer_identity(stream)? == *own_identity()? {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "peer executable identity mismatch",
        ))
    }
}

/// Verify the process named by `pid` is running the same executable image as
/// us - [`attest_peer`], but keyed by pid instead of by a connected socket.
/// [`super::lockfile::listen_and_publish`] uses this to decide whether a lock
/// naming a live pid belongs to a genuine peer broker (defer to it) or to a
/// reused/foreign pid (supersede the stale lock). A mismatch returns
/// `PermissionDenied`; an unmeasurable target propagates its own error.
pub fn attest_pid(pid: u32) -> io::Result<()> {
    if pid_identity(pid)? == *own_identity()? {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "pid executable identity mismatch",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::super::socket::loopback_pair;
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn peer_identity_of_own_pid_matches_own_identity() {
        // Hashing our own pid by the peer mechanism must equal the cached self
        // identity: self and peer are measured the identical way, so an identical
        // binary produces an identical digest.
        let by_pid = pid_identity(std::process::id()).unwrap();
        assert_eq!(&by_pid, own_identity().unwrap());
    }

    #[test]
    fn attest_peer_accepts_our_own_process() {
        // The peer of a local pair is this very process, so attestation must accept it; on macOS this exercises
        // the real audit-token -> SecCode -> cdhash path end to end, on Windows the pipe pid -> image path -> hash
        // path. The foreign-binary rejection lives in tests/protocol/e2e.py: a single process cannot become a
        // different binary.
        let (a, _b) = loopback_pair();
        assert!(attest_peer(&a).is_ok());
    }

    /// A child of ours running a different binary, blocked until killed. On
    /// Unix the byte the shell echoes is read before returning: spawn() can
    /// return while the child is still a pre-exec clone of US (its
    /// /proc/<pid>/exe naming our own binary), and measuring in that window
    /// attested it as self on GitHub's ubuntu runners. Windows has no such
    /// window: the image is cmd.exe from creation.
    fn foreign_child() -> std::process::Child {
        #[cfg(unix)]
        {
            use std::io::Read;

            let mut child = std::process::Command::new("sh")
                .args(["-c", "echo r; exec sleep 30"])
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("spawn sh");
            let mut byte = [0u8; 1];
            let signalled = child
                .stdout
                .as_mut()
                .expect("child stdout is piped")
                .read_exact(&mut byte);
            // Reap before a failed expectation can leave the sleeper running.
            if signalled.is_err() {
                let _ = child.kill();
                let _ = child.wait();
            }
            signalled.expect("child signals it has exec'd");
            child
        }
        #[cfg(windows)]
        {
            // `pause` blocks on stdin, which nothing writes.
            std::process::Command::new("cmd")
                .args(["/C", "pause"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .spawn()
                .expect("spawn cmd")
        }
    }

    #[test]
    fn attest_pid_accepts_self_and_rejects_a_foreign_binary() {
        // Self: the pid-keyed measurement of this very process must match the
        // cached self identity.
        assert!(attest_pid(std::process::id()).is_ok());

        // Foreign: a child WE spawned (a specific, verified pid, never a pattern match) running a different binary
        // must be rejected with PermissionDenied.
        let mut child = foreign_child();
        let attested = attest_pid(child.id());
        // Reap the child BEFORE asserting: a failed assertion must not leave
        // the blocked child running.
        let _ = child.kill();
        let _ = child.wait();
        let err = attested.expect_err("a foreign binary must not attest");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    /// On Windows the harness is the creator of our stdin pipe, which the test
    /// runner's stdin need not be; the Windows resolution is pinned by
    /// `platform::windows::pipe`'s self-spawning test instead.
    #[cfg(unix)]
    #[test]
    fn attest_parent_measures_the_spawning_process() {
        // The parent here is the test runner (cargo / a shell), a real signed or ad-hoc-signed image: an external
        // fact the measurement must resolve on every supported host. The value varies by host, and its shape is
        // carried by the type, so only resolution is asserted.
        attest_parent().expect("parent must be measurable");
    }
}
