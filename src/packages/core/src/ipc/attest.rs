//! Executable-identity attestation: policy for accepting a peer or a pid, and
//! for measuring the harness (parent) that spawned an MCP-server instance. The
//! per-OS identity measurement (Linux `/proc/<pid>/exe` SHA256, macOS
//! code-directory hash + Team ID) lives in [`super::platform`]; this module
//! owns the trust decision - the same-binary allowlist is exactly `{our own
//! binary}` for a bridge peer, and every ambiguity fails closed. See ADR-0020
//! and ADR-0024.

use std::io;

use super::platform::os;
use super::socket::BridgeStream;

/// This process's own executable identity, computed once and cached: a peer is accepted only when its running
/// image yields the same value by the same measurement. [`ensure_own_identity`] primes the cache at startup,
/// before any connection is accepted or dialed, so "self" is fixed from the genuine binary and a later on-disk
/// replacement cannot redefine it.
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

/// Measure our **parent process**, the harness (MCP client) that spawned this MCP-server-mode instance: the input to
/// the trusted-client allowlist ([`crate::allowlist`]). stdin is an anonymous pipe with no kernel peer credentials, so
/// the attestable peer is the spawner `getppid` names, not the pipe's writer.
///
/// ```text
/// real parent already dead  -> measures the reaper (commonly pid 1): refused by an enforced allowlist unless it names
///                              that binary; unenrolled admission ignores the identity (allowlist::decide)
/// who writes our stdin      -> unproven (ADR-0024): the pipe's write end can be inherited or passed on, and no
///                              user-space mechanism attests an anonymous pipe
/// pid-keyed measurement     -> the same pid-reuse race as attest_pid (ADR-0020); on macOS pid_client_identity still
///                              validates the running image via SecCodeCheckValidity
/// ```
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn attest_parent() -> io::Result<super::ClientIdentity> {
    // getppid cannot fail and returns the current parent's pid.
    let ppid = crate::sys::parent_pid();
    let ppid = u32::try_from(ppid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "parent pid out of range"))?;
    os::pid_client_identity(ppid)
}

/// Verify the peer on `stream` runs the same executable image as us; the trusted-identity allowlist is exactly
/// `{our own binary}`, and the caller drops the connection on any error. Both ends run it (the server on the native
/// host right after accept, the native host on the server right after connect); ADR-0020 says what this proves and
/// what it cannot.
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
/// [`super::lockfile::listen_and_publish`] uses this to decide whether a lock
/// naming a live pid belongs to a genuine peer broker (defer to it) or to a
/// reused/foreign pid (supersede the stale lock). A mismatch returns
/// `PermissionDenied`; an unmeasurable target propagates its own error.
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

#[cfg(test)]
mod tests {
    use super::*;
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
        // A real different-but-signed peer (python3) is rejected in tests/protocol/e2e.py.
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
        // The peer of a local socketpair is this very process, so attestation must accept it; on macOS this
        // exercises the real audit-token -> SecCode -> cdhash path end to end. The foreign-binary rejection
        // lives in tests/protocol/e2e.py: a single process cannot become a different binary.
        let (a, _b) = UnixStream::pair().unwrap();
        assert!(attest_peer(&a).is_ok());
    }

    #[test]
    fn attest_pid_accepts_self_and_rejects_a_foreign_binary() {
        // Self: the pid-keyed measurement of this very process must match the
        // cached self identity.
        assert!(attest_pid(std::process::id()).is_ok());

        // Foreign: a child WE spawned (a specific, verified pid, never a pattern match) running a different binary
        // must be rejected with PermissionDenied. The byte the shell echoes is read before measuring: spawn() can
        // return while the child is still a pre-exec clone of US (its /proc/<pid>/exe naming our own binary), and
        // measuring in that window attested it as self on GitHub's ubuntu runners.
        use std::io::Read;
        let mut child = std::process::Command::new("sh")
            .args(["-c", "echo r; exec sleep 30"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn sh");
        let mut byte = [0u8; 1];
        let handshake = child
            .stdout
            .as_mut()
            .expect("child stdout is piped")
            .read_exact(&mut byte);
        let attested = attest_pid(child.id());
        // Reap the child BEFORE asserting: a failed assertion must not leave
        // the 30-second sleeper running.
        let _ = child.kill();
        let _ = child.wait();
        handshake.expect("child signals it has exec'd");
        let err = attested.expect_err("a foreign binary must not attest");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn attest_parent_measures_the_spawning_process() {
        // The parent here is the test runner (cargo / a shell), a real signed or ad-hoc-signed image, so the
        // measurement resolves; the value varies by host, so only its shape is asserted.
        let id = attest_parent().expect("parent must be measurable");
        assert!(!id.hash.is_empty());
        assert_eq!(id.hash.len() % 2, 0);
        assert!(id.hash.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
