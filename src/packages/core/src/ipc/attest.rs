//! The trust decision over the per-OS identity measurement in [`super::platform`]: a bridge peer is accepted
//! only as our own binary, and every ambiguity fails closed.

use std::io;

use super::identity::{ClientIdentity, HashDigest};
use super::platform::os;
use super::socket::BridgeStream;

/// Cached for the process lifetime, failure included: a self that could not be measured at startup is never
/// re-measured against a possibly replaced image.
fn own_identity() -> io::Result<&'static HashDigest> {
    use std::sync::OnceLock;

    static CACHE: OnceLock<Option<HashDigest>> = OnceLock::new();
    CACHE
        .get_or_init(|| os::own_identity().ok())
        .as_ref()
        .ok_or_else(|| io::Error::other(os::OWN_IDENTITY_ERROR))
}

/// Runs once at startup, before any bridge connection is accepted or dialed, so "self" is fixed from the
/// genuine image and a later on-disk replacement cannot redefine it.
pub fn ensure_own_identity() -> io::Result<&'static str> {
    own_identity().map(HashDigest::as_str)
}

/// Measure the harness that spawned this MCP-server instance, the input to [`crate::allowlist`]. stdin is an
/// anonymous pipe with no kernel peer credentials, so the attestable process is the spawner: `getppid` on
/// Unix, the creator of our stdin pipe on Windows (a Windows launcher can record any process it can open as
/// the parent). docs/security/trust-boundaries.md carries the residuals.
///
/// ```text
/// parent already dead (Unix)  -> the reaper is measured; an enforced allowlist refuses it unless it names it
/// who writes our stdin        -> unproven: a pipe end can be inherited or duplicated
/// pid-keyed measurement       -> the pid-reuse race of [`attest_pid`]; macOS still validates the image
/// ```
pub fn attest_parent() -> io::Result<ClientIdentity> {
    #[cfg(unix)]
    let harness = u32::try_from(crate::sys::parent_pid())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "parent pid out of range"))?;
    #[cfg(windows)]
    let harness = os::pipe::stdin_pipe_creator()?;
    os::pid_client_identity(harness)
}

/// Both ends run this right after accept/connect and drop the connection on any error. The digests are
/// public, so the comparison need not be constant-time.
pub fn attest_peer(stream: &BridgeStream) -> io::Result<()> {
    if os::peer_identity(stream)? == *own_identity()? {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "peer executable identity mismatch",
        ))
    }
}

/// [`attest_peer`] keyed by pid, so it carries the pid-reuse race noted on `peercred::peer_pid`: only a
/// positive match grants trust, and an unmeasurable target reads as a mismatch.
pub fn attest_pid(pid: u32) -> io::Result<()> {
    if os::pid_identity(pid)? == *own_identity()? {
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
        let by_pid = os::pid_identity(std::process::id()).unwrap();
        assert_eq!(&by_pid, own_identity().unwrap());
    }

    #[test]
    fn attest_peer_accepts_our_own_process() {
        // The peer of a local pair is this process, so the real OS path runs end to end (macOS: audit
        // token -> SecCode -> cdhash; Windows: pipe pid -> image hash). Foreign-binary rejection lives in
        // tests/protocol/e2e.py: one process cannot become another binary.
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
        assert!(attest_pid(std::process::id()).is_ok());

        // A child WE spawned: a verified pid, never a pattern match.
        let mut child = foreign_child();
        let attested = attest_pid(child.id());
        // Reap before asserting, so a failed expectation cannot leave the blocked child running.
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
        // The parent is the test runner, an image the measurement must resolve on every supported host (on
        // macOS a real ad-hoc or Team-ID signature); the value varies per host, so only resolution is asserted.
        attest_parent().expect("parent must be measurable");
    }
}
