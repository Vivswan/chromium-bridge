//! Windows mechanisms: a named pipe in the local pipe namespace as the bridge
//! transport, the pipe peer's process identity (image hash plus Authenticode
//! publisher), and process liveness. The contract with Windows (the pipe name,
//! the user-only descriptor text, the trust verdict codes) is pure and compiles
//! on every platform, so each platform's test run exercises it; the mechanisms
//! behind it are Windows-only FFI quarantines, one per concern.
//!
//! ```text
//! pipe     -> CreateNamedPipeW / CreateFileW, overlapped reads with a deadline, cross-thread shutdown
//! acl      -> the current user's SID rendered to an SDDL descriptor only that SID can open
//! process  -> OpenProcess, the image path, liveness
//! signer   -> WinVerifyTrust and the leaf certificate's subject
//! ```
//!
//! The image is measured by re-opening its path, so the pid-reuse race noted on
//! [`super::super::peercred::peer_pid`] applies, plus the window in which a
//! running image is renamed and another file placed at its path; Windows has no
//! user-mode handle to the mapped image itself. The threat model records both.

use std::path::Path;

use sha2::{Digest, Sha256};

#[cfg(windows)]
pub(crate) mod acl;
#[cfg(windows)]
pub(crate) mod pipe;
#[cfg(windows)]
pub(crate) mod process;
#[cfg(windows)]
pub(crate) mod signer;

#[cfg(windows)]
use std::io;

#[cfg(windows)]
use super::super::identity::{ClientIdentity, HashDigest};
#[cfg(windows)]
use super::super::socket::BridgeStream;

/// The pipe namespace of the local machine. A name outside it (a `\\host\pipe\`
/// UNC path, a plain file path) would make `CreateFileW` open something other
/// than a local pipe, so [`PipeName`] admits this prefix alone.
const PIPE_NAMESPACE: &str = r"\\.\pipe\";

/// Windows caps a pipe name at 256 characters.
const PIPE_NAME_MAX: usize = 256;

/// The bridge pipe's name, parsed once where a name enters: derived by the
/// server that binds it, read from the lock file on the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipeName(String);

impl PipeName {
    /// The pipe one broker binds. The pipe namespace is machine-global and
    /// flat, so the per-user runtime directory's path is hashed into the leaf
    /// (one pipe per user, another per test scratch directory), and the
    /// broker's pid follows it: a surviving broker of another build keeps its
    /// name and its connections while the new one binds a fresh name, which a
    /// name held across instances would refuse.
    pub fn for_broker(runtime_dir: &Path, pid: u32) -> PipeName {
        let digest = Sha256::digest(runtime_dir.to_string_lossy().as_bytes());
        let leaf = hex::encode(digest.get(..16).unwrap_or_default());
        PipeName(format!("{PIPE_NAMESPACE}chromium-bridge-{leaf}-{pid}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for PipeName {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let leaf = value
            .strip_prefix(PIPE_NAMESPACE)
            .ok_or_else(|| format!("pipe name must start with {PIPE_NAMESPACE}"))?;
        if leaf.is_empty() || leaf.contains(['\\', '/']) {
            return Err("pipe name must be one leaf under the local pipe namespace".to_string());
        }
        if value.len() > PIPE_NAME_MAX {
            return Err(format!("pipe name exceeds {PIPE_NAME_MAX} characters"));
        }
        Ok(PipeName(value.to_string()))
    }
}

impl From<PipeName> for String {
    fn from(name: PipeName) -> String {
        name.0
    }
}

/// A SID in its string form (`S-1-5-21-...`), as `ConvertSidToStringSidW`
/// spells it. Parsed so only the digits-and-dashes alphabet can reach the SDDL
/// text in [`user_only_sddl`], where any other character would change the
/// descriptor's meaning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidString(String);

impl TryFrom<String> for SidString {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let well_formed = value.strip_prefix("S-1-").is_some_and(|rest| {
            !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit() || b == b'-')
        });
        if well_formed {
            Ok(SidString(value))
        } else {
            Err("SID must be S-1- followed by digits and dashes".to_string())
        }
    }
}

/// The descriptor text for the bridge pipe: generic-all to `sid`, nothing to
/// anyone else, and `P` so no inherited entry widens it. Windows parses this
/// string, so its exact spelling is the contract.
pub fn user_only_sddl(sid: &SidString) -> String {
    format!("D:P(A;;GA;;;{})", sid.0)
}

/// The process that created a pipe, from the pids the kernel recorded for its
/// two ends. A spawner opens both ends of a child's stdio pipe itself, so they
/// agree and name it; ends opened by different processes mean the pipe was
/// handed on, and an end we opened ourselves cannot be the harness's.
pub fn pipe_creator(client: u32, server: u32, me: u32) -> Result<u32, String> {
    if client != server {
        return Err(format!(
            "stdin pipe ends belong to different processes ({client} and {server}); the harness cannot be attested"
        ));
    }
    if client == me {
        return Err("stdin pipe was created by this process".to_string());
    }
    Ok(client)
}

/// `WinVerifyTrust`'s verdict on an image, folded to the outcomes the publisher
/// anchor distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustStatus {
    /// The signature verifies and chains to a trusted root.
    Trusted,
    /// No embedded Authenticode signature.
    Unsigned,
    /// A signature is present but does not match the file's contents.
    Tampered,
    /// Signed, but the chain is not trusted (self-signed, expired, revoked, or
    /// another verdict); the HRESULT is kept for the log.
    Untrusted(i32),
}

/// `winerror.h` values; the `windows-sys` spellings are pinned to these in a
/// Windows-only test.
pub const TRUST_E_NOSIGNATURE: i32 = hresult(0x800B_0100);
pub const TRUST_E_BAD_DIGEST: i32 = hresult(0x8009_6010);

const fn hresult(code: u32) -> i32 {
    i32::from_ne_bytes(code.to_ne_bytes())
}

impl TrustStatus {
    pub fn from_hresult(code: i32) -> TrustStatus {
        match code {
            0 => TrustStatus::Trusted,
            TRUST_E_NOSIGNATURE => TrustStatus::Unsigned,
            TRUST_E_BAD_DIGEST => TrustStatus::Tampered,
            other => TrustStatus::Untrusted(other),
        }
    }
}

/// The publisher anchor an image earns from its trust verdict and its signer's
/// subject. An unsigned or untrusted image anchors by hash alone; a tampered
/// one is refused outright, as a macOS image failing `SecCodeCheckValidity` is.
pub fn publisher_anchor(
    status: TrustStatus,
    subject: Option<String>,
) -> std::io::Result<Option<super::super::identity::TeamId>> {
    use std::io::{Error, ErrorKind};

    use super::super::identity::TeamId;

    match (status, subject) {
        (TrustStatus::Trusted, Some(subject)) => TeamId::try_from(subject)
            .map(Some)
            .map_err(|e| Error::new(ErrorKind::InvalidData, e)),
        (TrustStatus::Trusted, None) => Err(Error::new(
            ErrorKind::InvalidData,
            "trusted signature without a readable signer subject",
        )),
        (TrustStatus::Unsigned | TrustStatus::Untrusted(_), _) => Ok(None),
        (TrustStatus::Tampered, _) => Err(Error::new(
            ErrorKind::PermissionDenied,
            "image signature does not match its contents",
        )),
    }
}

/// Error message for an unmeasurable self identity, used by
/// [`super::super::attest`].
#[cfg(windows)]
pub(crate) const OWN_IDENTITY_ERROR: &str = "cannot hash own executable image";

/// This process's own executable identity: the SHA-256 of its image file,
/// found the same way a peer's is so the two measurements compare.
#[cfg(windows)]
pub(crate) fn own_identity() -> io::Result<HashDigest> {
    pid_identity(std::process::id())
}

/// The peer's running-image identity, keyed by the pid the kernel records
/// for the other end of the pipe.
#[cfg(windows)]
pub(crate) fn peer_identity(stream: &BridgeStream) -> io::Result<HashDigest> {
    pid_identity(stream.peer_pid()?)
}

/// The running-image identity of an arbitrary process named by pid.
#[cfg(windows)]
pub(crate) fn pid_identity(pid: u32) -> io::Result<HashDigest> {
    HashDigest::of_file(&process::image_path(pid)?)
}

/// The full client identity of a process: its image hash plus the
/// Authenticode publisher of that image when the signature verifies.
#[cfg(windows)]
pub(crate) fn pid_client_identity(pid: u32) -> io::Result<ClientIdentity> {
    let image = process::image_path(pid)?;
    Ok(ClientIdentity {
        hash: HashDigest::of_file(&image)?,
        team_id: signer::publisher_of(&image)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_derived_pipe_name_parses_back_and_differs_per_runtime_dir_and_broker() {
        // External facts the type carries: the lock's endpoint is read by
        // another process, so what the server derives must parse on the client;
        // the pipe namespace is machine-global, so two users' runtime
        // directories must not share a name; and a name held by a surviving
        // broker cannot be bound again, so two brokers must not share one.
        let alice = Path::new(r"C:\Users\alice\AppData\Local\chromium-bridge");
        let bob = Path::new(r"C:\Users\bob\AppData\Local\chromium-bridge");
        let a = PipeName::for_broker(alice, 4100);
        assert_eq!(PipeName::try_from(a.as_str()), Ok(a.clone()));
        assert_ne!(a, PipeName::for_broker(bob, 4100));
        assert_ne!(a, PipeName::for_broker(alice, 4101));
    }

    #[test]
    fn a_planted_lock_endpoint_outside_the_local_pipe_namespace_is_refused() {
        // CreateFileW opens whatever path it is handed: a UNC pipe reaches
        // another machine, a file path a plain file. Each is refused at parse.
        for (endpoint, why) in [
            (r"\\evil\pipe\chromium-bridge", "remote pipe"),
            (r"C:\Users\alice\run.lock", "file path"),
            (r"\\.\pipe\", "empty leaf"),
            (r"\\.\pipe\a\b", "nested leaf"),
            (r"\\.\pipe/a", "slash separator"),
            ("127.0.0.1:4321", "the retired loopback endpoint"),
        ] {
            assert!(PipeName::try_from(endpoint).is_err(), "{why}: {endpoint}");
        }
        let long = format!(r"\\.\pipe\{}", "x".repeat(PIPE_NAME_MAX));
        assert!(
            PipeName::try_from(long.as_str()).is_err(),
            "over the length cap"
        );
    }

    #[test]
    fn the_pipe_creator_is_the_one_process_behind_both_ends() {
        // The harness measurement keys on this fold: a spawner opens both ends
        // of its child's stdin pipe, so agreeing pids name it; an end handed on
        // from another process, or one this process opened, must not attest
        // anyone (the Windows wording of the stdin-writer residual).
        assert_eq!(pipe_creator(4100, 4100, 7), Ok(4100));
        assert!(
            pipe_creator(4100, 4200, 7).is_err(),
            "ends from two processes"
        );
        assert!(pipe_creator(7, 7, 7).is_err(), "our own pipe");
    }

    #[test]
    fn the_descriptor_grants_the_one_sid_and_refuses_an_injectable_sid() {
        // Windows parses the SDDL text, so its spelling is a cross-process
        // contract; and a SID string carrying other characters could rewrite
        // the descriptor, so the alphabet is pinned at the parse.
        let sid = SidString::try_from("S-1-5-21-1-2-3-1001".to_string()).unwrap();
        assert_eq!(user_only_sddl(&sid), "D:P(A;;GA;;;S-1-5-21-1-2-3-1001)");
        for bad in ["", "S-1-", "S-1-5-21)(A;;GA;;;WD", "s-1-5-18", "S-2-5-18"] {
            assert!(SidString::try_from(bad.to_string()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_publisher_anchor_follows_the_trust_verdict() {
        // winerror.h values are an external fact; the fold from verdict to
        // anchor is the trust decision the allowlist relies on.
        type Anchor = Result<Option<&'static str>, std::io::ErrorKind>;
        let subject = Some("CN=Example Publisher, O=Example, C=US".to_string());
        let cases: [(i32, Option<String>, Anchor); 6] = [
            (
                0,
                subject.clone(),
                Ok(Some("CN=Example Publisher, O=Example, C=US")),
            ),
            (0, None, Err(std::io::ErrorKind::InvalidData)),
            (0, Some(String::new()), Err(std::io::ErrorKind::InvalidData)),
            (TRUST_E_NOSIGNATURE, None, Ok(None)),
            (hresult(0x800B_0109), subject.clone(), Ok(None)),
            (
                TRUST_E_BAD_DIGEST,
                subject,
                Err(std::io::ErrorKind::PermissionDenied),
            ),
        ];
        for (code, subject, expected) in cases {
            let got = publisher_anchor(TrustStatus::from_hresult(code), subject)
                .map(|anchor| anchor.map(String::from))
                .map_err(|e| e.kind());
            let expected = expected.map(|anchor| anchor.map(str::to_string));
            assert_eq!(got, expected, "hresult {code:#x}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn the_local_hresult_spellings_match_windows_sys() {
        // Cross-crate consistency the compiler cannot express: the pure fold
        // above must name the same values WinVerifyTrust returns.
        use windows_sys::Win32::Foundation;
        assert_eq!(TRUST_E_NOSIGNATURE, Foundation::TRUST_E_NOSIGNATURE);
        assert_eq!(TRUST_E_BAD_DIGEST, Foundation::TRUST_E_BAD_DIGEST);
    }
}
