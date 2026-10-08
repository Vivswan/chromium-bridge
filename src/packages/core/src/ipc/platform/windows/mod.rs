//! The pipe name and the descriptor text are pure and compile into every platform's test build; the trust
//! fold and the FFI behind it are Windows-only, one quarantine per concern. The image is measured by
//! re-opening its path; docs/security/trust-boundaries.md records what that leaves open.

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
    /// The pipe one broker binds. The namespace is machine-global and flat, so the runtime directory's path
    /// is hashed into the leaf (one pipe per user or scratch dir) and the pid follows it (a surviving broker
    /// keeps its name while the new one binds a fresh one).
    pub fn for_broker(runtime_dir: &Path, pid: u32) -> PipeName {
        let digest = Sha256::digest(runtime_dir.to_string_lossy().as_bytes());
        let leaf = hex::encode(digest.get(..16).unwrap_or_default());
        PipeName(format!("{PIPE_NAMESPACE}genkan-{leaf}-{pid}"))
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

/// Parsed so only the digits-and-dashes alphabet of `ConvertSidToStringSidW` can reach the SDDL text in
/// [`user_only_sddl`], where any other character would change the descriptor's meaning.
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

/// Every spawner (CreatePipe, libuv, Rust's Command) opens both ends of a child's stdio pipe itself, so the
/// two pids agree and name it; ends opened by different processes mean the pipe was handed on, and an end we
/// opened ourselves cannot be the harness's.
#[cfg(windows)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(windows)]
pub enum TrustStatus {
    Trusted(String),
    Unsigned,
    Tampered,
    /// Self-signed, expired, revoked, or another verdict; the HRESULT is kept for the log.
    Untrusted(i32),
}

/// Local copies of the `winerror.h` values, pinned to `windows-sys` by a test.
#[cfg(windows)]
pub const TRUST_E_NOSIGNATURE: i32 = hresult(0x800B_0100);
#[cfg(windows)]
pub const TRUST_E_BAD_DIGEST: i32 = hresult(0x8009_6010);

#[cfg(windows)]
const fn hresult(code: u32) -> i32 {
    i32::from_ne_bytes(code.to_ne_bytes())
}

#[cfg(windows)]
impl TrustStatus {
    pub fn classify(
        code: i32,
        subject: impl FnOnce() -> std::io::Result<String>,
    ) -> std::io::Result<TrustStatus> {
        Ok(match code {
            0 => TrustStatus::Trusted(subject()?),
            TRUST_E_NOSIGNATURE => TrustStatus::Unsigned,
            TRUST_E_BAD_DIGEST => TrustStatus::Tampered,
            other => TrustStatus::Untrusted(other),
        })
    }
}

/// The publisher anchor an image earns from its trust verdict. An unsigned or
/// untrusted image anchors by hash alone; a tampered one is refused outright,
/// as a macOS image failing `SecCodeCheckValidity` is.
#[cfg(windows)]
pub fn publisher_anchor(
    status: TrustStatus,
) -> std::io::Result<Option<super::super::identity::SignerId>> {
    use std::io::{Error, ErrorKind};

    use super::super::identity::SignerId;

    match status {
        TrustStatus::Trusted(subject) => SignerId::try_from(subject)
            .map(Some)
            .map_err(|e| Error::new(ErrorKind::InvalidData, e)),
        TrustStatus::Unsigned | TrustStatus::Untrusted(_) => Ok(None),
        TrustStatus::Tampered => Err(Error::new(
            ErrorKind::PermissionDenied,
            "image signature does not match its contents",
        )),
    }
}

#[cfg(windows)]
pub(crate) const OWN_IDENTITY_ERROR: &str = "cannot hash own executable image";

#[cfg(windows)]
pub(crate) fn own_identity() -> io::Result<HashDigest> {
    pid_identity(std::process::id())
}

#[cfg(windows)]
pub(crate) fn peer_identity(stream: &BridgeStream) -> io::Result<HashDigest> {
    pid_identity(stream.peer_pid()?)
}

#[cfg(windows)]
pub(crate) fn pid_identity(pid: u32) -> io::Result<HashDigest> {
    HashDigest::of_file(&process::image_path(pid)?)
}

#[cfg(windows)]
pub(crate) fn pid_client_identity(pid: u32) -> io::Result<ClientIdentity> {
    let image = process::image_path(pid)?;
    Ok(ClientIdentity {
        hash: HashDigest::of_file(&image)?,
        signer: signer::publisher_of(&image)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_derived_pipe_name_parses_back_and_differs_per_runtime_dir_and_broker() {
        // The lock's endpoint is read by another process, so what the server derives must parse on the
        // client; the namespace is machine-global, so two runtime dirs or two brokers must never share a
        // name.
        let alice = Path::new(r"C:\Users\alice\AppData\Local\genkan");
        let bob = Path::new(r"C:\Users\bob\AppData\Local\genkan");
        let a = PipeName::for_broker(alice, 4100);
        assert_eq!(PipeName::try_from(a.as_str()), Ok(a.clone()));
        assert_ne!(a, PipeName::for_broker(bob, 4100));
        assert_ne!(a, PipeName::for_broker(alice, 4101));
    }

    #[test]
    fn a_planted_lock_endpoint_outside_the_local_pipe_namespace_is_refused() {
        // CreateFileW opens whatever path it is handed: a UNC pipe reaches another machine, a file path a
        // file.
        for (endpoint, why) in [
            (r"\\evil\pipe\genkan", "remote pipe"),
            (r"C:\Users\alice\run.lock", "file path"),
            (r"\\.\pipe\", "empty leaf"),
            (r"\\.\pipe\a\b", "nested leaf"),
            (r"\\.\pipe/a", "slash separator"),
            ("127.0.0.1:4321", "a loopback TCP address"),
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
    fn the_descriptor_grants_the_one_sid_and_refuses_an_injectable_sid() {
        // Windows parses the SDDL text, so its spelling is a contract; a SID carrying other characters could
        // rewrite the descriptor.
        let sid = SidString::try_from("S-1-5-21-1-2-3-1001".to_string()).unwrap();
        assert_eq!(user_only_sddl(&sid), "D:P(A;;GA;;;S-1-5-21-1-2-3-1001)");
        for bad in ["", "S-1-", "S-1-5-21)(A;;GA;;;WD", "s-1-5-18", "S-2-5-18"] {
            assert!(SidString::try_from(bad.to_string()).is_err(), "{bad:?}");
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
