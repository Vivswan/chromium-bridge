//! The credential-store seam, through `keyring`: one entry per runtime directory, named [`super::KEY_LABEL`]
//! plus a digest of the directory's path. The store is per OS user while everything else here is per runtime
//! directory, and the name must be derivable after the directory is gone (a Linux session runtime directory
//! is cleared at logout), so nothing has to remember it.
//!
//! ```text
//! two directories (a protocol suite's beside the real one) -> two entries, never one shared
//! a test build                                             -> compiled against no store: holds nothing and
//!                                                             refuses every write, so no test reaches the
//!                                                             developer's Keychain
//! ```

use p256::elliptic_curve::zeroize::Zeroizing;

use super::EnclaveError;

#[cfg(not(test))]
mod real {
    use sha2::{Digest, Sha256};

    use crate::enclave::{EnclaveError, KEY_LABEL};

    /// `keyring` keys an entry on a service and a user; the project is the service, the versioned name plus
    /// the runtime directory's digest the user.
    const SERVICE: &str = "chromium-bridge";

    pub(super) fn entry() -> Result<keyring::Entry, EnclaveError> {
        let dir = crate::ipc::RuntimeDir::resolve()
            .map_err(|e| EnclaveError::Keychain(format!("runtime dir: {e}")))?;
        let digest = Sha256::digest(path_bytes(dir.as_path()));
        let suffix = hex::encode(digest.get(..16).unwrap_or_default());
        keyring::Entry::new(SERVICE, &format!("{KEY_LABEL}.{suffix}")).map_err(classify)
    }

    /// The path's own bytes, lossless: two directories that differ only in a byte no string can carry must
    /// not hash to one entry.
    #[cfg(unix)]
    fn path_bytes(path: &std::path::Path) -> Vec<u8> {
        use std::os::unix::ffi::OsStrExt as _;
        path.as_os_str().as_bytes().to_vec()
    }

    #[cfg(windows)]
    fn path_bytes(path: &std::path::Path) -> Vec<u8> {
        use std::os::windows::ffi::OsStrExt as _;
        path.as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    /// `keyring::Error` is `non_exhaustive`; the callers match `NoEntry` before this, so every variant here
    /// is a store that did not do what was asked. Two entries under one name is a planted duplicate, never a
    /// choice to make silently.
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "keyring::Error is non_exhaustive; the callers match NoEntry before classify"
    )]
    pub(super) fn classify(e: keyring::Error) -> EnclaveError {
        match e {
            keyring::Error::Ambiguous(_) => EnclaveError::KeyInvalid(
                "multiple credential-store entries carry the host key name",
            ),
            other => EnclaveError::Keychain(format!("credential store: {other}")),
        }
    }
}

pub(super) fn set(scalar: &[u8]) -> Result<(), EnclaveError> {
    #[cfg(not(test))]
    {
        real::entry()?.set_secret(scalar).map_err(real::classify)
    }
    #[cfg(test)]
    {
        let _ = scalar;
        Err(EnclaveError::Keychain(
            "no credential store is reachable from a test build".into(),
        ))
    }
}

/// `Ok(None)` is the one absent answer: the store answered and holds no entry.
pub(super) fn get() -> Result<Option<Zeroizing<Vec<u8>>>, EnclaveError> {
    #[cfg(not(test))]
    {
        match real::entry()?.get_secret() {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(real::classify(e)),
        }
    }
    #[cfg(test)]
    {
        Ok(None)
    }
}

/// Delete the entry and confirm it is gone. The macOS backend of the pinned `keyring` discards the OS status
/// of the delete, so the read-back is the only evidence the scalar left the store.
pub(super) fn delete() -> Result<(), EnclaveError> {
    #[cfg(not(test))]
    {
        match real::entry()?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {}
            Err(e) => return Err(real::classify(e)),
        }
    }
    match get()? {
        None => Ok(()),
        Some(_) => Err(EnclaveError::Keychain(
            "the credential store still holds the host key after deleting it".into(),
        )),
    }
}
