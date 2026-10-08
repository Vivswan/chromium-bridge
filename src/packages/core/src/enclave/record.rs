//! `host_key.json`: the host key's scalar when the user chose `pair --file-store`. The credential-store
//! alternative needs no record (store.rs derives its entry name), so this file's presence IS the choice.

use std::fmt;

use p256::elliptic_curve::zeroize::Zeroizing;
use p256::elliptic_curve::Generate as _;
use p256::SecretKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{base64_decode, base64_encode, EnclaveError};
use crate::runtime_record::{Ladder, Record};

/// The 0600 file the scalar lives in under `--file-store`. A same-user process editing it gains nothing: the
/// extension pins the public key, and a swapped scalar fails that pin closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostKeyFile {
    pub scalar: Scalar,
}

impl Record for HostKeyFile {
    const FILE: &'static str = "host_key.json";
    const MAX_BYTES: usize = 4 * 1024;
    const LADDER: Ladder = crate::migrations::host_key::LADDER;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStore {
    CredentialStore,
    File,
}

/// A P-256 private scalar, valid by construction (`p256` refuses zero and anything at or past the group
/// order, and samples a fresh one itself): zeroed on drop, base64 of exactly 32 big-endian bytes on the
/// wire, never printed. Equality is the library's constant-time compare.
#[derive(Clone, PartialEq, Eq)]
pub struct Scalar(SecretKey);

impl Scalar {
    pub fn random() -> Result<Self, EnclaveError> {
        SecretKey::try_generate_from_rng(&mut getrandom::SysRng)
            .map(Scalar)
            .map_err(|e| EnclaveError::Keychain(format!("csprng: {e}")))
    }

    /// Exactly 32 bytes; `SecretKey::from_slice` would zero-pad a shorter input, which is a second spelling.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnclaveError> {
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| EnclaveError::KeyInvalid("the stored scalar is not 32 bytes"))?;
        SecretKey::from_bytes(&array.into())
            .map(Scalar)
            .map_err(|_| EnclaveError::KeyInvalid("the stored scalar is not a P-256 private key"))
    }

    pub fn secret_key(&self) -> &SecretKey {
        &self.0
    }
}

impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Scalar(..)")
    }
}

impl Serialize for Scalar {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = Zeroizing::new(self.0.to_bytes());
        serializer.serialize_str(&base64_encode(bytes.as_slice()))
    }
}

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = Zeroizing::new(String::deserialize(deserializer)?);
        let bytes = Zeroizing::new(base64_decode(&text).map_err(serde::de::Error::custom)?);
        Scalar::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}
