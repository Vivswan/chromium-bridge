//! The kernel-attested client identity and its two typed values, parsed once
//! where a value enters (a measurement, a `trust.json` entry, a relayed attach
//! frame, a CLI flag) so no compare site re-validates. A wrong-form on-disk
//! value is never normalized: it fails the whole decode, which every caller
//! fails closed on.

use serde::{Deserialize, Serialize};

/// A measured image digest: a 20-byte macOS `cdhash`, or a 32-byte SHA-256 of
/// the image file (Linux `/proc/<pid>/exe`, the Windows image path), as
/// lowercase hex (40 or 64 characters). No other width or spelling can equal a
/// measurement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "envelope-schema",
    derive(schemars::JsonSchema),
    schemars(with = "String")
)]
#[serde(try_from = "String")]
pub struct HashDigest(String);

const DIGEST_WIDTHS: [usize; 2] = [20, 32];

impl HashDigest {
    /// The digest as its lowercase hex string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The SHA-256 of a file's contents, streamed: the image measurement on
    /// Linux (`/proc/<pid>/exe`) and Windows (the image path).
    #[cfg(any(target_os = "linux", windows))]
    pub(crate) fn of_file(path: &std::path::Path) -> std::io::Result<HashDigest> {
        use std::io::Read;

        use sha2::{Digest, Sha256};

        let mut file = std::fs::File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            // read() never returns more than buf.len(); a broken Read impl that
            // did would corrupt the identity hash, so refuse it instead.
            let chunk = buf.get(..n).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "read returned an impossible length",
                )
            })?;
            hasher.update(chunk);
        }
        HashDigest::try_from(hasher.finalize().as_slice())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

impl TryFrom<String> for HashDigest {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let canonical = DIGEST_WIDTHS.contains(&(value.len() / 2))
            && value.len().is_multiple_of(2)
            && value
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if canonical {
            Ok(HashDigest(value))
        } else {
            Err("hash anchor must be 40 or 64 lowercase hex characters".to_string())
        }
    }
}

impl TryFrom<&str> for HashDigest {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        HashDigest::try_from(value.to_string())
    }
}

impl TryFrom<&[u8]> for HashDigest {
    type Error = String;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if DIGEST_WIDTHS.contains(&bytes.len()) {
            Ok(HashDigest(hex::encode(bytes)))
        } else {
            Err(format!(
                "digest must be 20 or 32 bytes, got {}",
                bytes.len()
            ))
        }
    }
}

impl From<HashDigest> for String {
    fn from(digest: HashDigest) -> String {
        digest.0
    }
}

impl std::fmt::Display for HashDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The code signer read off a validated signature: the Apple Team ID on macOS,
/// the Authenticode signer's X.500 subject on Windows. Non-empty: an unsigned
/// or ad-hoc image measures no signer at all, so an empty anchor could never
/// match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "envelope-schema",
    derive(schemars::JsonSchema),
    schemars(with = "String")
)]
#[serde(try_from = "String")]
pub struct SignerId(String);

impl SignerId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SignerId {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Err("signer anchor must be non-empty".to_string())
        } else if value.contains('\0') {
            Err("signer anchor must not contain a NUL byte".to_string())
        } else {
            Ok(SignerId(value))
        }
    }
}

impl TryFrom<&str> for SignerId {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        SignerId::try_from(value.to_string())
    }
}

impl From<SignerId> for String {
    fn from(signer: SignerId) -> String {
        signer.0
    }
}

impl std::fmt::Display for SignerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A harness's kernel-attested code identity, the input to the trusted-client
/// allowlist decision ([`crate::allowlist`]). `signer` is present only for an
/// image whose signature names a publisher (always `None` on Linux and for
/// ad-hoc / unsigned builds).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIdentity {
    pub hash: HashDigest,
    pub signer: Option<SignerId>,
}

impl From<&crate::protocol::HarnessId> for ClientIdentity {
    /// The allowlist-input projection of a relayed harness identity. Drops
    /// `name` deliberately: it is a self-asserted log label, never an
    /// authorization key.
    fn from(h: &crate::protocol::HarnessId) -> Self {
        ClientIdentity {
            hash: h.hash.clone(),
            signer: h.signer.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_measured_digest_parses_back_equal_to_itself() {
        // The two constructors meet: what the measurement boundary produces
        // from bytes is exactly what the parse boundary accepts from text, so
        // a measured hash written to trust.json always reads back and
        // matches. Pins the encoder's lowercase output (an external fact of
        // the hex crate), which a parse of uppercase hex would silently reject.
        for (bytes, hex) in [
            (&[0xabu8; 20][..], "ab".repeat(20)),
            (&[0x0fu8; 32][..], "0f".repeat(32)),
        ] {
            let measured = HashDigest::try_from(bytes).unwrap();
            assert_eq!(measured.as_str(), hex);
            assert_eq!(HashDigest::try_from(measured.as_str()), Ok(measured));
        }
        // Bytes of a width no platform measures are refused the same way.
        assert!(HashDigest::try_from(&[0xabu8; 19][..]).is_err());
        assert!(HashDigest::try_from(&[][..]).is_err());
    }
}
