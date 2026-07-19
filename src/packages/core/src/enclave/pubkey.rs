//! The enrollment key's public half (65-byte X9.63 uncompressed P-256 point)
//! and its fingerprints.

use sha2::{Digest, Sha256};

use super::encoding::base64_encode;
use super::EnclaveError;

/// The enrollment key's public half, validated to be a 65-byte uncompressed
/// X9.63 P-256 point (`0x04 || X || Y`) - exactly what WebCrypto's
/// `importKey("raw", ...)` accepts for ECDSA P-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnclavePublicKey {
    sec1: Vec<u8>,
}

impl EnclavePublicKey {
    pub fn from_x963(bytes: Vec<u8>) -> Result<Self, EnclaveError> {
        if bytes.len() != 65 {
            return Err(EnclaveError::Keychain(format!(
                "public key is {} bytes, expected 65 (X9.63 uncompressed P-256)",
                bytes.len()
            )));
        }
        // Length 65 was just checked, so a first byte exists; 0 is not 0x04,
        // so the impossible empty case still lands in the error arm.
        let lead = bytes.first().copied().unwrap_or(0);
        if lead != 0x04 {
            return Err(EnclaveError::Keychain(format!(
                "public key does not start with 0x04 (uncompressed point), got 0x{lead:02x}",
            )));
        }
        Ok(Self { sec1: bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.sec1
    }

    pub fn to_base64(&self) -> String {
        base64_encode(&self.sec1)
    }

    /// SHA-256 of the 65 raw point bytes, lowercase hex. This is the `key_id`
    /// in `enclave_proof` frames and the fingerprint the user compares between
    /// the `pair` terminal output and the extension's enrollment UI.
    pub fn fingerprint_hex(&self) -> String {
        crate::ipc::hex_encode(Sha256::digest(&self.sec1).as_slice())
    }

    /// Fingerprint grouped in 4-char blocks for human comparison.
    pub fn fingerprint_display(&self) -> String {
        let hex = self.fingerprint_hex();
        hex.as_bytes()
            .chunks(4)
            .map(String::from_utf8_lossy)
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_parse_validates_shape() {
        let mut good = vec![0x04];
        good.extend_from_slice(&[0xab; 64]);
        let pk = EnclavePublicKey::from_x963(good.clone()).unwrap();
        assert_eq!(pk.as_bytes(), &good[..]);
        assert_eq!(pk.fingerprint_hex().len(), 64);
        // Grouped display covers the same hex.
        assert_eq!(
            pk.fingerprint_display().replace(' ', ""),
            pk.fingerprint_hex()
        );

        // Wrong length.
        assert!(EnclavePublicKey::from_x963(vec![0x04; 64]).is_err());
        assert!(EnclavePublicKey::from_x963(vec![0x04; 66]).is_err());
        assert!(EnclavePublicKey::from_x963(Vec::new()).is_err());
        // Compressed-point prefix is rejected: the contract is uncompressed.
        let mut compressed = vec![0x02];
        compressed.extend_from_slice(&[0xab; 64]);
        assert!(EnclavePublicKey::from_x963(compressed).is_err());
    }
}
