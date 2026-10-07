use sha2::{Digest, Sha256};

use super::base64_encode;
use super::EnclaveError;

/// The X9.63 uncompressed point, `0x04 || X || Y`; the extension's verifier rejects any other length.
pub const PUBKEY_LEN: usize = 65;

/// Exactly what WebCrypto's `importKey("raw", ...)` accepts for ECDSA P-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnclavePublicKey {
    sec1: Vec<u8>,
}

impl EnclavePublicKey {
    pub fn from_x963(bytes: Vec<u8>) -> Result<Self, EnclaveError> {
        if bytes.len() != PUBKEY_LEN {
            return Err(EnclaveError::Keychain(format!(
                "public key is {} bytes, expected {PUBKEY_LEN} (X9.63 uncompressed P-256)",
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
        hex::encode(Sha256::digest(&self.sec1))
    }

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
        assert_eq!(
            pk.fingerprint_display().replace(' ', ""),
            pk.fingerprint_hex()
        );

        assert!(EnclavePublicKey::from_x963(vec![0x04; 64]).is_err());
        assert!(EnclavePublicKey::from_x963(vec![0x04; 66]).is_err());
        assert!(EnclavePublicKey::from_x963(Vec::new()).is_err());
        // Compressed-point prefix is rejected: the contract is uncompressed.
        let mut compressed = vec![0x02];
        compressed.extend_from_slice(&[0xab; 64]);
        assert!(EnclavePublicKey::from_x963(compressed).is_err());
    }
}
