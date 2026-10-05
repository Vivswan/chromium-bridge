//! The one base64url engine behind every WebAuthn byte field on the wire (challenge, credential ids,
//! authenticator data, clientDataJSON, signatures): unpadded, as `PublicKeyCredential.toJSON()` spells them.

use base64::Engine as _;

pub fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The exact inverse of [`encode`]: padding and nonzero trailing bits are refused, so every byte string has
/// one accepted spelling and a signed field cannot be re-spelled without failing to decode.
pub fn decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input)
}
