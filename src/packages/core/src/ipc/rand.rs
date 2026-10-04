//! The per-run secret and the handshake nonces: 128 bits from the OS CSPRNG,
//! hex-encoded.

use std::io;

/// 128 bits from the OS CSPRNG, hex-encoded. Used for the per-run secret that
/// keys the HMAC handshake and for the per-connection challenge nonces. Fails
/// closed if the CSPRNG is unavailable: a weaker fallback (time, pid, address
/// bits) would be guessable and silently void the authentication guarantee, so
/// the caller must refuse to proceed instead.
pub(crate) fn generate_secret() -> io::Result<String> {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf)?;
    Ok(hex::encode(buf))
}

/// The image-identity measurements in `ipc::platform` reach the hex encoder
/// through this name; they are owned by another change and move to
/// `hex::encode` directly with it.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_is_32_hex_chars_and_unique() {
        let s = generate_secret().unwrap();
        assert_eq!(s.len(), 32);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
        // 128 bits from the CSPRNG: two draws colliding means the RNG is
        // broken (or the fail-closed path silently regressed to something
        // deterministic).
        assert_ne!(s, generate_secret().unwrap());
    }
}
