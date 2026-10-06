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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every handshake challenge comes from here, so a draw that repeats lets a captured response verify
    /// again; nothing else notices a generator that went deterministic.
    #[test]
    fn consecutive_draws_differ() {
        assert_ne!(generate_secret().unwrap(), generate_secret().unwrap());
    }
}
