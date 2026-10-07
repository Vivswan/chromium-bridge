use std::io;

/// Fails closed when the CSPRNG is unavailable: a fallback (time, pid, address bits) would be guessable and
/// silently void the handshake's authentication, so the caller refuses to run instead.
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
