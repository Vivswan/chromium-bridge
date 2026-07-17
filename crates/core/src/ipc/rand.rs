//! OS-CSPRNG-backed secrets and hex encoding, shared by the lock file's
//! per-run secret, the handshake nonces, and the enclave module's
//! fingerprints.

use std::io;

/// 128 bits from the OS CSPRNG, hex-encoded. Used for the per-run secret that
/// keys the HMAC handshake and for the per-connection challenge nonces. Fails
/// closed if the CSPRNG is unavailable: a weaker fallback (time, pid, address
/// bits) would be guessable and silently void the authentication guarantee, so
/// the caller must refuse to proceed instead.
pub(crate) fn generate_secret() -> io::Result<String> {
    let mut buf = [0u8; 16];
    fill_os_random(&mut buf)?;
    Ok(hex_encode(&buf))
}

#[cfg(unix)]
fn fill_os_random(buf: &mut [u8]) -> io::Result<()> {
    use std::io::Read;

    // We avoid pulling in `rand` by reading /dev/urandom directly (macOS and
    // Linux both expose it).
    let mut f = std::fs::File::open("/dev/urandom")?;
    f.read_exact(buf)
}

#[cfg(windows)]
fn fill_os_random(buf: &mut [u8]) -> io::Result<()> {
    super::platform::windows::fill_os_random(buf)
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
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
