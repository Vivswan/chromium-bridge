//! base64 (encode only - the proof frame carries sig + pubkey as base64).

/// Standard-alphabet base64 with padding (RFC 4648). Encode-only, so no
/// dependency is pulled in for one direction of one codec.
pub fn base64_encode(bytes: &[u8]) -> String {
    // Standard-alphabet character for one 6-bit group. A total match on the
    // masked value: no table indexing, no fallback that could silently emit
    // wrong proof material.
    let sextet = |n: u32, shift: u32| -> char {
        // The & 63 mask bounds the value to 6 bits, so the u8 cast is exact.
        let v = ((n >> shift) & 63) as u8;
        match v {
            0..=25 => char::from(b'A' + v),
            26..=51 => char::from(b'a' + (v - 26)),
            52..=61 => char::from(b'0' + (v - 52)),
            62 => '+',
            // v is masked to 0..=63, so this arm is exactly 63.
            _ => '/',
        }
    };
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        // chunks(3) yields 1..=3 bytes, so the first byte always exists.
        let b0 = chunk.first().copied().unwrap_or(0) as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(sextet(n, 18));
        out.push(sextet(n, 12));
        out.push(if chunk.len() > 1 { sextet(n, 6) } else { '=' });
        out.push(if chunk.len() > 2 { sextet(n, 0) } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_rfc4648_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }
}
