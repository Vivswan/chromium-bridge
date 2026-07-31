//! base64 (encode only - the proof frame carries sig + pubkey as base64).

/// Standard-alphabet base64 with padding (RFC 4648). Encode-only, so no
/// dependency is pulled in for one direction of one codec.
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));
    for chunk in bytes.chunks(3) {
        // chunks(3) yields 1..=3 bytes, so the first byte always exists;
        // absent bytes contribute zero bits and pad with '='.
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied();
        let b2 = chunk.get(2).copied();
        out.push(sextet(b0 >> 2));
        out.push(sextet(((b0 & 0x03) << 4) | (b1.unwrap_or(0) >> 4)));
        out.push(match b1 {
            Some(b1) => sextet(((b1 & 0x0f) << 2) | (b2.unwrap_or(0) >> 6)),
            None => '=',
        });
        out.push(match b2 {
            Some(b2) => sextet(b2 & 0x3f),
            None => '=',
        });
    }
    out
}

/// Standard-alphabet character for one 6-bit group. A total match on the
/// masked value: no table indexing, no arithmetic, no fallback that could
/// silently emit wrong proof material.
fn sextet(v: u8) -> char {
    match v & 63 {
        0 => 'A',
        1 => 'B',
        2 => 'C',
        3 => 'D',
        4 => 'E',
        5 => 'F',
        6 => 'G',
        7 => 'H',
        8 => 'I',
        9 => 'J',
        10 => 'K',
        11 => 'L',
        12 => 'M',
        13 => 'N',
        14 => 'O',
        15 => 'P',
        16 => 'Q',
        17 => 'R',
        18 => 'S',
        19 => 'T',
        20 => 'U',
        21 => 'V',
        22 => 'W',
        23 => 'X',
        24 => 'Y',
        25 => 'Z',
        26 => 'a',
        27 => 'b',
        28 => 'c',
        29 => 'd',
        30 => 'e',
        31 => 'f',
        32 => 'g',
        33 => 'h',
        34 => 'i',
        35 => 'j',
        36 => 'k',
        37 => 'l',
        38 => 'm',
        39 => 'n',
        40 => 'o',
        41 => 'p',
        42 => 'q',
        43 => 'r',
        44 => 's',
        45 => 't',
        46 => 'u',
        47 => 'v',
        48 => 'w',
        49 => 'x',
        50 => 'y',
        51 => 'z',
        52 => '0',
        53 => '1',
        54 => '2',
        55 => '3',
        56 => '4',
        57 => '5',
        58 => '6',
        59 => '7',
        60 => '8',
        61 => '9',
        62 => '+',
        // Masked to 0..=63 above, so this arm is exactly 63.
        _ => '/',
    }
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

    #[test]
    fn base64_alphabet_is_exhaustive_and_ordered() {
        // A one-byte chunk's first character is the byte's top 6 bits, so
        // encoding v << 2 walks the whole alphabet in order - pinning every
        // arm of the sextet match.
        let alphabet: String = (0u8..64)
            .map(|v| base64_encode(&[v << 2]).chars().next().unwrap())
            .collect();
        assert_eq!(
            alphabet,
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        );
    }
}
