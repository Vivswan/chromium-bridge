//! base64 (standard alphabet): encode for the proof frames, strict decode
//! for the signed policy baseline (ADR-0032). Hand-rolled both ways so no
//! dependency is pulled in for one codec.

/// Standard-alphabet base64 with padding (RFC 4648).
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

/// A base64 string [`base64_decode`] refused. The reason is diagnostic only;
/// every rejection means the same thing to a caller - the input is not the
/// canonical encoding of any byte string.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid base64: {0}")]
pub struct Base64DecodeError(&'static str);

/// Strict standard-alphabet base64 decode (RFC 4648): the exact inverse of
/// [`base64_encode`], accepting only what it emits. Padding is required,
/// non-alphabet bytes (whitespace included) are refused, and so are
/// non-canonical encodings (nonzero trailing bits, e.g. `Zh==`), so every
/// byte string has exactly one accepted spelling - no two spellings of one
/// signed document.
pub fn base64_decode(input: &str) -> Result<Vec<u8>, Base64DecodeError> {
    let bytes = input.as_bytes();
    let exact = bytes.chunks_exact(4);
    if !exact.remainder().is_empty() {
        return Err(Base64DecodeError("length is not a multiple of 4"));
    }
    let mut out = Vec::with_capacity(bytes.len().div_ceil(4).saturating_mul(3));
    let mut chunks = exact.peekable();
    while let Some(chunk) = chunks.next() {
        let is_last = chunks.peek().is_none();
        // chunks_exact(4) yields exactly 4 bytes; the error arm cannot fire.
        let [c0, c1, c2, c3]: [u8; 4] = chunk
            .try_into()
            .map_err(|_| Base64DecodeError("chunk is not 4 bytes"))?;
        let v0 = unsextet(c0)?;
        let v1 = unsextet(c1)?;
        out.push((v0 << 2) | (v1 >> 4));
        match (c2, c3) {
            (b'=', b'=') => {
                if !is_last {
                    return Err(Base64DecodeError("padding before the final group"));
                }
                if v1 & 0x0f != 0 {
                    return Err(Base64DecodeError("nonzero trailing bits"));
                }
            }
            (b'=', _) => return Err(Base64DecodeError("malformed padding")),
            (_, b'=') => {
                if !is_last {
                    return Err(Base64DecodeError("padding before the final group"));
                }
                let v2 = unsextet(c2)?;
                if v2 & 0x03 != 0 {
                    return Err(Base64DecodeError("nonzero trailing bits"));
                }
                out.push(((v1 & 0x0f) << 4) | (v2 >> 2));
            }
            (_, _) => {
                let v2 = unsextet(c2)?;
                let v3 = unsextet(c3)?;
                out.push(((v1 & 0x0f) << 4) | (v2 >> 2));
                out.push(((v2 & 0x03) << 6) | v3);
            }
        }
    }
    Ok(out)
}

/// 6-bit group for one standard-alphabet character: the exact inverse of
/// [`sextet`], in the same style - a total match, no table indexing, no
/// arithmetic, and every non-alphabet byte (including `=`, handled by the
/// caller) refused.
fn unsextet(c: u8) -> Result<u8, Base64DecodeError> {
    match c {
        b'A' => Ok(0),
        b'B' => Ok(1),
        b'C' => Ok(2),
        b'D' => Ok(3),
        b'E' => Ok(4),
        b'F' => Ok(5),
        b'G' => Ok(6),
        b'H' => Ok(7),
        b'I' => Ok(8),
        b'J' => Ok(9),
        b'K' => Ok(10),
        b'L' => Ok(11),
        b'M' => Ok(12),
        b'N' => Ok(13),
        b'O' => Ok(14),
        b'P' => Ok(15),
        b'Q' => Ok(16),
        b'R' => Ok(17),
        b'S' => Ok(18),
        b'T' => Ok(19),
        b'U' => Ok(20),
        b'V' => Ok(21),
        b'W' => Ok(22),
        b'X' => Ok(23),
        b'Y' => Ok(24),
        b'Z' => Ok(25),
        b'a' => Ok(26),
        b'b' => Ok(27),
        b'c' => Ok(28),
        b'd' => Ok(29),
        b'e' => Ok(30),
        b'f' => Ok(31),
        b'g' => Ok(32),
        b'h' => Ok(33),
        b'i' => Ok(34),
        b'j' => Ok(35),
        b'k' => Ok(36),
        b'l' => Ok(37),
        b'm' => Ok(38),
        b'n' => Ok(39),
        b'o' => Ok(40),
        b'p' => Ok(41),
        b'q' => Ok(42),
        b'r' => Ok(43),
        b's' => Ok(44),
        b't' => Ok(45),
        b'u' => Ok(46),
        b'v' => Ok(47),
        b'w' => Ok(48),
        b'x' => Ok(49),
        b'y' => Ok(50),
        b'z' => Ok(51),
        b'0' => Ok(52),
        b'1' => Ok(53),
        b'2' => Ok(54),
        b'3' => Ok(55),
        b'4' => Ok(56),
        b'5' => Ok(57),
        b'6' => Ok(58),
        b'7' => Ok(59),
        b'8' => Ok(60),
        b'9' => Ok(61),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(Base64DecodeError("byte outside the standard alphabet")),
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

    #[test]
    fn base64_decode_round_trips_encode() {
        // The RFC vectors, both directions.
        for (bytes, b64) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_decode(b64).unwrap(), bytes);
            assert_eq!(base64_decode(&base64_encode(bytes)).unwrap(), bytes);
        }
        // Every byte value, at every offset within a 3-byte group - pinning
        // every arm of the unsextet match through the encoder.
        let all: Vec<u8> = (0u8..=255).collect();
        assert_eq!(base64_decode(&base64_encode(&all)).unwrap(), all);
        assert_eq!(base64_decode(&base64_encode(&all[1..])).unwrap(), all[1..]);
        assert_eq!(base64_decode(&base64_encode(&all[2..])).unwrap(), all[2..]);
    }

    #[test]
    fn base64_decode_rejects_invalid_input() {
        for bad in [
            // Not a multiple of 4.
            "Z", "Zg", "Zg=", "Zm9vYQ",
            // Bytes outside the standard alphabet (whitespace, url-safe, and
            // non-ASCII included) - strictness means no tolerated variants.
            "Zm9v\n", "Zm 9v", "Zm9-", "Zm9_", "Zm\u{e9}",
            // Malformed or misplaced padding.
            "====", "Z===", "Zg=v", "Zg==Zg==", "Zm8=Zm8=",
            // Non-canonical trailing bits: decode(x) must be the unique
            // spelling encode emits ("Zg==" and "Zm8=" are the canonical
            // forms).
            "Zh==", "Zm9=",
        ] {
            assert!(base64_decode(bad).is_err(), "{bad:?} must be refused");
        }
        // The reason is diagnostic, but the type is comparable for tests.
        assert_eq!(
            base64_decode("Zg="),
            Err(Base64DecodeError("length is not a multiple of 4"))
        );
    }
}
