//! DER (X9.62 ECDSA-Sig-Value) -> raw r||s (IEEE P1363, 64 bytes).

use super::EnclaveError;

/// Convert a DER-encoded ECDSA P-256 signature (what `SecKeyCreateSignature`
/// returns) to the fixed 64-byte `r || s` form WebCrypto's `verify` expects.
///
/// The parser is strict DER: definite lengths only, positive minimally-encoded
/// integers, no trailing bytes. The input always comes from Security.framework
/// (which emits strict DER), so any deviation is treated as corruption and
/// rejected rather than repaired.
pub fn der_to_raw_signature(der: &[u8]) -> Result<[u8; 64], EnclaveError> {
    let bad = EnclaveError::Signing;

    // SEQUENCE header. A P-256 ECDSA-Sig-Value body is at most 70 bytes
    // (2 INTEGERs of at most 33 value bytes + 2-byte headers), and DER
    // requires the minimal length form, so a valid signature can only ever
    // use the one-byte short form. Any long-form length (0x80..) is either
    // non-minimal or claims an impossible size; reject both outright.
    let (&tag, rest) = der
        .split_first()
        .ok_or_else(|| bad("empty signature".into()))?;
    if tag != 0x30 {
        return Err(bad(format!("expected SEQUENCE (0x30), got 0x{tag:02x}")));
    }
    let (&len_byte, rest) = rest
        .split_first()
        .ok_or_else(|| bad("truncated SEQUENCE length".into()))?;
    if len_byte >= 0x80 {
        return Err(bad(format!(
            "long-form SEQUENCE length 0x{len_byte:02x} cannot occur in a P-256 signature"
        )));
    }
    let (seq_len, body) = (len_byte as usize, rest);
    if body.len() != seq_len {
        return Err(bad(format!(
            "SEQUENCE length {seq_len} does not match body length {}",
            body.len()
        )));
    }

    let (r, body) = der_read_integer(body)?;
    let (s, body) = der_read_integer(body)?;
    if !body.is_empty() {
        return Err(bad("trailing bytes after s".into()));
    }

    let mut out = [0u8; 64];
    out[32 - r.len()..32].copy_from_slice(r);
    out[64 - s.len()..64].copy_from_slice(s);
    Ok(out)
}

/// Read one strict-DER INTEGER holding a positive value of at most 32 bytes.
/// Returns the value bytes with any single sign-padding 0x00 stripped, plus
/// the remaining input.
fn der_read_integer(input: &[u8]) -> Result<(&[u8], &[u8]), EnclaveError> {
    let bad = EnclaveError::Signing;

    let (&tag, rest) = input
        .split_first()
        .ok_or_else(|| bad("truncated INTEGER".into()))?;
    if tag != 0x02 {
        return Err(bad(format!("expected INTEGER (0x02), got 0x{tag:02x}")));
    }
    let (&len, rest) = rest
        .split_first()
        .ok_or_else(|| bad("truncated INTEGER length".into()))?;
    let len = len as usize;
    // 33 = 32 value bytes + one 0x00 sign pad. Anything longer cannot be a
    // P-256 scalar; the long length form (>= 0x80) is impossible below 34.
    if len == 0 || len > 33 {
        return Err(bad(format!("INTEGER length {len} out of range")));
    }
    if rest.len() < len {
        return Err(bad("INTEGER runs past end of input".into()));
    }
    let (value, remaining) = rest.split_at(len);

    // Positive, minimally encoded: a leading 0x00 is legal only as sign
    // padding for a value whose top bit is set, and a top bit set without
    // that padding would encode a negative number.
    let stripped = if value[0] == 0x00 {
        if value.len() == 1 {
            // INTEGER 0 — impossible for a valid ECDSA r or s, but it is
            // well-formed DER; map it to 32 zero bytes and let the verifier
            // reject the signature.
            &value[..0]
        } else if value[1] & 0x80 == 0 {
            return Err(bad("non-minimal INTEGER encoding".into()));
        } else {
            &value[1..]
        }
    } else if value[0] & 0x80 != 0 {
        return Err(bad("negative INTEGER".into()));
    } else {
        value
    };
    if stripped.len() > 32 {
        return Err(bad(format!(
            "INTEGER value {} bytes exceeds the 32-byte P-256 scalar",
            stripped.len()
        )));
    }
    Ok((stripped, remaining))
}

/// Minimal strict-DER encoder for ECDSA-Sig-Value, used to build test vectors
/// and roundtrip against the parser (also from the macOS software-key tests
/// in [`super::key`]). Test-only on purpose: the production path never needs
/// to *emit* DER.
#[cfg(test)]
pub(super) fn raw_to_der(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    fn integer(v: &[u8; 32]) -> Vec<u8> {
        let mut trimmed: &[u8] = v;
        while trimmed.len() > 1 && trimmed[0] == 0 {
            trimmed = &trimmed[1..];
        }
        let pad = trimmed[0] & 0x80 != 0;
        let mut out = vec![0x02, (trimmed.len() + usize::from(pad)) as u8];
        if pad {
            out.push(0x00);
        }
        out.extend_from_slice(trimmed);
        out
    }
    let body: Vec<u8> = [integer(r), integer(s)].concat();
    let mut out = vec![0x30];
    if body.len() < 0x80 {
        out.push(body.len() as u8);
    } else {
        out.push(0x81);
        out.push(body.len() as u8);
    }
    out.extend(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filled(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn der_roundtrip_plain_values() {
        // Top bits clear: 32-byte integers, no sign padding.
        let r = filled(0x11);
        let s = filled(0x7f);
        let der = raw_to_der(&r, &s);
        let raw = der_to_raw_signature(&der).unwrap();
        assert_eq!(&raw[..32], &r);
        assert_eq!(&raw[32..], &s);
    }

    #[test]
    fn der_roundtrip_high_bit_needs_sign_padding() {
        // Top bit set: DER carries a 33-byte INTEGER with a 0x00 sign pad —
        // the most likely first bug in a naive converter.
        let r = filled(0x80);
        let s = filled(0xff);
        let der = raw_to_der(&r, &s);
        // Both integers must be 33 bytes on the wire.
        assert_eq!(der[3], 33);
        let raw = der_to_raw_signature(&der).unwrap();
        assert_eq!(&raw[..32], &r);
        assert_eq!(&raw[32..], &s);
    }

    #[test]
    fn der_roundtrip_short_values_left_pad() {
        // Leading zero bytes are absent in DER; the converter must left-pad
        // back to 32 bytes.
        let mut r = [0u8; 32];
        r[31] = 0x01; // value 1 -> one-byte INTEGER
        let mut s = [0u8; 32];
        s[30] = 0x02;
        s[31] = 0x03; // two-byte INTEGER
        let der = raw_to_der(&r, &s);
        let raw = der_to_raw_signature(&der).unwrap();
        assert_eq!(&raw[..32], &r);
        assert_eq!(&raw[32..], &s);
    }

    #[test]
    fn der_zero_integer_is_wellformed() {
        // INTEGER 0 is valid DER (never a valid ECDSA scalar; the verifier
        // rejects the signature, not the parser).
        let der = [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00];
        let raw = der_to_raw_signature(&der).unwrap();
        assert_eq!(raw, [0u8; 64]);
    }

    #[test]
    fn der_long_form_length_is_rejected() {
        // Two 33-byte integers make the maximum body: 70 bytes, still short
        // form. DER's minimal-length rule means a valid P-256 signature can
        // never use the long form, so a long-form length is corruption even
        // when its value is internally consistent.
        let r = filled(0xaa);
        let s = filled(0xbb);
        let der = raw_to_der(&r, &s);
        assert_eq!(der[1], 70); // the biggest possible body is still short form
        let mut long = vec![0x30, 0x81, 70];
        long.extend_from_slice(&der[2..]);
        assert!(der_to_raw_signature(&long).is_err());
    }

    #[test]
    fn der_rejects_malformed_inputs() {
        let ok = raw_to_der(&filled(0x22), &filled(0x33));

        // Empty / truncated.
        assert!(der_to_raw_signature(&[]).is_err());
        assert!(der_to_raw_signature(&ok[..ok.len() - 1]).is_err());
        // Wrong outer tag.
        let mut bad = ok.clone();
        bad[0] = 0x31;
        assert!(der_to_raw_signature(&bad).is_err());
        // Wrong inner tag.
        let mut bad = ok.clone();
        bad[2] = 0x03;
        assert!(der_to_raw_signature(&bad).is_err());
        // Trailing garbage.
        let mut bad = ok.clone();
        bad.push(0x00);
        assert!(der_to_raw_signature(&bad).is_err());
        // Sequence length that overshoots the body.
        let mut bad = ok.clone();
        bad[1] += 1;
        assert!(der_to_raw_signature(&bad).is_err());
        // Negative integer (top bit set, no sign pad).
        let neg = [0x30, 0x08, 0x02, 0x02, 0x80, 0x01, 0x02, 0x02, 0x00, 0x81];
        assert!(der_to_raw_signature(&neg).is_err());
        // Non-minimal encoding (0x00 pad over a low top bit).
        let nonmin = [0x30, 0x08, 0x02, 0x03, 0x00, 0x01, 0x02, 0x02, 0x01, 0x02];
        assert!(der_to_raw_signature(&nonmin).is_err());
        // Zero-length integer.
        let empty_int = [0x30, 0x04, 0x02, 0x00, 0x02, 0x00];
        assert!(der_to_raw_signature(&empty_int).is_err());
        // Oversize integer: 33 value bytes without a legal sign pad.
        let mut oversize = vec![0x30, 72, 0x02, 34, 0x00];
        oversize.extend_from_slice(&[0x01; 33]);
        oversize.extend_from_slice(&[0x02, 32]);
        oversize.extend_from_slice(&[0x01; 32]);
        assert!(der_to_raw_signature(&oversize).is_err());
        // Unsupported multi-byte long form (cannot occur for P-256).
        let multi = [0x30, 0x82, 0x00, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        assert!(der_to_raw_signature(&multi).is_err());
    }

    mod der_fuzz {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Roundtrip: any (r, s) pair survives encode -> parse.
            #[test]
            fn roundtrip(r in prop::array::uniform32(any::<u8>()),
                         s in prop::array::uniform32(any::<u8>())) {
                let der = raw_to_der(&r, &s);
                let raw = der_to_raw_signature(&der).unwrap();
                prop_assert_eq!(&raw[..32], &r[..]);
                prop_assert_eq!(&raw[32..], &s[..]);
            }

            /// The parser never panics on arbitrary bytes (it runs on frames
            /// that cross a process boundary).
            #[test]
            fn never_panics(data in prop::collection::vec(any::<u8>(), 0..128)) {
                let _ = der_to_raw_signature(&data);
            }
        }
    }
}
