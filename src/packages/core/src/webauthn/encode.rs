//! Encoders for the WebAuthn byte layouts, the inverse of the parsers: what the crate's tests sign over,
//! and what the fuzz workspace's seed corpus is built from (`fuzz/src/seeds/webauthn_authdata.rs`). Never
//! built into a shipped binary: the host only ever reads these layouts.

use coset::iana::{self, EnumI64 as _};
use coset::{CborSerializable as _, CoseKeyBuilder};

pub mod flags {
    pub const UP: u8 = 0x01;
    pub const UV: u8 = 0x04;
    pub const BE: u8 = 0x08;
    pub const BS: u8 = 0x10;
    pub const AT: u8 = 0x40;
    pub const ED: u8 = 0x80;
}

/// The P-256 generator as an uncompressed SEC1 point: a public key on the curve by definition, so a seed
/// or a fuzz oracle has a credential key without a private scalar anywhere near it.
pub const P256_GENERATOR_SEC1: [u8; 65] = [
    0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
    0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
    0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
    0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51,
    0xf5,
];

/// The attested block is written exactly when `attested` is given, whatever `flags` claims, so a seed can
/// lie about AT.
pub fn authenticator_data(
    rp_id_hash: &[u8; 32],
    flags: u8,
    sign_count: u32,
    attested: Option<(&[u8], &[u8])>,
) -> Vec<u8> {
    let mut out = rp_id_hash.to_vec();
    out.push(flags);
    out.extend_from_slice(&sign_count.to_be_bytes());
    if let Some((id, cose)) = attested {
        out.extend_from_slice(&[0xaa; 16]);
        let len = u16::try_from(id.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(id);
        out.extend_from_slice(cose);
    }
    out
}

/// The COSE algorithm identifiers the seeds and tests spell out: ES256 is the only one the verifier accepts.
pub const ES256: i64 = -7;
pub const RS256: i64 = -257;

/// A COSE EC2 P-256 key over the uncompressed SEC1 point `sec1`, under the COSE algorithm `alg` (an
/// unregistered number leaves `alg` absent, itself a refused shape). A point shorter than 65 bytes yields
/// the malformed-coordinates seed.
pub fn cose_ec2_key(sec1: &[u8], alg: i64) -> Vec<u8> {
    let (x, y) = sec1
        .get(1..)
        .map(|xy| xy.split_at(xy.len() / 2))
        .unwrap_or((&[], &[]));
    let key = CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x.to_vec(), y.to_vec());
    match iana::Algorithm::from_i64(alg) {
        Some(alg) => key.algorithm(alg),
        None => key,
    }
    .build()
    .to_vec()
    .unwrap_or_default()
}
