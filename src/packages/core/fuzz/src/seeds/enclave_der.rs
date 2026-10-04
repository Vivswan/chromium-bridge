//! `seeds/enclave_der/`: strict-DER ECDSA-Sig-Value inputs for `der_to_raw_signature`. The valid
//! signatures come from the core's own test-and-fuzz DER encoder, the one its round-trip tests use.

use chromium_bridge_core::enclave::{der_to_raw_signature, raw_to_der};

use super::{Directory, Seed};
use crate::targets;

fn reads(bytes: &[u8]) -> bool {
    der_to_raw_signature(bytes).is_ok()
}

pub(super) fn directory() -> Directory {
    let one = {
        let mut scalar = [0u8; 32];
        scalar[31] = 1;
        scalar
    };
    let two_bytes = {
        let mut scalar = [0u8; 32];
        scalar[30] = 2;
        scalar[31] = 3;
        scalar
    };
    let minimal = raw_to_der(&one, &one);
    let full = raw_to_der(&[0x80; 32], &[0xff; 32]);
    let short = raw_to_der(&one, &two_bytes);
    let long_form = [vec![0x30, 0x81], full[1..].to_vec()].concat();
    let negative = [minimal[..4].to_vec(), vec![0x81], minimal[5..].to_vec()].concat();
    Directory {
        target: targets::ENCLAVE_DER,
        seeds: vec![
            Seed::accepted("sig_minimal", minimal, reads),
            Seed::accepted("sig_full_width_sign_padded", full.clone(), reads),
            Seed::accepted("sig_short_scalars", short, reads),
            Seed::refused("truncated_header", full[..3].to_vec(), reads),
            Seed::refused("truncated_mid_integer", full[..10].to_vec(), reads),
            Seed::refused("long_form_length", long_form, reads),
            Seed::refused("trailing_byte", [full, vec![0x00]].concat(), reads),
            Seed::refused("negative_integer", negative, reads),
            Seed::refused("empty", Vec::new(), reads),
        ],
    }
}
