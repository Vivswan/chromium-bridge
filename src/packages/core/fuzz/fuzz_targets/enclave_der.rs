#![no_main]
//! Fuzz the hand-written strict-DER parser that converts Security.framework
//! ECDSA signatures to WebCrypto's raw r||s form. Its input is normally
//! framework-produced, but zero trust says the byte parser itself must reject
//! any corruption without panicking.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = chromium_bridge_core::enclave::der_to_raw_signature(data);
});
