#![no_main]
//! The strict-DER ECDSA signature parser; the body is `targets::enclave_der`.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| chromium_bridge_fuzz::targets::enclave_der(data));
