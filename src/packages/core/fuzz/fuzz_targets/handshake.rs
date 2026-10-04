#![no_main]
//! The authenticated-handshake frame decoder; the body and its oracle are `targets::handshake`.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| chromium_bridge_fuzz::targets::handshake(data));
