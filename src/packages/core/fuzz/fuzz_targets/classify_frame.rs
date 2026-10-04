#![no_main]
//! The native-messaging control-frame classifier; the body and its oracles are `targets::classify_frame`.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| chromium_bridge_fuzz::targets::classify_frame(data));
