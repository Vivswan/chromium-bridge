#![no_main]
//! The Chrome Native-Messaging frame decoder; the body and its oracle are `targets::nm_frame`.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| chromium_bridge_fuzz::targets::nm_frame(data));
