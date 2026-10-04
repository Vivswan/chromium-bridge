#![no_main]
//! The ours/foreign manifest decision; the body and its oracle are `targets::registration_manifest`.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| chromium_bridge_fuzz::targets::registration_manifest(data));
