#![no_main]
//! The policy store parse surface; the body and its oracles are `targets::policy_doc`.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| chromium_bridge_fuzz::targets::policy_doc(data));
