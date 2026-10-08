#![no_main]
//! The internal bridge NDJSON envelope reader; the body is `targets::bridge_envelope`.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| genkan_fuzz::targets::bridge_envelope(data));
