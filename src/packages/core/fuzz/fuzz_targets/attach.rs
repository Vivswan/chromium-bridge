#![no_main]
//! The post-handshake role-declaration frame decoder; the body and its oracle are `targets::attach`.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| genkan_fuzz::targets::attach(data));
