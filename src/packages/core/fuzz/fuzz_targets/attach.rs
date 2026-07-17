#![no_main]
//! Fuzz the post-handshake role-declaration frame decoder (AttachRequest). A
//! peer sends exactly one of these before any session traffic; a malformed or
//! hostile frame must fail closed, never panic the broker.
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

use chromium_bridge_core::protocol::AttachRequest;

fuzz_target!(|data: &[u8]| {
    let _: std::io::Result<Option<AttachRequest>> =
        chromium_bridge_core::protocol::bridge_read(&mut Cursor::new(data));
});
