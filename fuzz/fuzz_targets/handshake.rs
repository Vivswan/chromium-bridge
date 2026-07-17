#![no_main]
//! Fuzz the authenticated-handshake frame decoder (Challenge / Response). These
//! frames arrive from a peer before it is trusted, so the decoder must survive
//! any bytes (a malformed MAC or label must fail closed, never panic).
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

use chromium_bridge_core::protocol::Handshake;

fuzz_target!(|data: &[u8]| {
    let _: std::io::Result<Option<Handshake>> =
        chromium_bridge_core::protocol::bridge_read(&mut Cursor::new(data));
});
