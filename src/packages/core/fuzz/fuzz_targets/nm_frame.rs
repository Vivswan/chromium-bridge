#![no_main]
//! Fuzz the Chrome Native-Messaging frame decoder (4-byte LE length prefix +
//! JSON). It runs on the extension<->host boundary, so it must reject or decode
//! any bytes without panicking (a panic aborts the host under panic=abort).
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let _ = chromium_bridge_core::protocol::nm_read_frame(&mut Cursor::new(data));
});
