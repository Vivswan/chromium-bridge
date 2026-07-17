#![no_main]
//! Fuzz the internal bridge NDJSON envelope reader (server<->native host). Even
//! an attested peer must not be able to crash the reader with malformed or
//! oversized input, so arbitrary bytes decoded as an arbitrary JSON value must
//! never panic.
use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let _: std::io::Result<Option<Value>> =
        chromium_bridge_core::protocol::bridge_read(&mut Cursor::new(data));
});
