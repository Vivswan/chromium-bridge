#![no_main]
//! Fuzz the internal bridge NDJSON envelope reader (server<->native host). Even
//! an attested peer must not be able to crash the reader with malformed or
//! oversized input, so arbitrary bytes decoded as an arbitrary JSON value must
//! never panic. The same bytes are also decoded as the two typed frames:
//! [`ParsedResp`], the session's production read path, whose `TryFrom`
//! refuses contradictory responses; and [`BridgeReq`], which Rust production
//! only constructs and writes (the extension is its inbound parser) but whose
//! flattened command pins the shape the extension must accept, so its typed
//! decode is held panic-free here too.
use chromium_bridge_core::protocol::{BridgeReq, ParsedResp};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let _: std::io::Result<Option<Value>> =
        chromium_bridge_core::protocol::bridge_read(&mut Cursor::new(data));
    let _: std::io::Result<Option<BridgeReq>> =
        chromium_bridge_core::protocol::bridge_read(&mut Cursor::new(data));
    let _: std::io::Result<Option<ParsedResp>> =
        chromium_bridge_core::protocol::bridge_read(&mut Cursor::new(data));
});
