#![no_main]
//! Fuzz the MCP JSON-RPC NDJSON reader. It runs on the harness<->server (and
//! relay) stdio boundary, the most likely target of a prompt-injection-hijacked
//! client, so arbitrary bytes must never panic it.
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let _ = chromium_bridge_core::protocol::mcp_read(&mut Cursor::new(data));
});
