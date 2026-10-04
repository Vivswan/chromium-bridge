#![no_main]
//! Fuzz the MCP JSON-RPC NDJSON reader. It runs on the harness<->server (and
//! relay) stdio boundary, the most likely target of a prompt-injection-hijacked
//! client, so arbitrary bytes must never panic it. Oracle: a decoded message
//! re-encodes to a line that decodes to the same value, so a relay forwarding
//! a message cannot change what the broker reads.
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

use chromium_bridge_core::protocol::{mcp_read, mcp_write, JsonRpc, MCP_MAX_LINE};

fuzz_target!(|data: &[u8]| {
    let Ok(Some(first)) = mcp_read(&mut Cursor::new(data)) else {
        return;
    };
    let mut bytes = Vec::new();
    mcp_write(&mut bytes, &first).expect("a decoded JsonRpc must encode");
    // The reader's cap counts the trailing newline the writer adds, so an
    // input of exactly the cap re-encodes one byte over it and is rightly
    // refused; identity is required of everything under the cap.
    if bytes.len() > MCP_MAX_LINE {
        return;
    }
    let second: JsonRpc = mcp_read(&mut Cursor::new(bytes.as_slice()))
        .expect("the encoded line must decode")
        .expect("the encoded line is one message");
    assert_eq!(
        serde_json::to_value(&first).expect("JsonRpc serializes"),
        serde_json::to_value(&second).expect("JsonRpc serializes"),
        "JsonRpc decode -> encode -> decode must be identity"
    );
});
