#![no_main]
//! Fuzz the authenticated-handshake frame decoder (Challenge / Response). These
//! frames arrive from a peer before it is trusted, so the decoder must survive
//! any bytes (a malformed MAC or label must fail closed, never panic). Oracle:
//! a decoded frame re-encodes to a frame that decodes to the same value, so
//! the MAC and label a verifier reads are the ones the peer wrote.
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

use chromium_bridge_core::protocol::{bridge_read, bridge_write, Handshake, BRIDGE_MAX_LINE};

fuzz_target!(|data: &[u8]| {
    let Ok(Some(first)) = bridge_read::<_, Handshake>(&mut Cursor::new(data)) else {
        return;
    };
    let mut bytes = Vec::new();
    bridge_write(&mut bytes, &first).expect("a decoded Handshake must encode");
    // The reader's cap counts the trailing newline the writer adds, so an
    // input of exactly the cap re-encodes one byte over it and is rightly
    // refused; identity is required of everything under the cap.
    if bytes.len() > BRIDGE_MAX_LINE {
        return;
    }
    let second: Handshake = bridge_read(&mut Cursor::new(bytes.as_slice()))
        .expect("the encoded frame must decode")
        .expect("the encoded frame is one line");
    assert_eq!(
        serde_json::to_value(&first).expect("Handshake serializes"),
        serde_json::to_value(&second).expect("Handshake serializes"),
        "Handshake decode -> encode -> decode must be identity"
    );
});
