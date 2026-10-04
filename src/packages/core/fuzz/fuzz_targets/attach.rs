#![no_main]
//! Fuzz the post-handshake role-declaration frame decoder (AttachRequest). A
//! peer sends exactly one of these before any session traffic; a malformed or
//! hostile frame must fail closed, never panic the broker. Oracle: a decoded
//! frame re-encodes to a frame that decodes to the same value, so no accepted
//! input is read one way and written another.
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

use chromium_bridge_core::protocol::{bridge_read, bridge_write, AttachRequest, BRIDGE_MAX_LINE};

fuzz_target!(|data: &[u8]| {
    let Ok(Some(first)) = bridge_read::<_, AttachRequest>(&mut Cursor::new(data)) else {
        return;
    };
    let mut bytes = Vec::new();
    bridge_write(&mut bytes, &first).expect("a decoded AttachRequest must encode");
    // BRIDGE_MAX_LINE counts the newline the writer adds (see its doc), so exactly-cap input re-encodes over it.
    if bytes.len() > BRIDGE_MAX_LINE {
        return;
    }
    let second: AttachRequest = bridge_read(&mut Cursor::new(bytes.as_slice()))
        .expect("the encoded frame must decode")
        .expect("the encoded frame is one line");
    assert_eq!(
        serde_json::to_value(&first).expect("AttachRequest serializes"),
        serde_json::to_value(&second).expect("AttachRequest serializes"),
        "AttachRequest decode -> encode -> decode must be identity"
    );
});
