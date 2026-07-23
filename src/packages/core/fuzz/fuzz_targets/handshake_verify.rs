#![no_main]
//! Fuzz the handshake VERIFIER, not just the frame decoder: strict hex MAC
//! decoding, HMAC verification, label validation, and the server accept path.
//! Every field is attacker-controlled pre-trust input, and a panic aborts the
//! MCP server under panic=abort - the pre-11706f7 hex_decode bug lived exactly
//! here. Also carries a correctness oracle, not just no-panic: the MAC
//! computed under the right key must always verify.
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

use chromium_bridge_core::ipc::{handshake_fuzz as hs, validate_label};

#[derive(Arbitrary, Debug)]
struct Input {
    key: Vec<u8>,
    provided_hex: String,
    nonce: String,
    label: Option<String>,
    secret: String,
    response_bytes: Vec<u8>,
}

fuzz_target!(|input: Input| {
    // Helper leg: the verifier's building blocks over hostile fields.
    let msg = hs::handshake_mac_message(&input.nonce, input.label.as_deref());
    let _ = hs::verify_mac(&input.key, &msg, &input.provided_hex);
    let _ = hs::hex_decode(&input.provided_hex);
    if let Some(label) = &input.label {
        let _ = validate_label(label);
    }

    // Oracle: the correctly computed MAC verifies.
    if let Ok(mac) = hs::compute_mac(&input.key, &msg) {
        hs::verify_mac(&input.key, &msg, &mac).expect("correct MAC must verify");
    }

    // Combined leg: the server accept path over a hostile response. The server
    // MAC-binds a fresh internal nonce, so a static response exercises the
    // fail-closed rejection path (the hostile-input surface); the success path
    // is the oracle above plus the socketpair round-trip unit tests.
    let mut reader = Cursor::new(input.response_bytes.as_slice());
    let mut out = Vec::new();
    let _ = hs::server_handshake_with_secret(&mut reader, &mut out, &input.secret);
});
