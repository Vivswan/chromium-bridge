#![no_main]
//! Fuzz the Chrome Native-Messaging frame decoder (4-byte LE length prefix +
//! JSON). It runs on the extension<->host boundary, so it must reject or decode
//! any bytes without panicking (a panic aborts the host under panic=abort).
//! Oracle: a decoded frame re-encodes to a frame that decodes to the same
//! value, and the encoder refuses only payloads over the outgoing cap.
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

use chromium_bridge_core::protocol::{nm_read_frame, nm_write_frame, NM_MAX_OUTGOING};

fuzz_target!(|data: &[u8]| {
    let Ok(Some(value)) = nm_read_frame(&mut Cursor::new(data)) else {
        return;
    };
    let mut bytes = Vec::new();
    match nm_write_frame(&mut bytes, &value) {
        Ok(()) => {
            let again = nm_read_frame(&mut Cursor::new(bytes.as_slice()))
                .expect("the encoded frame must decode")
                .expect("the encoded frame is one message");
            assert_eq!(
                again, value,
                "native-messaging decode -> encode -> decode must be identity"
            );
        }
        Err(_) => {
            let json = serde_json::to_vec(&value).expect("a decoded Value serializes");
            assert!(
                json.len() > NM_MAX_OUTGOING,
                "nm_write_frame refused a frame under the outgoing cap"
            );
        }
    }
});
