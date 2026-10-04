#![no_main]
//! Fuzz the native-messaging control-frame classifier: the router that decides whether an
//! extension-relayed frame is forwarded, answered, or dropped. Beyond "never panics", the oracles are
//! independent of the classifier's own reading of the frame: a frame is host control only when its
//! `type` is a string, that string is the tag's exact wire spelling, and a parsed request re-classifies
//! to itself from its own serialization (HostRequest's Serialize and Deserialize agree).
use libfuzzer_sys::fuzz_target;

use chromium_bridge_core::protocol::control::{classify_nm_frame, FrameDisposition};
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    let Ok(frame) = serde_json::from_slice::<Value>(data) else {
        return;
    };
    let type_field = frame.get("type").and_then(Value::as_str);
    match classify_nm_frame(&frame) {
        FrameDisposition::Forward => {}
        FrameDisposition::Handle(request) => {
            assert!(
                type_field.is_some(),
                "only a string `type` is a control tag: {frame}"
            );
            let Ok(again) = serde_json::to_value(&request) else {
                panic!("a parsed request serializes: {request:?}");
            };
            match classify_nm_frame(&again) {
                FrameDisposition::Handle(reparsed) => assert_eq!(
                    reparsed, request,
                    "a request re-classifies to itself from its own serialization"
                ),
                FrameDisposition::Forward | FrameDisposition::Malformed { .. } => {
                    panic!("a request's own serialization must classify as a request: {again}")
                }
            }
        }
        FrameDisposition::Malformed { tag, .. } => {
            assert_eq!(
                type_field,
                Some(tag.to_string().as_str()),
                "the frame's `type` is exactly the tag's wire spelling"
            );
            // Every tag has a defined answer; building it must not panic.
            let _reply = tag.malformed_reply();
        }
    }
});
