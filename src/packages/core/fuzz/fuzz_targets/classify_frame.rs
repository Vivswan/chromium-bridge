#![no_main]
//! Fuzz the native-messaging control-frame classifier: the router that decides whether an
//! extension-relayed frame is forwarded, answered, or dropped. Beyond "never panics", the oracles are
//! independent of the classifier's own reading of the frame: a forwarded frame carries no string `type`
//! that spells a control tag, a handled or malformed frame's `type` is exactly the tag it was read as, and
//! a parsed request re-classifies to itself from its own serialization (HostRequest's Serialize and
//! Deserialize agree).
use libfuzzer_sys::fuzz_target;

use chromium_bridge_core::protocol::control::{classify_nm_frame, FrameDisposition, HostControlTag};
use serde_json::Value;

/// The tag `type_field` spells, by serde's own reading of the string, or `None`.
fn spelled_tag(type_field: Option<&str>) -> Option<HostControlTag> {
    serde_json::from_value(Value::String(type_field?.to_string())).ok()
}

fuzz_target!(|data: &[u8]| {
    let Ok(frame) = serde_json::from_slice::<Value>(data) else {
        return;
    };
    let type_field = frame.get("type").and_then(Value::as_str);
    match classify_nm_frame(&frame) {
        FrameDisposition::Forward => assert!(
            spelled_tag(type_field).is_none(),
            "a forwarded frame carries no control tag: {frame}"
        ),
        FrameDisposition::Handle(request) => {
            let Ok(again) = serde_json::to_value(&request) else {
                panic!("a parsed request serializes: {request:?}");
            };
            assert_eq!(
                again.get("type").and_then(Value::as_str),
                type_field,
                "the parsed request's tag is the frame's `type`"
            );
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
