//! `seeds/handshake/`: the challenge and the HMAC response frames, read by `bridge_read::<Handshake>`.
//! The response MAC is the real HMAC under a fixed key, so the frame is one a verifier with that key
//! accepts.

use std::io::Cursor;

use genkan_core::ipc::{handshake_fuzz, validate_label};
use genkan_core::protocol::{bridge_read, Handshake};
use serde_json::json;

use super::{edited, ndjson, repeated_key, Directory, Seed};
use crate::targets;

fn reads(bytes: &[u8]) -> bool {
    matches!(
        bridge_read::<_, Handshake>(&mut Cursor::new(bytes)),
        Ok(Some(_))
    )
}

/// A `Response` whose label the verifier would honour: the frame decoder takes any string, the label
/// rule is applied after the MAC verifies.
fn reads_labelled_response(bytes: &[u8]) -> bool {
    match bridge_read::<_, Handshake>(&mut Cursor::new(bytes)) {
        Ok(Some(Handshake::Response {
            label: Some(label), ..
        })) => validate_label(&label),
        Ok(Some(Handshake::Response { label: None, .. } | Handshake::Challenge { .. }))
        | Ok(None)
        | Err(_) => false,
    }
}

pub(super) fn directory() -> Directory {
    let nonce = "0123456789abcdef0123456789abcdef";
    let secret = b"example-secret";
    let mac = |label: Option<&str>| {
        handshake_fuzz::compute_mac(secret, &handshake_fuzz::handshake_mac_message(nonce, label))
            .expect("HMAC over a non-empty key")
    };
    let challenge = json_of!(Handshake::Challenge {
        nonce: nonce.into()
    });
    let response = json_of!(Handshake::Response {
        mac: mac(Some("chrome")),
        label: Some("chrome".into()),
    });
    let unlabelled = json_of!(Handshake::Response {
        mac: mac(None),
        label: None,
    });
    Directory {
        target: targets::HANDSHAKE,
        seeds: vec![
            Seed::accepted("challenge", ndjson(&challenge), reads),
            Seed::accepted("response", ndjson(&response), reads_labelled_response),
            Seed::accepted("response_no_label", ndjson(&unlabelled), reads),
            Seed::refused(
                "unknown_type",
                ndjson(&edited(&challenge, |v| v["type"] = json!("hello"))),
                reads,
            ),
            Seed::refused(
                "response_unknown_field",
                ndjson(&edited(&response, |v| v["surprise"] = json!(true))),
                reads,
            ),
            Seed::refused(
                "response_mac_type",
                ndjson(&edited(&response, |v| v["mac"] = json!(1))),
                reads,
            ),
            Seed::refused(
                "response_label_over_bound",
                ndjson(&edited(&response, |v| v["label"] = json!("x".repeat(33)))),
                reads_labelled_response,
            ),
            Seed::refused(
                "response_repeated_key",
                [repeated_key(&response, "mac"), b"\n".to_vec()].concat(),
                reads,
            ),
        ],
    }
}
