//! `seeds/nm_frame/`: length-prefixed native-messaging frames for `nm_read_frame`, the control frames
//! and a bridge response as the extension sends them, plus prefixes the decoder must refuse.

use std::io::Cursor;

use genkan_core::enclave::{base64_encode, SIG_LEN};
use genkan_core::policy::{PolicyDoc, PolicyOverlay};
use genkan_core::protocol::control::{HostRequest, KillStatus, PolicyControl, PolicyStatus};
use genkan_core::protocol::{nm_read_frame, BridgeResp};
use serde_json::json;

use super::{compact, nm, Directory, Seed};
use crate::targets;

fn reads(bytes: &[u8]) -> bool {
    matches!(nm_read_frame(&mut Cursor::new(bytes)), Ok(Some(_)))
}

pub(super) fn directory() -> Directory {
    let challenge = json_of!(HostRequest::EnclaveChallenge {
        nonce: "example-nonce".into(),
        context: Some("pair".into()),
    });
    let body = compact(&challenge);
    let frames = [
        ("enclave_challenge", challenge),
        (
            "kill_status_result",
            json_of!(KillStatus::Read { killed: false }.into_frame()),
        ),
        (
            "policy_current",
            json_of!(PolicyStatus::Present {
                baseline_b64: base64_encode(&compact(&json_of!(PolicyDoc::default()))),
                sig_b64: Some(base64_encode(&[0u8; SIG_LEN])),
                overlay: Some(PolicyOverlay {
                    page_eval_enabled: Some(false),
                    ..PolicyOverlay::default()
                }),
            }
            .into_frame()),
        ),
        (
            "lang_current",
            json_of!(PolicyControl::LangCurrent {
                value: "en".into(),
                seq: 1
            }),
        ),
        (
            "bridge_response",
            json_of!(BridgeResp::ok(1, json!({ "tabs": [] }))),
        ),
    ];
    let mut seeds: Vec<Seed> = frames
        .iter()
        .map(|(name, frame)| Seed::accepted(*name, nm(frame), reads))
        .collect();
    let overrun = u32::try_from(body.len() + 1).expect("a small frame");
    seeds.extend([
        Seed::refused("length_over_cap", u32::MAX.to_le_bytes().to_vec(), reads),
        Seed::refused(
            "length_overruns_body",
            [overrun.to_le_bytes().to_vec(), body].concat(),
            reads,
        ),
        Seed::refused(
            "body_not_json",
            [4u32.to_le_bytes().to_vec(), b"nope".to_vec()].concat(),
            reads,
        ),
        Seed::refused("truncated_prefix", vec![0x01, 0x00], reads),
    ]);
    Directory {
        target: targets::NM_FRAME,
        seeds,
    }
}
