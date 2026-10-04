//! `seeds/bridge_envelope/`: one request per catalogue tool (`bridge_read::<BridgeReq>`) and the
//! responses the session reads (`bridge_read::<ParsedResp>`).

use std::io::Cursor;

use chromium_bridge_core::protocol::{bridge_read, BridgeReq, BridgeResp, ParsedResp};
use serde_json::json;

use super::{edited, ndjson, repeated_key, tool_requests, without, Directory, Seed};
use crate::targets;

fn reads_request(bytes: &[u8]) -> bool {
    matches!(
        bridge_read::<_, BridgeReq>(&mut Cursor::new(bytes)),
        Ok(Some(_))
    )
}

fn reads_response(bytes: &[u8]) -> bool {
    matches!(
        bridge_read::<_, ParsedResp>(&mut Cursor::new(bytes)),
        Ok(Some(_))
    )
}

pub(super) fn directory() -> Directory {
    let mut seeds = Vec::new();
    let mut first_request = None;
    for (name, _, command) in tool_requests() {
        let request = json_of!(BridgeReq {
            id: 7,
            command,
            browser: Some("chrome".into()),
        });
        first_request.get_or_insert_with(|| request.clone());
        seeds.push(Seed::accepted(
            format!("request_{name}"),
            ndjson(&request),
            reads_request,
        ));
    }
    let request = first_request.expect("the catalogue has at least one tool");
    let ok = json_of!(BridgeResp::ok(7, json!({ "tabs": [] })));
    let err = json_of!(BridgeResp::err(7, "example error"));
    seeds.extend([
        Seed::accepted("response_ok", ndjson(&ok), reads_response),
        Seed::accepted("response_err", ndjson(&err), reads_response),
        Seed::refused(
            "request_unknown_op",
            ndjson(&edited(&request, |v| v["op"] = json!("example_op"))),
            reads_request,
        ),
        Seed::refused(
            "request_string_id",
            ndjson(&edited(&request, |v| v["id"] = json!("7"))),
            reads_request,
        ),
        Seed::refused(
            "request_unknown_field",
            ndjson(&edited(&request, |v| v["surprise"] = json!(true))),
            reads_request,
        ),
        Seed::refused(
            "request_args_unknown_field",
            ndjson(&edited(&request, |v| v["args"]["surprise"] = json!(true))),
            reads_request,
        ),
        Seed::refused(
            "request_repeated_id",
            [repeated_key(&request, "id"), b"\n".to_vec()].concat(),
            reads_request,
        ),
        Seed::refused(
            "response_ok_with_error",
            ndjson(&edited(&ok, |v| v["error"] = json!("example error"))),
            reads_response,
        ),
        Seed::refused(
            "response_err_with_data",
            ndjson(&edited(&err, |v| v["data"] = json!({}))),
            reads_response,
        ),
        Seed::refused(
            "response_err_without_error",
            ndjson(&without(&err, "error")),
            reads_response,
        ),
    ]);
    Directory {
        target: targets::BRIDGE_ENVELOPE,
        seeds,
    }
}
