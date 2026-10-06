use super::control::*;
use super::*;
use crate::tools::args::ElementTargetArgs;
use serde_json::json;
use std::io::Cursor;

#[test]
fn nm_read_eof_is_none() {
    let mut cur = Cursor::new(Vec::<u8>::new());
    assert!(nm_read_frame(&mut cur).unwrap().is_none());
}

#[test]
fn nm_write_rejects_oversize() {
    let v = json!({ "s": "x".repeat(NM_MAX_OUTGOING + 10) });
    let err = nm_write_frame(&mut Vec::new(), &v).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn ndjson_read_cap_boundary_is_exact() {
    // Pins the off-by-one the +1 sentinel guards, for a terminated line and
    // for an unterminated one (the hostile stream that never sends the
    // newline) alike. Valid JSON throughout, so a refusal here is the cap's
    // and not the decoder's.
    let line = br#"{"id":1,"op":"tab_list","args":{}}"#.to_vec();
    let mut terminated = line.clone();
    terminated.push(b'\n');
    for (row, wire) in [("terminated", terminated), ("unterminated", line)] {
        let total = wire.len();
        let got: Option<BridgeReq> =
            ndjson_read_capped(&mut Cursor::new(wire.clone()), total, "test")
                .unwrap_or_else(|e| panic!("{row}: a line exactly at the cap must parse: {e}"));
        assert_eq!(got.map(|req| req.id), Some(1), "{row}");
        let err = ndjson_read_capped::<_, BridgeReq>(&mut Cursor::new(wire), total - 1, "test")
            .err()
            .unwrap_or_else(|| panic!("{row}: one byte under the cap must refuse"));
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{row}");
    }
}

#[test]
fn ndjson_read_skips_blank_lines_without_recursing() {
    // Sized past any plausible stack depth, so a regression back to a
    // recursive skip (the reader's doc says why it loops) crashes rather
    // than passes.
    let mut buf = vec![b'\n'; 200_000];
    mcp_write(&mut buf, &JsonRpc::ok(json!(2), json!({}))).unwrap();
    let got = mcp_read(&mut Cursor::new(buf)).unwrap().unwrap();
    assert_eq!(got.id, Some(json!(2)));
}

#[test]
fn bridge_envelope_roundtrip() {
    let command = BridgeCommand::PageClick(ElementTargetArgs {
        r#ref: Some("e3".into()),
        selector: None,
    });
    let req = BridgeReq {
        id: 7,
        command: command.clone(),
        browser: Some("brave".into()),
    };
    let mut buf = Vec::new();
    bridge_write(&mut buf, &req).unwrap();
    // The wire form is the flat contract: the command's op and args beside
    // the envelope fields, camelCase names, no Rust field names.
    let wire: Value = serde_json::from_slice(&buf[..buf.len() - 1]).unwrap();
    assert_eq!(wire["op"], "page_click");
    assert_eq!(wire["args"], json!({ "ref": "e3" }));
    assert!(wire.get("command").is_none());
    let got: BridgeReq = bridge_read(&mut Cursor::new(buf)).unwrap().unwrap();
    assert_eq!(got.id, 7);
    assert_eq!(got.command, command);
    assert_eq!(got.browser.as_deref(), Some("brave"));

    // A request without the browser field (older peer) deserializes with
    // browser defaulted to None, and None is omitted on the wire.
    let bare: BridgeReq = bridge_read(&mut Cursor::new(
        b"{\"id\":1,\"op\":\"tab_list\",\"args\":{}}\n".to_vec(),
    ))
    .unwrap()
    .unwrap();
    assert_eq!(bare.browser, None);
    let mut buf = Vec::new();
    bridge_write(&mut buf, &bare).unwrap();
    assert!(!String::from_utf8(buf).unwrap().contains("browser"));
}

// The extension's parseBridgeReq refuses an op outside the catalogue and an
// arg outside the op's strictObject; the Rust reader must agree, or the two
// ends of the bridge accept different frames and a request the host would
// forward is one the extension drops (or the reverse). The envelope case is
// the control that already held before the typed command.
#[test]
fn bridge_req_parse_refuses_exactly_what_the_extension_refuses() {
    for wire in [
        r#"{"id":1,"op":"steal_cookies","args":{}}"#,
        r#"{"id":1,"op":"tab_focus","args":{"tabId":7,"extra":true}}"#,
        r#"{"id":1,"op":"tab_focus","args":{}}"#,
        r#"{"id":1,"op":"tab_focus","args":{"tabId":"7"}}"#,
        r#"{"id":1,"op":"page_click","args":{"ref":null}}"#,
        r#"{"id":1,"op":"tab_list"}"#,
        r#"{"id":1,"op":"tab_list","args":{},"extra":1}"#,
    ] {
        let err = bridge_read::<_, BridgeReq>(&mut Cursor::new(format!("{wire}\n"))).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{wire}");
    }
    // The same frames with the one offending part fixed parse, so the
    // refusals above are the typed command's, not a broken reader.
    for wire in [
        r#"{"id":1,"op":"tab_focus","args":{"tabId":7}}"#,
        r#"{"id":1,"op":"page_click","args":{}}"#,
        r#"{"id":1,"op":"tab_list","args":{},"browser":"brave"}"#,
    ] {
        let got: BridgeReq = bridge_read(&mut Cursor::new(format!("{wire}\n")))
            .unwrap()
            .unwrap_or_else(|| panic!("{wire}: EOF"));
        assert_eq!(got.id, 1, "{wire}");
    }
}

#[test]
fn wire_types_reject_unknown_fields() {
    // Zero trust, fail closed: an unexpected field on any bridge wire
    // frame is a protocol violation (a newer peer, a confused peer, or an
    // attacker probing the parser) and must be rejected, never silently
    // ignored. Each case pairs the reject with a positive control so a
    // failure here means the deny, not a broken fixture.

    // Handshake: both variants.
    for (bad, good) in [
        (
            json!({ "type": "challenge", "nonce": "n", "extra": 1 }),
            json!({ "type": "challenge", "nonce": "n" }),
        ),
        (
            json!({ "type": "response", "mac": "m", "label": "b", "extra": 1 }),
            json!({ "type": "response", "mac": "m", "label": "b" }),
        ),
    ] {
        assert!(
            serde_json::from_value::<Handshake>(bad.clone()).is_err(),
            "should reject: {bad}"
        );
        assert!(serde_json::from_value::<Handshake>(good).is_ok());
    }

    // AttachRequest: the browser role frame (empty struct variant exists
    // exactly so this reject works), the client frame, and an extra field
    // nested inside the harness identity.
    for (bad, good) in [
        (
            json!({ "attach": "browser", "extra": 1 }),
            json!({ "attach": "browser" }),
        ),
        (
            json!({ "attach": "client", "extra": 1 }),
            json!({ "attach": "client" }),
        ),
        (
            json!({ "attach": "client", "harness": { "hash": "ab".repeat(20), "extra": 1 } }),
            json!({ "attach": "client", "harness": { "hash": "ab".repeat(20) } }),
        ),
    ] {
        assert!(
            serde_json::from_value::<AttachRequest>(bad.clone()).is_err(),
            "should reject: {bad}"
        );
        assert!(serde_json::from_value::<AttachRequest>(good).is_ok());
    }

    // HarnessId directly.
    assert!(serde_json::from_value::<HarnessId>(
        json!({ "hash": "ab".repeat(20), "signer": "t", "name": "n", "extra": 1 })
    )
    .is_err());

    // AttachReply: all three variants.
    for (bad, good) in [
        (
            json!({ "attach_reply": "accepted", "extra": 1 }),
            json!({ "attach_reply": "accepted" }),
        ),
        (
            json!({ "attach_reply": "refused", "reason": "r", "extra": 1 }),
            json!({ "attach_reply": "refused", "reason": "r" }),
        ),
        (
            json!({ "attach_reply": "unavailable", "reason": "r", "extra": 1 }),
            json!({ "attach_reply": "unavailable", "reason": "r" }),
        ),
    ] {
        assert!(
            serde_json::from_value::<AttachReply>(bad.clone()).is_err(),
            "should reject: {bad}"
        );
        assert!(serde_json::from_value::<AttachReply>(good).is_ok());
    }

    // Bridge envelope: the deny guards the envelope only; `args` stays
    // free-form (validated per-op downstream).
    assert!(serde_json::from_value::<BridgeReq>(
        json!({ "id": 1, "op": "tab_list", "args": {}, "extra": 1 })
    )
    .is_err());
    // A tab target rides in the tool's args, never on the envelope.
    assert!(serde_json::from_value::<BridgeReq>(
        json!({ "id": 1, "op": "tab_list", "tabId": 3, "args": {} })
    )
    .is_err());
    // A string id is rejected on both envelopes: the server is the sole
    // assigner and only assigns integers; the contract's string arm is
    // forward-compat only (see the field docs on BridgeReq::id).
    assert!(serde_json::from_value::<BridgeReq>(
        json!({ "id": "s-1", "op": "tab_list", "args": {} })
    )
    .is_err());
    // `args` is a required envelope field: every command serializes its
    // struct (`{}` for arg-less ops), and the reader rejects a frame that
    // omits it - the same language the extension's Zod validator enforces.
    assert!(serde_json::from_value::<BridgeReq>(json!({ "id": 1, "op": "tab_list" })).is_err());
    assert!(serde_json::from_value::<BridgeResp>(json!({ "id": "s-1", "ok": true })).is_err());
    assert!(serde_json::from_value::<BridgeResp>(
        json!({ "id": 1, "ok": true, "data": {}, "extra": 1 })
    )
    .is_err());
    assert!(
        serde_json::from_value::<BridgeResp>(json!({ "id": 1, "ok": true, "data": {} })).is_ok()
    );

    // Enclave control frames: every variant rejects an unexpected field,
    // with positive controls, and a challenge carrying one is classified
    // malformed under its tag (answered with an error), never signed.
    for (bad, good) in [
        (
            json!({ "type": "enclave_challenge", "nonce": "n", "extra": 1 }),
            json!({ "type": "enclave_challenge", "nonce": "n", "context": "c" }),
        ),
        (
            json!({ "type": "enclave_proof", "sig": "s", "key_id": "k", "pubkey": "p", "extra": 1 }),
            json!({ "type": "enclave_proof", "sig": "s", "key_id": "k", "pubkey": "p" }),
        ),
        (
            json!({ "type": "enclave_error", "reason": "r", "extra": 1 }),
            json!({ "type": "enclave_error", "reason": "r" }),
        ),
        (
            json!({ "type": "enclave_revoke", "extra": 1 }),
            json!({ "type": "enclave_revoke" }),
        ),
        (
            json!({ "type": "enclave_revoked", "extra": 1 }),
            json!({ "type": "enclave_revoked" }),
        ),
    ] {
        assert!(
            serde_json::from_value::<EnclaveControl>(bad.clone()).is_err(),
            "should reject: {bad}"
        );
        assert!(serde_json::from_value::<EnclaveControl>(good).is_ok());
    }
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "enclave_challenge", "nonce": "n", "extra": 1 })),
        FrameDisposition::Malformed {
            tag: HostControlTag::EnclaveChallenge,
            ..
        }
    ));

    // Admin control frames: every variant rejects an
    // unexpected field, with positive controls.
    for (bad, good) in [
        (
            json!({ "type": "client_list", "extra": 1 }),
            json!({ "type": "client_list" }),
        ),
        (
            json!({ "type": "client_revoke", "name": "codex", "extra": 1 }),
            json!({ "type": "client_revoke", "name": "codex" }),
        ),
        (
            json!({ "type": "client_revoke_result", "ok": true, "extra": 1 }),
            json!({ "type": "client_revoke_result", "ok": true }),
        ),
        (
            json!({ "type": "client_list_result", "ok": true, "enrolled": false,
                    "clients": [], "extra": 1 }),
            json!({ "type": "client_list_result", "ok": true, "enrolled": false,
                    "clients": [] }),
        ),
    ] {
        assert!(
            serde_json::from_value::<AdminControl>(bad.clone()).is_err(),
            "should reject: {bad}"
        );
        assert!(serde_json::from_value::<AdminControl>(good).is_ok());
    }

    // Policy control frames: every variant rejects an
    // unexpected field, with positive controls.
    for (bad, good) in [
        (
            json!({ "type": "policy_get", "extra": 1 }),
            json!({ "type": "policy_get" }),
        ),
        (
            json!({ "type": "policy_current", "ok": true, "baseline": "b", "sig": "s",
                    "overlay": {}, "extra": 1 }),
            json!({ "type": "policy_current", "ok": true, "baseline": "b", "sig": "s",
                    "overlay": {} }),
        ),
        // The overlay is the typed crate::policy::PolicyOverlay: a field
        // outside the policy catalogue fails the whole frame parse.
        (
            json!({ "type": "policy_current", "ok": true, "baseline": "b", "sig": "s",
                    "overlay": { "requireEnrollment": false } }),
            json!({ "type": "policy_current", "ok": true, "baseline": "b", "sig": "s",
                    "overlay": { "pageEvalEnabled": false } }),
        ),
        (
            json!({ "type": "lang_get", "extra": 1 }),
            json!({ "type": "lang_get" }),
        ),
        (
            json!({ "type": "lang_set", "value": "en", "extra": 1 }),
            json!({ "type": "lang_set", "value": "en" }),
        ),
        (
            json!({ "type": "lang_current", "value": "en", "seq": 1, "extra": 1 }),
            json!({ "type": "lang_current", "value": "en", "seq": 1 }),
        ),
    ] {
        assert!(
            serde_json::from_value::<PolicyControl>(bad.clone()).is_err(),
            "should reject: {bad}"
        );
        assert!(serde_json::from_value::<PolicyControl>(good).is_ok());
    }
    // The optional policy_current fields default: the failure shape
    // travels as ok:false with only an error.
    assert!(serde_json::from_value::<PolicyControl>(
        json!({ "type": "policy_current", "ok": false, "error": "unreadable store" })
    )
    .is_ok());
}

#[test]
fn parsed_resp_admits_exactly_the_two_legal_response_states() {
    // Success with data (and the legal data-omitted success, resolved to
    // Null once, at the boundary).
    let ok: ParsedResp =
        serde_json::from_value(json!({ "id": 4, "ok": true, "data": { "n": 1 } })).unwrap();
    assert_eq!(ok.id, 4);
    assert_eq!(ok.outcome, Ok(json!({ "n": 1 })));
    let bare_ok: ParsedResp = serde_json::from_value(json!({ "id": 5, "ok": true })).unwrap();
    assert_eq!(bare_ok.outcome, Ok(Value::Null));

    // Failure with an error.
    let err: ParsedResp =
        serde_json::from_value(json!({ "id": 6, "ok": false, "error": "boom" })).unwrap();
    assert_eq!(err.outcome, Err("boom".to_string()));

    // Every contradictory mixture the flat wire triple can spell is
    // refused at the parse, fail closed - the guard for the loose shape
    // ever returning: success claiming an error, failure carrying data,
    // and a bare failure with nothing to report.
    for bad in [
        json!({ "id": 1, "ok": true, "error": "e" }),
        json!({ "id": 1, "ok": true, "data": {}, "error": "e" }),
        json!({ "id": 1, "ok": false, "data": {} }),
        json!({ "id": 1, "ok": false, "data": {}, "error": "e" }),
        json!({ "id": 1, "ok": false }),
    ] {
        assert!(
            serde_json::from_value::<ParsedResp>(bad.clone()).is_err(),
            "must refuse: {bad}"
        );
    }

    // The refusal reaches the session's read boundary as InvalidData, the
    // same class as a malformed frame, so the reader drops the connection.
    let line = b"{\"id\":1,\"ok\":false,\"data\":{}}\n".to_vec();
    let err = bridge_read::<_, ParsedResp>(&mut Cursor::new(line)).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}
