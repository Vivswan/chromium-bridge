use super::control::*;
use super::*;
use serde_json::json;
use std::io::Cursor;

#[test]
fn nm_frame_roundtrip() {
    let v = json!({ "op": "tab_list", "id": 1 });
    let mut buf = Vec::new();
    nm_write_frame(&mut buf, &v).unwrap();
    // 4-byte LE length prefix precedes the JSON body.
    let body_len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    assert_eq!(body_len, buf.len() - 4);
    let mut cur = Cursor::new(buf);
    assert_eq!(nm_read_frame(&mut cur).unwrap().unwrap(), v);
}

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
fn nm_read_rejects_huge_prefix() {
    // 0xFFFFFFFF length (~4 GB) exceeds the 64 MB inbound clamp.
    let mut cur = Cursor::new(vec![0xFF, 0xFF, 0xFF, 0xFF]);
    let err = nm_read_frame(&mut cur).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn mcp_ndjson_single_line_roundtrip() {
    // Embedded newline must be escaped so the frame stays one NDJSON line.
    let msg = JsonRpc::ok(json!(1), json!({ "text": "a\nb" }));
    let mut buf = Vec::new();
    mcp_write(&mut buf, &msg).unwrap();
    assert_eq!(buf.iter().filter(|&&b| b == b'\n').count(), 1);
    assert!(buf.ends_with(b"\n"));
    let got = mcp_read(&mut Cursor::new(buf)).unwrap().unwrap();
    assert_eq!(got.id, Some(json!(1)));
}

#[test]
fn mcp_read_rejects_a_line_over_the_cap() {
    // A newline-less client line longer than the cap is rejected instead of
    // being buffered in full (the memory-exhaustion path on the client
    // leg). A tiny cap keeps the test fast; mcp_read wires the real 64 MB.
    let mut r = Cursor::new(vec![b'x'; 64]); // no newline, cap is 16
    let err = mcp_read_capped(&mut r, 16).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn mcp_read_cap_boundary_is_exact() {
    // The cap counts the whole line, newline included. A line whose length
    // equals the cap parses; one byte tighter rejects it. Pins the
    // off-by-one the +1 sentinel guards.
    let mut wire = br#"{"jsonrpc":"2.0","id":1}"#.to_vec();
    wire.push(b'\n');
    let total = wire.len();

    let got = mcp_read_capped(&mut Cursor::new(wire.clone()), total).unwrap();
    assert_eq!(got.unwrap().id, Some(json!(1)));

    let err = mcp_read_capped(&mut Cursor::new(wire), total - 1).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn mcp_read_skips_blank_lines_without_recursing() {
    // A large flood of blank lines: the iterative loop skips them in
    // constant stack, whereas the old `return mcp_read(r)` recursion would
    // grow the stack once per blank and overflow (aborting under
    // panic=abort). Sized well past any plausible stack depth, so a
    // regression back to recursion makes this test crash rather than pass.
    let mut buf = vec![b'\n'; 200_000];
    let msg = JsonRpc::ok(json!(2), json!({}));
    mcp_write(&mut buf, &msg).unwrap();
    let got = mcp_read(&mut Cursor::new(buf)).unwrap().unwrap();
    assert_eq!(got.id, Some(json!(2)));
}

#[test]
fn bridge_envelope_roundtrip() {
    let req = BridgeReq {
        id: 7,
        op: "page_click".into(),
        tab_id: Some(3),
        args: json!({ "ref": "e3" }),
        browser: Some("brave".into()),
    };
    let mut buf = Vec::new();
    bridge_write(&mut buf, &req).unwrap();
    // The wire form uses the contract's camelCase field name, not the
    // Rust field name.
    let wire: Value = serde_json::from_slice(&buf[..buf.len() - 1]).unwrap();
    assert_eq!(wire["tabId"], 3);
    assert!(wire.get("tab_id").is_none());
    let got: BridgeReq = bridge_read(&mut Cursor::new(buf)).unwrap().unwrap();
    assert_eq!(got.id, 7);
    assert_eq!(got.op, "page_click");
    assert_eq!(got.tab_id, Some(3));
    assert_eq!(got.args, json!({ "ref": "e3" }));
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

#[test]
fn bridge_read_rejects_a_line_over_the_cap() {
    // A newline-less line longer than the cap is rejected instead of being
    // buffered in full (the memory-exhaustion path). A tiny cap keeps the
    // test fast; the public bridge_read wires the real 64 MB ceiling.
    let mut r = Cursor::new(vec![b'x'; 64]); // no newline, cap is 16
    let err = bridge_read_capped::<_, Value>(&mut r, 16).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn bridge_read_cap_boundary_is_exact() {
    // The cap counts the whole line, newline included. A line whose length
    // equals the cap parses; one byte tighter rejects it rather than
    // truncating. This pins the off-by-one the +1 sentinel guards.
    let mut wire = br#"{"id":1,"op":"x","args":{}}"#.to_vec();
    wire.push(b'\n');
    let total = wire.len();

    let got: Option<BridgeReq> = bridge_read_capped(&mut Cursor::new(wire.clone()), total).unwrap();
    assert_eq!(got.unwrap().id, 1);

    let err = bridge_read_capped::<_, BridgeReq>(&mut Cursor::new(wire), total - 1).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn bridge_read_skips_blank_lines_without_recursing() {
    // A large flood of blank lines is skipped iteratively, in constant
    // stack; a recursive skip would grow the stack once per blank and
    // overflow (aborting under panic=abort). Sized well past any plausible
    // stack depth, so a regression to recursion crashes rather than passes.
    let mut wire = vec![b'\n'; 200_000];
    bridge_write(
        &mut wire,
        &BridgeReq {
            id: 9,
            op: "noop".into(),
            tab_id: None,
            args: json!({}),
            browser: None,
        },
    )
    .unwrap();
    let got: BridgeReq = bridge_read(&mut Cursor::new(wire)).unwrap().unwrap();
    assert_eq!(got.id, 9);
}

#[test]
fn handshake_challenge_and_response_roundtrip() {
    // Challenge frame carries the tagged type + nonce.
    let chal = Handshake::Challenge {
        nonce: "abc123".into(),
    };
    let mut buf = Vec::new();
    bridge_write(&mut buf, &chal).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&buf[..buf.len() - 1]).unwrap(),
        json!({ "type": "challenge", "nonce": "abc123" })
    );
    let back: Handshake = bridge_read(&mut Cursor::new(buf)).unwrap().unwrap();
    assert!(matches!(back, Handshake::Challenge { nonce } if nonce == "abc123"));

    // Response frame: label is optional and omitted when None.
    let resp = Handshake::Response {
        mac: "deadbeef".into(),
        label: None,
    };
    let mut buf = Vec::new();
    bridge_write(&mut buf, &resp).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&buf[..buf.len() - 1]).unwrap(),
        json!({ "type": "response", "mac": "deadbeef" })
    );
    // A response with no label deserializes with label defaulted to None.
    let back: Handshake = bridge_read(&mut Cursor::new(
        b"{\"type\":\"response\",\"mac\":\"x\"}\n".to_vec(),
    ))
    .unwrap()
    .unwrap();
    assert!(matches!(back, Handshake::Response { label: None, .. }));
}

#[test]
fn attach_frames_roundtrip_and_are_tagged() {
    // Browser attach is a bare role marker (its label rode the signed
    // handshake response, not this frame).
    assert_eq!(
        serde_json::to_value(AttachRequest::Browser {}).unwrap(),
        json!({ "attach": "browser" })
    );
    // Client attach carries the relay's attested harness identity; a name
    // is optional and is a log label only.
    let client = AttachRequest::Client {
        harness: Some(HarnessId {
            hash: "abc123".into(),
            team_id: Some("3ZMH96L4V9".into()),
            name: Some("claude-code".into()),
        }),
    };
    let v = serde_json::to_value(&client).unwrap();
    assert_eq!(v["attach"], "client");
    assert_eq!(v["harness"]["hash"], "abc123");
    assert_eq!(v["harness"]["team_id"], "3ZMH96L4V9");
    let back: AttachRequest = serde_json::from_value(v).unwrap();
    assert!(matches!(back, AttachRequest::Client { harness: Some(h) } if h.hash == "abc123"));

    // A client attach with no measurable harness omits the field.
    let bare = AttachRequest::Client { harness: None };
    assert_eq!(
        serde_json::to_value(&bare).unwrap(),
        json!({ "attach": "client" })
    );

    // Replies are tagged and roundtrip.
    for reply in [
        AttachReply::Accepted {},
        AttachReply::Refused {
            reason: "not allowlisted".into(),
        },
        AttachReply::Unavailable {
            reason: "capacity".into(),
        },
    ] {
        let v = serde_json::to_value(&reply).unwrap();
        let back: AttachReply = serde_json::from_value(v).unwrap();
        assert_eq!(
            serde_json::to_value(back).unwrap(),
            serde_json::to_value(reply).unwrap()
        );
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
            json!({ "attach": "client", "harness": { "hash": "h", "extra": 1 } }),
            json!({ "attach": "client", "harness": { "hash": "h" } }),
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
        json!({ "hash": "h", "team_id": "t", "name": "n", "extra": 1 })
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
    // The pre-rename snake_case field is an unknown field now. Safe: no
    // released peer ever emitted it (the field was always None/omitted),
    // and a peer that does send it is out of contract.
    assert!(serde_json::from_value::<BridgeReq>(
        json!({ "id": 1, "op": "tab_list", "tab_id": 3, "args": {} })
    )
    .is_err());
    assert!(serde_json::from_value::<BridgeReq>(
        json!({ "id": 1, "op": "tab_list", "tabId": 3, "args": {} })
    )
    .is_ok());
    // A string id is rejected on both envelopes: the server is the sole
    // assigner and only assigns integers; the contract's string arm is
    // forward-compat only (see the field docs on BridgeReq::id).
    assert!(serde_json::from_value::<BridgeReq>(
        json!({ "id": "s-1", "op": "tab_list", "args": {} })
    )
    .is_err());
    // `args` is a required envelope field: every builder sends an object
    // (`{}` for arg-less ops, see tools/handlers.rs), and the reader
    // rejects a frame that omits it - the same language the extension's
    // Zod validator enforces.
    assert!(serde_json::from_value::<BridgeReq>(json!({ "id": 1, "op": "tab_list" })).is_err());
    assert!(serde_json::from_value::<BridgeResp>(json!({ "id": "s-1", "ok": true })).is_err());
    let req: BridgeReq =
        serde_json::from_value(json!({ "id": 1, "op": "x", "args": { "free": "form" } })).unwrap();
    assert_eq!(req.args["free"], "form");
    assert!(serde_json::from_value::<BridgeResp>(
        json!({ "id": 1, "ok": true, "data": {}, "extra": 1 })
    )
    .is_err());
    assert!(
        serde_json::from_value::<BridgeResp>(json!({ "id": 1, "ok": true, "data": {} })).is_ok()
    );

    // Enclave control frames: all five variants reject an unexpected
    // field, and a challenge carrying one is classified Malformed
    // (answered with an error), never signed.
    assert!(serde_json::from_value::<EnclaveControl>(
        json!({ "type": "enclave_challenge", "nonce": "n", "extra": 1 })
    )
    .is_err());
    assert!(serde_json::from_value::<EnclaveControl>(
        json!({ "type": "enclave_proof", "sig": "s", "key_id": "k", "pubkey": "p", "extra": 1 })
    )
    .is_err());
    assert!(serde_json::from_value::<EnclaveControl>(
        json!({ "type": "enclave_error", "reason": "r", "extra": 1 })
    )
    .is_err());
    assert!(serde_json::from_value::<EnclaveControl>(
        json!({ "type": "enclave_revoke", "extra": 1 })
    )
    .is_err());
    assert!(serde_json::from_value::<EnclaveControl>(
        json!({ "type": "enclave_revoked", "extra": 1 })
    )
    .is_err());
    assert!(serde_json::from_value::<EnclaveControl>(json!({ "type": "enclave_revoke" })).is_ok());
    assert!(serde_json::from_value::<EnclaveControl>(json!({ "type": "enclave_revoked" })).is_ok());
    // The presence frames (ADR-0031) reject unknown fields the same way,
    // with positive controls.
    assert!(serde_json::from_value::<EnclaveControl>(
        json!({ "type": "presence_challenge", "nonce": "n", "extra": 1 })
    )
    .is_err());
    assert!(serde_json::from_value::<EnclaveControl>(
        json!({ "type": "presence_proof", "sig": "s", "key_id": "k", "pubkey": "p",
                "extra": 1 })
    )
    .is_err());
    assert!(serde_json::from_value::<EnclaveControl>(
        json!({ "type": "presence_error", "reason": "r", "extra": 1 })
    )
    .is_err());
    assert!(serde_json::from_value::<EnclaveControl>(
        json!({ "type": "presence_challenge", "nonce": "n", "context": "c" })
    )
    .is_ok());
    assert!(serde_json::from_value::<EnclaveControl>(
        json!({ "type": "presence_proof", "sig": "s", "key_id": "k", "pubkey": "p" })
    )
    .is_ok());
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "enclave_challenge", "nonce": "n", "extra": 1 })),
        FrameDisposition::Malformed
    ));

    // Admin control frames (ADR-0025): every variant rejects an
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

    // Policy control frames (ADR-0032): every variant rejects an
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
            json!({ "type": "legacy_settings", "bag": {}, "extra": 1 }),
            json!({ "type": "legacy_settings", "bag": {} }),
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
fn bridge_envelope_wire_keys_are_pinned() {
    // These Rust types ARE the canonical envelope contract (ADR-0028);
    // the extension's Zod validators are checked against them by the CI
    // double-derivation diff (scripts/check-envelope-parity.ts). This
    // test pins the exact wire field names locally, so a rename or an
    // added field fails `cargo test` immediately (this is the test that
    // would have caught tab_id-vs-tabId) instead of waiting for the
    // cross-language diff.
    fn wire_keys<T: Serialize>(v: &T) -> std::collections::BTreeSet<String> {
        serde_json::to_value(v)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    }
    fn expected(keys: &[&str]) -> std::collections::BTreeSet<String> {
        keys.iter().map(|s| s.to_string()).collect()
    }

    let req = BridgeReq {
        id: 1,
        op: "tab_list".into(),
        tab_id: Some(2),
        args: json!({}),
        browser: Some("brave".into()),
    };
    assert_eq!(
        wire_keys(&req),
        expected(&["args", "browser", "id", "op", "tabId"]),
        "BridgeReq wire fields changed - update the Zod validator \
         (src/packages/shared/src/envelope.ts) and bump BRIDGE_PROTOCOL_VERSION \
         if the change is incompatible"
    );

    let resp = BridgeResp {
        id: 1,
        ok: false,
        data: Some(json!({})),
        error: Some("e".into()),
    };
    assert_eq!(
        wire_keys(&resp),
        expected(&["data", "error", "id", "ok"]),
        "BridgeResp wire fields changed - update the Zod validator \
         (src/packages/shared/src/envelope.ts) and bump BRIDGE_PROTOCOL_VERSION \
         if the change is incompatible"
    );
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
