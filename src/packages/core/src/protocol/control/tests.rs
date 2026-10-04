use super::*;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

/// Every variant's `type` tag of an internally tagged wire enum, read from the schema the contract
/// emitter derives, so no hand-written sample list has to stay complete.
fn variant_tags<T: schemars::JsonSchema>() -> BTreeMap<String, Value> {
    let schema = serde_json::to_value(schemars::schema_for!(T)).unwrap();
    schema["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .map(|variant| {
            let tag = variant["properties"]["type"]["const"]
                .as_str()
                .unwrap()
                .to_string();
            (tag, variant.clone())
        })
        .collect()
}

/// Every [`HostControlTag`], from its schema: the single derived enumeration of the tag set.
fn all_host_control_tags() -> Vec<HostControlTag> {
    let schema = serde_json::to_value(schemars::schema_for!(HostControlTag)).unwrap();
    schema["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tag| serde_json::from_value(tag.clone()).unwrap())
        .collect()
}

fn without_descriptions(mut schema: Value) -> Value {
    fn strip(v: &mut Value) {
        match v {
            Value::Object(map) => {
                map.remove("description");
                map.values_mut().for_each(strip);
            }
            Value::Array(items) => items.iter_mut().for_each(strip),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    strip(&mut schema);
    schema
}

#[test]
fn host_control_tags_mirror_the_wire_enums() {
    // Cross-type consistency Rust cannot express: HostControlTag is a separate enum, and a variant added to
    // EnclaveControl / AdminControl / PolicyControl without it would classify as Forward (relayed to the MCP
    // server) instead of being answered or dropped. The tag strings are read from each enum's own schema.
    let mut wire: Vec<String> = Vec::new();
    wire.extend(variant_tags::<EnclaveControl>().into_keys());
    wire.extend(variant_tags::<AdminControl>().into_keys());
    wire.extend(variant_tags::<PolicyControl>().into_keys());
    let distinct: BTreeSet<&str> = wire.iter().map(String::as_str).collect();
    assert_eq!(
        distinct.len(),
        wire.len(),
        "a tag appears in more than one wire enum: {wire:?}"
    );
    let tags: BTreeSet<String> = all_host_control_tags()
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        tags,
        distinct.iter().map(ToString::to_string).collect(),
        "HostControlTag must name exactly the wire enums' variants"
    );
    // Both classifiers recognize every tag: the socket->stdout pump drops a server-injected one, and the
    // stdin->socket pump never forwards one.
    for tag in all_host_control_tags() {
        let frame = json!({ "type": tag.to_string() });
        assert_eq!(host_control_type(&frame), Some(tag), "{tag}");
        assert!(
            !matches!(classify_nm_frame(&frame), FrameDisposition::Forward),
            "{tag} must never classify as Forward"
        );
    }
}

#[test]
fn host_request_variants_match_their_wire_enum_variants() {
    // Cross-type consistency: the extension's generated writer types come from the wire enums, while the
    // host parses HostRequest; a field present on one side only would make the genuine extension's frame
    // malformed (or let a field travel unparsed). Compared as schemas, docs aside.
    let mut wire = variant_tags::<EnclaveControl>();
    wire.extend(variant_tags::<AdminControl>());
    wire.extend(variant_tags::<PolicyControl>());
    let requests = variant_tags::<HostRequest>();
    assert!(!requests.is_empty(), "HostRequest has variants");
    for (tag, request) in requests {
        let counterpart = wire
            .get(&tag)
            .unwrap_or_else(|| panic!("HostRequest::{tag} has no wire-enum variant"));
        assert_eq!(
            without_descriptions(request),
            without_descriptions(counterpart.clone()),
            "HostRequest {tag} drifted from its wire-enum variant"
        );
    }
}

/// The classifier's answer for one frame, with serde's error text (not part of the contract) left out.
#[derive(Debug)]
enum Expect {
    Forward,
    Handle(HostRequest),
    Malformed(HostControlTag),
}

fn audit(kind: crate::audit::AuditKind) -> HostRequest {
    HostRequest::AuditEvent {
        kind: ExtensionAuditKind(kind),
        outcome: None,
        tool: None,
        name: None,
        detail: None,
        cid: None,
    }
}

#[test]
fn classification_matrix() {
    // The wire contract with the extension: relay traffic and near-misses forward untouched (a swallowed
    // relay frame desynchronizes the bridge), a well-formed request is handled, and anything else wearing a
    // control tag is malformed under that tag. The forgery gate for audit kinds lives in the parse: a
    // host-owned kind never becomes a request.
    use crate::audit::AuditKind;
    use Expect::{Forward, Handle, Malformed};
    use HostControlTag as Tag;
    let cases = [
        (json!({ "op": "tab_list", "id": 1 }), Forward),
        (json!({ "id": 7, "ok": true, "data": {} }), Forward),
        (
            json!({ "type": "challenge", "nonce": "socket-handshake-shape" }),
            Forward,
        ),
        (json!({ "type": "response", "mac": "aa" }), Forward),
        (json!({ "type": "enclave_other" }), Forward),
        (json!({ "type": 42 }), Forward),
        // Regression (review of this refactor): the externally tagged spelling of a unit variant
        // parses as HostControlTag from a Value; only a string `type` is a control tag.
        (json!({ "type": { "kill_status": null } }), Forward),
        (json!("enclave_error"), Forward),
        (json!(null), Forward),
        (
            json!({ "type": "enclave_challenge", "nonce": "n", "context": "c" }),
            Handle(HostRequest::EnclaveChallenge {
                nonce: "n".into(),
                context: Some("c".into()),
            }),
        ),
        (
            json!({ "type": "enclave_challenge", "nonce": "n" }),
            Handle(HostRequest::EnclaveChallenge {
                nonce: "n".into(),
                context: None,
            }),
        ),
        (
            json!({ "type": "enclave_challenge" }),
            Malformed(Tag::EnclaveChallenge),
        ),
        (
            json!({ "type": "enclave_challenge", "nonce": 5 }),
            Malformed(Tag::EnclaveChallenge),
        ),
        (
            json!({ "type": "enclave_challenge", "nonce": "n", "extra": 1 }),
            Malformed(Tag::EnclaveChallenge),
        ),
        (
            json!({ "type": "enclave_revoke" }),
            Handle(HostRequest::EnclaveRevoke {}),
        ),
        (
            json!({ "type": "enclave_revoke", "extra": 1 }),
            Malformed(Tag::EnclaveRevoke),
        ),
        (
            json!({ "type": "presence_challenge", "nonce": "n", "context": "c" }),
            Handle(HostRequest::PresenceChallenge {
                nonce: "n".into(),
                context: Some("c".into()),
            }),
        ),
        (
            json!({ "type": "presence_challenge" }),
            Malformed(Tag::PresenceChallenge),
        ),
        (
            json!({ "type": "presence_challenge", "nonce": 5 }),
            Malformed(Tag::PresenceChallenge),
        ),
        (
            json!({ "type": "presence_challenge", "nonce": "n", "extra": 1 }),
            Malformed(Tag::PresenceChallenge),
        ),
        (
            json!({ "type": "client_list" }),
            Handle(HostRequest::ClientList {}),
        ),
        (
            json!({ "type": "client_list", "extra": 1 }),
            Malformed(Tag::ClientList),
        ),
        (
            json!({ "type": "client_revoke", "name": "codex" }),
            Handle(HostRequest::ClientRevoke {
                name: "codex".into(),
            }),
        ),
        (
            json!({ "type": "client_revoke" }),
            Malformed(Tag::ClientRevoke),
        ),
        (
            json!({ "type": "kill_status" }),
            Handle(HostRequest::KillStatus {}),
        ),
        (
            json!({ "type": "kill_engage" }),
            Handle(HostRequest::KillEngage {}),
        ),
        (
            json!({ "type": "kill_release" }),
            Handle(HostRequest::KillRelease {}),
        ),
        (
            json!({ "type": "kill_status", "extra": 1 }),
            Malformed(Tag::KillStatus),
        ),
        (
            json!({ "type": "kill_engage", "extra": 1 }),
            Malformed(Tag::KillEngage),
        ),
        (
            json!({ "type": "kill_release", "extra": 1 }),
            Malformed(Tag::KillRelease),
        ),
        (
            json!({ "type": "audit_event", "kind": "confirm_denied", "tool": "eval", "cid": "c-42" }),
            Handle(HostRequest::AuditEvent {
                kind: ExtensionAuditKind(AuditKind::ConfirmDenied),
                outcome: None,
                tool: Some("eval".into()),
                name: None,
                detail: None,
                cid: Some("c-42".into()),
            }),
        ),
        (
            json!({ "type": "audit_event", "kind": "confirm_shown" }),
            Handle(audit(AuditKind::ConfirmShown)),
        ),
        (json!({ "type": "audit_event" }), Malformed(Tag::AuditEvent)),
        (
            json!({ "type": "audit_event", "kind": 5 }),
            Malformed(Tag::AuditEvent),
        ),
        (
            json!({ "type": "audit_event", "kind": "kill_engage" }),
            Malformed(Tag::AuditEvent),
        ),
        (
            json!({ "type": "audit_event", "kind": "harness_admit" }),
            Malformed(Tag::AuditEvent),
        ),
        (
            json!({ "type": "audit_event", "kind": "tool_call" }),
            Malformed(Tag::AuditEvent),
        ),
        (
            json!({ "type": "audit_event", "kind": "presence_sign" }),
            Malformed(Tag::AuditEvent),
        ),
        (
            json!({ "type": "audit_event", "kind": "admission" }),
            Malformed(Tag::AuditEvent),
        ),
        (
            json!({ "type": "audit_event", "kind": "" }),
            Malformed(Tag::AuditEvent),
        ),
        (
            json!({ "type": "policy_get" }),
            Handle(HostRequest::PolicyGet {}),
        ),
        (
            json!({ "type": "policy_get", "extra": 1 }),
            Malformed(Tag::PolicyGet),
        ),
        (
            json!({ "type": "lang_get" }),
            Handle(HostRequest::LangGet {}),
        ),
        (
            json!({ "type": "lang_get", "extra": 1 }),
            Malformed(Tag::LangGet),
        ),
        (
            json!({ "type": "lang_set", "value": "en" }),
            Handle(HostRequest::LangSet { value: "en".into() }),
        ),
        (json!({ "type": "lang_set" }), Malformed(Tag::LangSet)),
        // Host->extension frames bounced back by the browser leg.
        (
            json!({ "type": "enclave_proof", "sig": "s" }),
            Malformed(Tag::EnclaveProof),
        ),
        (
            json!({ "type": "enclave_error", "reason": "r" }),
            Malformed(Tag::EnclaveError),
        ),
        (
            json!({ "type": "enclave_revoked" }),
            Malformed(Tag::EnclaveRevoked),
        ),
        (
            json!({ "type": "presence_proof", "sig": "s" }),
            Malformed(Tag::PresenceProof),
        ),
        (
            json!({ "type": "presence_error", "reason": "r" }),
            Malformed(Tag::PresenceError),
        ),
        (
            json!({ "type": "client_list_result", "ok": true }),
            Malformed(Tag::ClientListResult),
        ),
        (
            json!({ "type": "client_revoke_result", "ok": true }),
            Malformed(Tag::ClientRevokeResult),
        ),
        (
            json!({ "type": "kill_status_result", "ok": true }),
            Malformed(Tag::KillStatusResult),
        ),
        (
            json!({ "type": "policy_current", "ok": true }),
            Malformed(Tag::PolicyCurrent),
        ),
        (
            json!({ "type": "lang_current", "value": "en", "seq": 1 }),
            Malformed(Tag::LangCurrent),
        ),
    ];
    for (frame, expect) in cases {
        let got = classify_nm_frame(&frame);
        let matched = match (&got, &expect) {
            (FrameDisposition::Forward, Forward) => true,
            (FrameDisposition::Handle(got), Handle(want)) => got == want,
            (FrameDisposition::Malformed { tag, .. }, Malformed(want)) => tag == want,
            (
                FrameDisposition::Forward
                | FrameDisposition::Handle(_)
                | FrameDisposition::Malformed { .. },
                Forward | Handle(_) | Malformed(_),
            ) => false,
        };
        assert!(matched, "{frame}: expected {expect:?}, got {got:?}");
    }
}

#[test]
fn malformed_replies_match_the_request_type() {
    // The reply frame type must match the request so the extension's pending request resolves instead of
    // timing out; the table covers every tag (checked against the derived set), so a new tag lands here too.
    use HostControlTag as Tag;
    enum Owed {
        Frame(Value),
        LangCurrent,
        Nothing,
    }
    use Owed::{Frame, LangCurrent, Nothing};
    let table = [
        (
            Tag::EnclaveChallenge,
            Frame(json!({ "type": "enclave_error", "reason": "invalid_challenge" })),
        ),
        (
            Tag::PresenceChallenge,
            Frame(json!({ "type": "presence_error", "reason": "invalid_challenge" })),
        ),
        (
            Tag::ClientList,
            Frame(
                json!({ "type": "client_list_result", "ok": false, "enrolled": false,
                          "clients": [], "error": "malformed client_list frame" }),
            ),
        ),
        (
            Tag::ClientRevoke,
            Frame(json!({ "type": "client_revoke_result", "ok": false,
                          "error": "malformed client_revoke frame" })),
        ),
        (
            Tag::KillStatus,
            Frame(json!({ "type": "kill_status_result", "ok": false,
                          "error": "malformed kill_status frame" })),
        ),
        (
            Tag::KillEngage,
            Frame(json!({ "type": "kill_status_result", "ok": false,
                          "error": "malformed kill_engage frame" })),
        ),
        (
            Tag::KillRelease,
            Frame(json!({ "type": "kill_status_result", "ok": false,
                          "error": "malformed kill_release frame" })),
        ),
        (
            Tag::PolicyGet,
            Frame(json!({ "type": "policy_current", "ok": false,
                          "error": "malformed policy_get frame" })),
        ),
        (Tag::LangGet, LangCurrent),
        (Tag::LangSet, LangCurrent),
        (Tag::EnclaveRevoke, Nothing),
        (Tag::AuditEvent, Nothing),
        (Tag::EnclaveProof, Nothing),
        (Tag::EnclaveError, Nothing),
        (Tag::EnclaveRevoked, Nothing),
        (Tag::PresenceProof, Nothing),
        (Tag::PresenceError, Nothing),
        (Tag::ClientListResult, Nothing),
        (Tag::ClientRevokeResult, Nothing),
        (Tag::KillStatusResult, Nothing),
        (Tag::PolicyCurrent, Nothing),
        (Tag::LangCurrent, Nothing),
    ];
    let covered: BTreeSet<HostControlTag> = table.iter().map(|(tag, _)| *tag).collect();
    let all: BTreeSet<HostControlTag> = all_host_control_tags().into_iter().collect();
    assert_eq!(covered, all, "every tag has a row above");
    for (tag, owed) in table {
        match (tag.malformed_reply(), owed) {
            (MalformedReply::Send(reply), Frame(want)) => {
                assert_eq!(serde_json::to_value(&reply).unwrap(), want, "{tag}");
            }
            (MalformedReply::LangCurrent, LangCurrent) | (MalformedReply::Drop, Nothing) => {}
            (got, Frame(_) | LangCurrent | Nothing) => panic!("{tag}: unexpected reply {got:?}"),
        }
    }
}

#[test]
fn kill_status_maps_onto_the_pinned_wire_shapes() {
    // The typed state is the only producer shape; its wire mapping is
    // pinned exactly, so `killed` travels iff `ok` and `error` iff not -
    // the mixtures the flat triple admits are unconstructible upstream.
    assert_eq!(
        serde_json::to_value(KillStatus::Read { killed: true }.into_frame()).unwrap(),
        json!({ "type": "kill_status_result", "ok": true, "killed": true })
    );
    assert_eq!(
        serde_json::to_value(KillStatus::Read { killed: false }.into_frame()).unwrap(),
        json!({ "type": "kill_status_result", "ok": true, "killed": false })
    );
    assert_eq!(
        serde_json::to_value(
            KillStatus::Unreadable {
                error: "corrupt".into()
            }
            .into_frame()
        )
        .unwrap(),
        json!({ "type": "kill_status_result", "ok": false, "error": "corrupt" })
    );
}

#[test]
fn enclave_control_serde_roundtrip() {
    // Challenge with and without context; the tag is the snake_case name.
    let chal = EnclaveControl::EnclaveChallenge {
        nonce: "n1".into(),
        context: Some("ctx".into()),
    };
    let v = serde_json::to_value(&chal).unwrap();
    assert_eq!(
        v,
        json!({ "type": "enclave_challenge", "nonce": "n1", "context": "ctx" })
    );
    let no_ctx = EnclaveControl::EnclaveChallenge {
        nonce: "n2".into(),
        context: None,
    };
    assert_eq!(
        serde_json::to_value(&no_ctx).unwrap(),
        json!({ "type": "enclave_challenge", "nonce": "n2" })
    );

    let proof = EnclaveControl::EnclaveProof {
        sig: "c2ln".into(),
        key_id: "ab".repeat(32),
        pubkey: "cHViCg==".into(),
    };
    let v = serde_json::to_value(&proof).unwrap();
    assert_eq!(v.get("type").unwrap(), "enclave_proof");
    let back: EnclaveControl = serde_json::from_value(v).unwrap();
    assert!(matches!(back, EnclaveControl::EnclaveProof { .. }));

    let err = EnclaveControl::EnclaveError {
        reason: "not_enrolled".into(),
    };
    assert_eq!(
        serde_json::to_value(&err).unwrap(),
        json!({ "type": "enclave_error", "reason": "not_enrolled" })
    );
}

#[test]
fn admin_control_serde_roundtrips() {
    use crate::allowlist::{Anchor, ClientEntry};
    let result = AdminControl::ClientListResult {
        ok: true,
        enrolled: true,
        clients: vec![ClientEntry {
            name: "claude-code".into(),
            anchor: Anchor::TeamId(crate::ipc::TeamId::try_from("TEAMID0001").unwrap()),
            added_unix: 42,
        }],
        error: None,
    };
    let v = serde_json::to_value(&result).unwrap();
    assert_eq!(v["type"], "client_list_result");
    assert_eq!(v["clients"][0]["anchor"]["kind"], "team_id");
    // `error: None` is omitted on the wire.
    assert!(v.get("error").is_none());
    let back: AdminControl = serde_json::from_value(v).unwrap();
    assert!(matches!(
        back,
        AdminControl::ClientListResult { ok: true, .. }
    ));

    let revoke_err = AdminControl::ClientRevokeResult {
        ok: false,
        error: Some("no trusted client named 'x'".into()),
    };
    let v = serde_json::to_value(&revoke_err).unwrap();
    assert_eq!(v["type"], "client_revoke_result");
    assert_eq!(v["ok"], false);
    let back: AdminControl = serde_json::from_value(v).unwrap();
    assert!(matches!(
        back,
        AdminControl::ClientRevokeResult { ok: false, .. }
    ));
}

#[test]
fn policy_current_serializes_exactly_its_pinned_key_set() {
    // Verification and the ratchet key on the extension's own pin and nothing else - a frame-supplied key
    // id would hand a substituted host a ratchet-reset lever. Pin the fully-populated frame's serialized
    // keys so no key-identity field (or anything else) can ever join it unnoticed.
    let frame = PolicyControl::PolicyCurrent {
        ok: true,
        baseline: Some("YmFzZQ==".into()),
        sig: Some("c2ln".into()),
        overlay: Some(crate::policy::PolicyOverlay::default()),
        error: Some("e".into()),
    };
    let value = serde_json::to_value(&frame).unwrap();
    let keys: BTreeSet<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let expected: BTreeSet<&str> = ["type", "ok", "baseline", "sig", "overlay", "error"]
        .into_iter()
        .collect();
    assert_eq!(keys, expected);
}

#[test]
fn policy_status_maps_onto_the_pinned_wire_shapes() {
    // The wire contract the extension's ok-split refinement enforces (shared/src/enclave.ts): the typed
    // state is the only producer, and its flattening is pinned byte for byte, so a baseline travels iff
    // `ok`, `error` iff not, and a `sig` never without its baseline.
    assert_eq!(
        serde_json::to_value(
            PolicyStatus::Present {
                baseline_b64: "YmFzZQ==".into(),
                sig_b64: Some("c2ln".into()),
                overlay: None,
            }
            .into_frame()
        )
        .unwrap(),
        json!({ "type": "policy_current", "ok": true, "baseline": "YmFzZQ==", "sig": "c2ln" })
    );
    assert_eq!(
        serde_json::to_value(
            PolicyStatus::Present {
                baseline_b64: "YmFzZQ==".into(),
                sig_b64: None,
                overlay: Some(crate::policy::PolicyOverlay::default()),
            }
            .into_frame()
        )
        .unwrap(),
        json!({ "type": "policy_current", "ok": true, "baseline": "YmFzZQ==", "overlay": {} })
    );
    assert_eq!(
        serde_json::to_value(
            PolicyStatus::Unavailable {
                error: "no policy baseline".into(),
            }
            .into_frame()
        )
        .unwrap(),
        json!({ "type": "policy_current", "ok": false, "error": "no policy baseline" })
    );
}
