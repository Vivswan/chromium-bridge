use super::*;
use serde_json::json;

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
fn classify_forwards_ordinary_frames() {
    // Bridge requests (op, no type) and arbitrary JSON forward untouched.
    for frame in [
        json!({ "op": "tab_list", "id": 1 }),
        json!({ "id": 7, "ok": true, "data": {} }),
        json!({ "type": "challenge", "nonce": "socket-handshake-shape" }),
        json!({ "type": "response", "mac": "aa" }),
        json!({ "type": 42 }),
        json!("just a string"),
        json!(null),
    ] {
        assert!(
            matches!(classify_nm_frame(&frame), FrameDisposition::Forward),
            "should forward: {frame}"
        );
    }
}

#[test]
fn classify_handles_challenge_locally_and_never_forwards_control_types() {
    match classify_nm_frame(&json!({ "type": "enclave_challenge", "nonce": "n", "context": "c" })) {
        FrameDisposition::Challenge { nonce, context } => {
            assert_eq!(nonce, "n");
            assert_eq!(context.as_deref(), Some("c"));
        }
        other => panic!("expected Challenge, got {other:?}"),
    }
    // Context is optional.
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "enclave_challenge", "nonce": "n" })),
        FrameDisposition::Challenge { context: None, .. }
    ));
    // A challenge missing its nonce is malformed - answered with an
    // error, never forwarded.
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "enclave_challenge" })),
        FrameDisposition::Malformed
    ));
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "enclave_challenge", "nonce": 5 })),
        FrameDisposition::Malformed
    ));
    // Stray proof/error frames are dropped, not forwarded.
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "enclave_proof", "sig": "s" })),
        FrameDisposition::Drop("enclave_proof")
    ));
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "enclave_error", "reason": "r" })),
        FrameDisposition::Drop("enclave_error")
    ));
}

#[test]
fn classify_handles_presence_frames_locally() {
    // A well-formed presence_challenge is handled by the host (ADR-0031),
    // never forwarded.
    match classify_nm_frame(&json!({ "type": "presence_challenge", "nonce": "n",
                                     "context": "c" }))
    {
        FrameDisposition::PresenceChallenge { nonce, context } => {
            assert_eq!(nonce, "n");
            assert_eq!(context.as_deref(), Some("c"));
        }
        other => panic!("expected PresenceChallenge, got {other:?}"),
    }
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "presence_challenge", "nonce": "n" })),
        FrameDisposition::PresenceChallenge { context: None, .. }
    ));
    // Malformed presence challenges are answered with a presence_error,
    // never signed and never forwarded.
    for bad in [
        json!({ "type": "presence_challenge" }),
        json!({ "type": "presence_challenge", "nonce": 5 }),
        json!({ "type": "presence_challenge", "nonce": "n", "extra": 1 }),
    ] {
        assert!(
            matches!(classify_nm_frame(&bad), FrameDisposition::MalformedPresence),
            "{bad}"
        );
    }
    // Stray presence proof/error frames from the browser leg are dropped:
    // they are host-originated frames only.
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "presence_proof", "sig": "s" })),
        FrameDisposition::Drop("presence_proof")
    ));
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "presence_error", "reason": "r" })),
        FrameDisposition::Drop("presence_error")
    ));
    // And the socket->stdout pump recognizes all three as host control
    // types, so a misbehaving server cannot inject a forged presence
    // verdict (the signature check would catch it, but it must not even
    // reach the extension).
    for tag in ["presence_challenge", "presence_proof", "presence_error"] {
        assert_eq!(
            host_control_type(&json!({ "type": tag })),
            Some(tag),
            "{tag}"
        );
    }
}

#[test]
fn classify_handles_revoke_and_admin_frames_locally() {
    // A well-formed enclave_revoke is handled by the host (ADR-0025).
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "enclave_revoke" })),
        FrameDisposition::RevokeHostKey
    ));
    // A malformed one is dropped: no error-reply contract exists for it,
    // and dropping fails closed without a misleading reason code.
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "enclave_revoke", "extra": 1 })),
        FrameDisposition::Drop(_)
    ));
    // A stray enclave_revoked from the extension is dropped (it is a
    // host-originated frame only).
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "enclave_revoked" })),
        FrameDisposition::Drop("enclave_revoked")
    ));

    // Admin requests classify to their handlers...
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "client_list" })),
        FrameDisposition::ClientList
    ));
    match classify_nm_frame(&json!({ "type": "client_revoke", "name": "codex" })) {
        FrameDisposition::ClientRevoke { name } => assert_eq!(name, "codex"),
        other => panic!("expected ClientRevoke, got {other:?}"),
    }
    // ...malformed admin requests get the matching {ok:false} reply,
    // carried as the typed AdminKind so the reply builder cannot
    // misroute one...
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "client_list", "extra": 1 })),
        FrameDisposition::MalformedAdmin(AdminKind::ClientList)
    ));
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "client_revoke" })),
        FrameDisposition::MalformedAdmin(AdminKind::ClientRevoke)
    ));
    // ...and stray result frames from the browser side are dropped.
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "client_list_result", "ok": true })),
        FrameDisposition::Drop("client_list_result")
    ));
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "client_revoke_result", "ok": true })),
        FrameDisposition::Drop("client_revoke_result")
    ));
}

#[test]
fn admin_control_serde_roundtrips() {
    use crate::allowlist::{Anchor, ClientEntry};
    let result = AdminControl::ClientListResult {
        ok: true,
        enrolled: true,
        clients: vec![ClientEntry {
            name: "claude-code".into(),
            anchor: Anchor::TeamId("3ZMH96L4V9".into()),
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
fn classify_handles_kill_and_audit_frames_locally() {
    // ADR-0030: the three kill requests classify to their handlers...
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "kill_status" })),
        FrameDisposition::KillStatus
    ));
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "kill_engage" })),
        FrameDisposition::KillEngage
    ));
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "kill_release" })),
        FrameDisposition::KillRelease
    ));
    // ...malformed variants get the matching ok:false reply path...
    for (tag, kind) in [
        ("kill_status", AdminKind::KillStatus),
        ("kill_engage", AdminKind::KillEngage),
        ("kill_release", AdminKind::KillRelease),
    ] {
        assert!(matches!(
            classify_nm_frame(&json!({ "type": tag, "extra": 1 })),
            FrameDisposition::MalformedAdmin(k) if k == kind
        ));
    }
    // ...a result frame never legitimately arrives inbound...
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "kill_status_result", "ok": true })),
        FrameDisposition::Drop(_)
    ));
    // ...an audit event carries its fields BY NAME to the handler, with
    // the kind already typed as extension-owned...
    match classify_nm_frame(&json!({
        "type": "audit_event", "kind": "confirm_denied", "tool": "eval", "cid": "c-42"
    })) {
        FrameDisposition::AuditEvent(fields) => {
            assert_eq!(fields.kind, crate::audit::AuditKind::ConfirmDenied);
            assert_eq!(fields.tool.as_deref(), Some("eval"));
            // The per-confirmation correlation id survives parsing so the
            // host writes it into the audit record for the panel to join on.
            assert_eq!(fields.cid.as_deref(), Some("c-42"));
        }
        other => panic!("expected AuditEvent, got {other:?}"),
    }
    // ...and a malformed one is dropped (fire-and-forget: no reply
    // contract to honor, and nothing may be recorded from garbage).
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "audit_event" })),
        FrameDisposition::Drop(_)
    ));
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "audit_event", "kind": 5 })),
        FrameDisposition::Drop(_)
    ));
}

#[test]
fn audit_events_with_host_owned_kinds_are_dropped_at_classification() {
    // The forgery gate lives IN classification: a frame claiming a
    // host-owned kind (an admission, a kill, a presence sign) never
    // becomes an AuditEvent disposition at all, so no downstream consumer
    // can record it. The offending value rides the drop for the log.
    for kind in [
        "kill_engage",
        "harness_admit",
        "tool_call",
        "presence_sign",
        "admission",
        "",
    ] {
        match classify_nm_frame(&json!({ "type": "audit_event", "kind": kind })) {
            FrameDisposition::DropForeignAuditKind { kind: k } => assert_eq!(k, kind),
            other => panic!("expected DropForeignAuditKind for {kind:?}, got {other:?}"),
        }
    }
    // Positive control: an extension-owned kind still classifies to a
    // typed, recordable AuditEvent.
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "audit_event", "kind": "confirm_shown" })),
        FrameDisposition::AuditEvent(AuditEventFields {
            kind: crate::audit::AuditKind::ConfirmShown,
            ..
        })
    ));
}

#[test]
fn admin_kind_tags_match_their_classification() {
    // The kind<->tag pairing, end to end: a malformed frame carrying each
    // kind's wire tag classifies to MalformedAdmin of exactly that kind,
    // so wire_tag and classify_nm_frame agree on the mapping (the const
    // assertion above only ties the tags to the derived SET).
    for &kind in AdminKind::ALL {
        match classify_nm_frame(&json!({ "type": kind.wire_tag(), "unexpected": 1 })) {
            FrameDisposition::MalformedAdmin(k) => {
                assert_eq!(k, kind, "{}", kind.wire_tag());
            }
            other => panic!("expected MalformedAdmin({kind:?}), got {other:?}"),
        }
    }
}

#[test]
fn every_control_variant_tag_is_derived_and_recognized() {
    use std::collections::BTreeSet;

    // One sample of EVERY variant of the three control enums.
    // Completeness of this list is enforced below (its tag set must equal
    // the derived tag set), and the derived set itself cannot miss a
    // variant: wire_tag's match has no wildcard arm, so a new variant
    // fails to compile until its tag joins the control_wire_tags! list
    // feeding both.
    let enclave: Vec<EnclaveControl> = vec![
        EnclaveControl::EnclaveChallenge {
            nonce: "n".into(),
            context: None,
        },
        EnclaveControl::EnclaveProof {
            sig: "s".into(),
            key_id: "k".into(),
            pubkey: "p".into(),
        },
        EnclaveControl::EnclaveError { reason: "r".into() },
        EnclaveControl::EnclaveRevoke {},
        EnclaveControl::EnclaveRevoked {},
        EnclaveControl::PresenceChallenge {
            nonce: "n".into(),
            context: None,
        },
        EnclaveControl::PresenceProof {
            sig: "s".into(),
            key_id: "k".into(),
            pubkey: "p".into(),
        },
        EnclaveControl::PresenceError { reason: "r".into() },
    ];
    let admin: Vec<AdminControl> = vec![
        AdminControl::ClientList {},
        AdminControl::ClientListResult {
            ok: true,
            enrolled: false,
            clients: Vec::new(),
            error: None,
        },
        AdminControl::ClientRevoke { name: "x".into() },
        AdminControl::ClientRevokeResult {
            ok: true,
            error: None,
        },
        AdminControl::KillStatus {},
        AdminControl::KillEngage {},
        AdminControl::KillRelease {},
        AdminControl::KillStatusResult {
            ok: true,
            killed: Some(false),
            error: None,
        },
        AdminControl::AuditEvent {
            kind: "confirm_shown".into(),
            outcome: None,
            tool: None,
            name: None,
            detail: None,
            cid: None,
        },
    ];
    let policy: Vec<PolicyControl> = vec![
        PolicyControl::PolicyGet {},
        PolicyControl::PolicyCurrent {
            ok: true,
            baseline: Some("YmFzZQ==".into()),
            sig: Some("c2ln".into()),
            overlay: Some(crate::policy::PolicyOverlay::default()),
            reason: None,
            error: None,
        },
        PolicyControl::LegacySettings { bag: json!({}) },
        PolicyControl::LangGet {},
        PolicyControl::LangSet { value: "en".into() },
        PolicyControl::LangCurrent {
            value: "en".into(),
            seq: 1,
        },
    ];

    // Serde round-trip per variant: the tag serde actually emits is the
    // tag the derived set claims, in both directions.
    let mut seen: BTreeSet<&'static str> = BTreeSet::new();
    for frame in &enclave {
        let v = serde_json::to_value(frame).unwrap();
        let tag = v.get("type").and_then(Value::as_str).unwrap();
        assert_eq!(tag, frame.wire_tag(), "serde tag drifted for {frame:?}");
        let back: EnclaveControl = serde_json::from_value(v).unwrap();
        assert_eq!(back.wire_tag(), frame.wire_tag());
        seen.insert(frame.wire_tag());
    }
    for frame in &admin {
        let v = serde_json::to_value(frame).unwrap();
        let tag = v.get("type").and_then(Value::as_str).unwrap();
        assert_eq!(tag, frame.wire_tag(), "serde tag drifted for {frame:?}");
        let back: AdminControl = serde_json::from_value(v).unwrap();
        assert_eq!(back.wire_tag(), frame.wire_tag());
        seen.insert(frame.wire_tag());
    }
    for frame in &policy {
        let v = serde_json::to_value(frame).unwrap();
        let tag = v.get("type").and_then(Value::as_str).unwrap();
        assert_eq!(tag, frame.wire_tag(), "serde tag drifted for {frame:?}");
        let back: PolicyControl = serde_json::from_value(v).unwrap();
        assert_eq!(back.wire_tag(), frame.wire_tag());
        seen.insert(frame.wire_tag());
    }
    let derived: BTreeSet<&'static str> = ENCLAVE_CONTROL_TAGS
        .iter()
        .chain(ADMIN_CONTROL_TAGS)
        .chain(POLICY_CONTROL_TAGS)
        .copied()
        .collect();
    assert_eq!(
        seen, derived,
        "the sample lists above must cover every control variant"
    );
    assert_eq!(
        derived.len(),
        ENCLAVE_CONTROL_TAGS.len() + ADMIN_CONTROL_TAGS.len() + POLICY_CONTROL_TAGS.len(),
        "a tag is duplicated across the control enums"
    );

    // Every derived tag is recognized by BOTH pumps' classifiers: the
    // socket->stdout pump drops a server-injected one, and the
    // stdin->socket pump never forwards one to the MCP server.
    for tag in &derived {
        assert_eq!(
            host_control_type(&json!({ "type": tag })),
            Some(*tag),
            "tag {tag} must be recognized as host control"
        );
        assert!(
            !matches!(
                classify_nm_frame(&json!({ "type": tag })),
                FrameDisposition::Forward
            ),
            "tag {tag} must never classify as Forward"
        );
    }
    // ...while bridge traffic and near-misses pass through untouched.
    assert_eq!(
        host_control_type(&json!({ "id": 1, "op": "tab_list" })),
        None
    );
    assert_eq!(host_control_type(&json!({ "type": "enclave_other" })), None);
    assert_eq!(host_control_type(&json!({ "type": 5 })), None);
    assert_eq!(host_control_type(&json!("enclave_error")), None);
}

#[test]
fn policy_frames_are_answered_or_dropped_and_recognized_as_host_control() {
    // ADR-0032 phase 2: the four extension-originated frames are ANSWERED
    // by the host (policy_get, legacy_settings, lang_get, lang_set), so
    // they classify to their own dispositions - never Drop, never Forward
    // (an old-style forward would tear the browser leg down on the MCP
    // server's strict BridgeResp parse). The two host->extension pushes
    // (policy_current, lang_current) arriving FROM the browser stay
    // DROPPED (host->extension only). Every one is still recognized as
    // host control by both pumps' classifiers.
    for tag in POLICY_CONTROL_TAGS {
        assert_eq!(
            host_control_type(&json!({ "type": tag })),
            Some(*tag),
            "tag {tag} must be recognized as host control"
        );
        assert!(
            !matches!(
                classify_nm_frame(&json!({ "type": tag })),
                FrameDisposition::Forward
            ),
            "tag {tag} must never classify as Forward"
        );
    }
    // The four answered frames map to their own dispositions.
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "policy_get" })),
        FrameDisposition::PolicyGet
    ));
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "legacy_settings", "bag": { "groupTabs": true } })),
        FrameDisposition::LegacySettings { .. }
    ));
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "lang_get" })),
        FrameDisposition::LangGet
    ));
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "lang_set", "value": "en" })),
        FrameDisposition::LangSet { .. }
    ));
    // The two host->extension pushes are dropped when they arrive from the
    // browser: they are host-originated only.
    for tag in ["policy_current", "lang_current"] {
        assert!(
            matches!(classify_nm_frame(&json!({ "type": tag })), FrameDisposition::Drop(t) if t == tag),
            "tag {tag} must classify as Drop from the browser leg"
        );
    }
    // Malformed extension-originated frames take their typed malformed arm
    // (a reply is owed) rather than Forward - except legacy_settings,
    // which is fire-and-forget and drops (audited, with the size only).
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "policy_get", "extra": 1 })),
        FrameDisposition::MalformedPolicy(PolicyKind::PolicyGet)
    ));
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "lang_get", "extra": 1 })),
        FrameDisposition::MalformedPolicy(PolicyKind::LangGet)
    ));
    assert!(matches!(
        classify_nm_frame(&json!({ "type": "lang_set" })),
        FrameDisposition::MalformedPolicy(PolicyKind::LangSet)
    ));
    let bagless = json!({ "type": "legacy_settings" });
    let expected = serde_json::to_vec(&bagless).unwrap().len();
    assert!(matches!(
        classify_nm_frame(&bagless),
        FrameDisposition::MalformedLegacySettings { bytes } if bytes == expected
    ));
}

#[test]
fn policy_current_serializes_exactly_its_pinned_key_set() {
    // ADR-0032 decision 3: verification and the ratchet key on the
    // extension's own pin and nothing else - a frame-supplied key id
    // would hand a substituted host a ratchet-reset lever. Pin the
    // fully-populated frame's serialized keys so no key-identity field
    // (or anything else) can ever join it unnoticed.
    let frame = PolicyControl::PolicyCurrent {
        ok: true,
        baseline: Some("YmFzZQ==".into()),
        sig: Some("c2ln".into()),
        overlay: Some(crate::policy::PolicyOverlay::default()),
        reason: Some("absent".into()),
        error: Some("e".into()),
    };
    let value = serde_json::to_value(&frame).unwrap();
    let keys: std::collections::BTreeSet<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let expected: std::collections::BTreeSet<&str> = [
        "type", "ok", "baseline", "sig", "overlay", "reason", "error",
    ]
    .into_iter()
    .collect();
    assert_eq!(keys, expected);
}

#[test]
fn policy_status_into_frame_forbids_illegal_mixtures() {
    // The KillStatus discipline for policy_current (ADR-0032): the typed
    // intermediate emits only the two flat shapes the contract means, so a
    // sig without a baseline, a baseline on an ok:false, or an ok:true
    // with an error is unconstructible past this point.
    match (PolicyStatus::Present {
        baseline_b64: "YmFzZQ==".into(),
        sig_b64: Some("c2ln".into()),
        overlay: None,
    })
    .into_frame()
    {
        PolicyControl::PolicyCurrent {
            ok: true,
            baseline: Some(_),
            sig: Some(_),
            error: None,
            ..
        } => {}
        other => panic!("present must be ok:true with baseline and no error: {other:?}"),
    }
    // An unsigned (app-floor) baseline: still ok:true with a baseline, sig
    // absent - never a sig without its baseline.
    match (PolicyStatus::Present {
        baseline_b64: "YmFzZQ==".into(),
        sig_b64: None,
        overlay: None,
    })
    .into_frame()
    {
        PolicyControl::PolicyCurrent {
            ok: true,
            baseline: Some(_),
            sig: None,
            ..
        } => {}
        other => panic!("unsigned present must carry the baseline and no sig: {other:?}"),
    }
    match (PolicyStatus::Unavailable {
        reason: Some(PolicyUnavailableReason::Absent),
        error: "no policy baseline".into(),
    })
    .into_frame()
    {
        PolicyControl::PolicyCurrent {
            ok: false,
            baseline: None,
            sig: None,
            overlay: None,
            reason: Some(r),
            error: Some(_),
        } => assert_eq!(r, "absent"),
        other => panic!("unavailable must be ok:false with no baseline claim: {other:?}"),
    }
}

#[test]
fn envelope_schema_inputs_are_pinned_and_pairwise_disjoint() {
    // emit_envelope_schema.rs - the input to the asymmetry gate
    // (`moon run check-envelope`) - derives from exactly EnclaveControl,
    // AdminControl, and PolicyControl (ADR-0032 phase 3 added the policy
    // group). Pin all three tag lists literally, pairwise disjoint, so a
    // frame can never silently join or leave the enums the gate derives,
    // and no tag can classify under two groups.
    let enclave: &[&str] = &[
        "enclave_challenge",
        "enclave_proof",
        "enclave_error",
        "enclave_revoke",
        "enclave_revoked",
        "presence_challenge",
        "presence_proof",
        "presence_error",
    ];
    assert_eq!(ENCLAVE_CONTROL_TAGS, enclave);
    let admin: &[&str] = &[
        "client_list",
        "client_list_result",
        "client_revoke",
        "client_revoke_result",
        "kill_status",
        "kill_engage",
        "kill_release",
        "kill_status_result",
        "audit_event",
    ];
    assert_eq!(ADMIN_CONTROL_TAGS, admin);
    let policy: &[&str] = &[
        "policy_get",
        "policy_current",
        "legacy_settings",
        "lang_get",
        "lang_set",
        "lang_current",
    ];
    assert_eq!(POLICY_CONTROL_TAGS, policy);
    let all: Vec<&str> = [
        ENCLAVE_CONTROL_TAGS,
        ADMIN_CONTROL_TAGS,
        POLICY_CONTROL_TAGS,
    ]
    .concat();
    let distinct: std::collections::BTreeSet<&str> = all.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        all.len(),
        "a control tag appears in more than one emitted enum"
    );
}
