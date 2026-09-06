use super::*;
use crate::protocol::BRIDGE_MAX_LINE;
use std::io::Cursor;

#[test]
fn presence_slot_is_single_flight_and_released_on_drop() {
    // The guard's constructor IS the acquire: while one guard exists the
    // slot cannot be won again, and dropping it (any exit path, including
    // a spawn failure dropping the never-run closure) releases it.
    let first = PresenceSlotGuard::try_acquire().unwrap();
    assert!(
        PresenceSlotGuard::try_acquire().is_none(),
        "the slot is single-flight while a guard exists"
    );
    drop(first);
    assert!(
        PresenceSlotGuard::try_acquire().is_some(),
        "dropping the guard releases the slot"
    );
}

#[test]
fn over_cap_line_on_receive_leg_is_rejected() {
    // One line just past the cap, followed by a perfectly valid frame: the
    // pump must fail closed at the over-cap line (stop, emit nothing, not
    // even the later valid frame). The old `reader.lines()` pump buffered
    // the giant line unbounded (the OOM path), skipped it as malformed,
    // and would have emitted the trailing frame - so this pins both the
    // cap and the fail-closed stop.
    let mut input = Vec::with_capacity(BRIDGE_MAX_LINE + 32);
    input.resize(BRIDGE_MAX_LINE + 1, b'x');
    input.extend_from_slice(b"\n{\"after\":true}\n");
    let out = Mutex::new(Vec::new());
    pump_socket_to_stdout(&mut Cursor::new(input), &out);
    assert!(out.into_inner().unwrap().is_empty());
}

#[test]
fn valid_lines_are_framed_until_the_over_cap_line() {
    // A legal frame, then an over-cap line, then another legal frame: the
    // first goes out as native messaging, and the pump stops at the
    // poisoned line - the frame after it must never be emitted.
    let mut input = b"{\"ok\":true}\n".to_vec();
    input.resize(input.len() + BRIDGE_MAX_LINE + 1, b'x');
    input.extend_from_slice(b"\n{\"after\":true}\n");
    let out = Mutex::new(Vec::new());
    pump_socket_to_stdout(&mut Cursor::new(input), &out);

    let mut cur = Cursor::new(out.into_inner().unwrap());
    let frame = nm_read_frame(&mut cur).unwrap().unwrap();
    assert_eq!(frame, serde_json::json!({ "ok": true }));
    // Nothing after the first frame: the over-cap line was rejected.
    assert!(nm_read_frame(&mut cur).unwrap().is_none());
}

#[test]
fn malformed_json_fails_closed() {
    // Malformed JSON used to be skip-and-continue; it now ends the pump
    // (fail closed against an attested-but-hostile peer), so the valid
    // frame after it must not be emitted.
    let out = Mutex::new(Vec::new());
    pump_socket_to_stdout(&mut Cursor::new(b"not-json\n{\"id\":2}\n".to_vec()), &out);
    assert!(out.into_inner().unwrap().is_empty());
}

#[test]
fn blank_lines_are_skipped_and_eof_ends_the_pump() {
    let out = Mutex::new(Vec::new());
    pump_socket_to_stdout(&mut Cursor::new(b"\n\n{\"id\":1}\n".to_vec()), &out);
    let mut cur = Cursor::new(out.into_inner().unwrap());
    let frame = nm_read_frame(&mut cur).unwrap().unwrap();
    assert_eq!(frame, serde_json::json!({ "id": 1 }));
    assert!(nm_read_frame(&mut cur).unwrap().is_none());
}

#[test]
fn server_injected_control_frames_are_dropped_not_forwarded() {
    // The server leg never legitimately carries host-handled control
    // frames (the ceremony and the admin exchange run extension <-> host
    // only), so injected frames - the nonce-burning enclave_error, the
    // false-compromise enclave_revoked, a forged client_list_result - must
    // be dropped while the pump keeps forwarding real traffic around them.
    let input = concat!(
        "{\"type\":\"enclave_error\",\"reason\":\"key_invalid\"}\n",
        "{\"type\":\"enclave_challenge\",\"nonce\":\"n\"}\n",
        "{\"type\":\"enclave_proof\",\"sig\":\"s\",\"key_id\":\"k\",\"pubkey\":\"p\"}\n",
        "{\"type\":\"enclave_revoke\"}\n",
        "{\"type\":\"enclave_revoked\"}\n",
        "{\"type\":\"presence_challenge\",\"nonce\":\"n\"}\n",
        "{\"type\":\"presence_proof\",\"sig\":\"s\",\"key_id\":\"k\",\"pubkey\":\"p\"}\n",
        "{\"type\":\"presence_error\",\"reason\":\"busy\"}\n",
        "{\"type\":\"client_list\"}\n",
        "{\"type\":\"client_list_result\",\"ok\":true,\"enrolled\":true,\"clients\":[]}\n",
        "{\"type\":\"client_revoke\",\"name\":\"codex\"}\n",
        "{\"type\":\"client_revoke_result\",\"ok\":true}\n",
        "{\"type\":\"kill_status\"}\n",
        "{\"type\":\"kill_engage\"}\n",
        "{\"type\":\"kill_release\"}\n",
        "{\"type\":\"kill_status_result\",\"ok\":true,\"killed\":false}\n",
        "{\"type\":\"audit_event\",\"kind\":\"confirm_allowed\"}\n",
        "{\"id\":7,\"op\":\"tab_list\"}\n",
    );
    let out = Mutex::new(Vec::new());
    pump_socket_to_stdout(&mut Cursor::new(input.as_bytes().to_vec()), &out);

    let mut cur = Cursor::new(out.into_inner().unwrap());
    let frame = nm_read_frame(&mut cur).unwrap().unwrap();
    assert_eq!(frame, serde_json::json!({ "id": 7, "op": "tab_list" }));
    assert!(nm_read_frame(&mut cur).unwrap().is_none());
}

#[test]
fn server_injected_policy_frames_are_dropped_not_forwarded() {
    // ADR-0032: the policy/language frames are host control, so a
    // misbehaving or substituted MCP server cannot inject a
    // `policy_current` down the server leg - the extension's ratchet
    // would refuse a forged relaxation anyway, but the frame must not
    // even reach it. Each one writes nothing to stdout and the pump
    // keeps going, forwarding real traffic around them.
    let input = concat!(
        "{\"type\":\"policy_current\",\"ok\":true,\"baseline\":\"YmFzZQ==\",\"sig\":\"c2ln\"}\n",
        "{\"type\":\"policy_get\"}\n",
        "{\"type\":\"legacy_settings\",\"bag\":{}}\n",
        "{\"type\":\"lang_get\"}\n",
        "{\"type\":\"lang_set\",\"value\":\"en\"}\n",
        "{\"type\":\"lang_current\",\"value\":\"en\",\"seq\":1}\n",
        "{\"id\":9,\"op\":\"tab_list\"}\n",
    );
    let out = Mutex::new(Vec::new());
    pump_socket_to_stdout(&mut Cursor::new(input.as_bytes().to_vec()), &out);

    let mut cur = Cursor::new(out.into_inner().unwrap());
    let frame = nm_read_frame(&mut cur).unwrap().unwrap();
    assert_eq!(frame, serde_json::json!({ "id": 9, "op": "tab_list" }));
    assert!(nm_read_frame(&mut cur).unwrap().is_none());
}

/// A scratch runtime dir for the ADR-0032 frame-answer tests (the policy
/// and language stores, the revocation record, and the audit trail all
/// resolve their paths internally): the crate-wide
/// [`crate::test_support::scratch_runtime_dir`] guard, so no test reads
/// or writes the user's real state and no other module's tests race the
/// process-global env var under plain `cargo test`.
use crate::test_support::scratch_runtime_dir;

fn audit_text() -> String {
    std::fs::read_to_string(crate::audit::audit_path()).unwrap_or_default()
}

#[test]
fn policy_frames_from_the_browser_are_answered_or_dropped() {
    // ADR-0032 phase 2: the four extension-originated frames are ANSWERED
    // by the host (policy_get, legacy_settings, lang_get, lang_set) - each
    // classifies to its own disposition, never Drop, never Forward (an
    // old-style forward would tear the browser leg down on the MCP
    // server's strict BridgeResp parse). The two host->extension pushes
    // (policy_current, lang_current) arriving FROM the browser stay
    // DROPPED (host->extension only). All are Handled, never forwarded. A
    // scratch runtime dir isolates the store reads/writes the answers do.
    let _dir = scratch_runtime_dir("native-host-answered-or-dropped");
    let out = Arc::new(Mutex::new(BufWriter::new(io::stdout())));
    for (frame, is_drop) in [
        (serde_json::json!({ "type": "policy_get" }), false),
        (
            serde_json::json!({ "type": "legacy_settings", "bag": {} }),
            false,
        ),
        (serde_json::json!({ "type": "lang_get" }), false),
        (
            serde_json::json!({ "type": "lang_set", "value": "zh_CN" }),
            false,
        ),
        (
            serde_json::json!({ "type": "policy_current", "ok": true }),
            true,
        ),
        (
            serde_json::json!({ "type": "lang_current", "value": "en", "seq": 1 }),
            true,
        ),
    ] {
        let disposition = classify_nm_frame(&frame);
        if is_drop {
            assert!(
                matches!(disposition, FrameDisposition::Drop(_)),
                "host->extension push must Drop from the browser leg: {frame}"
            );
        } else {
            assert!(
                !matches!(
                    disposition,
                    FrameDisposition::Drop(_) | FrameDisposition::Forward
                ),
                "extension-originated frame must be answered, not dropped/forwarded: {frame}"
            );
        }
        let verdict = handle_control_frame(frame, &out).unwrap();
        assert!(matches!(verdict, Inbound::Handled));
    }
}

#[test]
fn legacy_settings_receipts_are_audited_and_only_recording_bumps_the_epoch() {
    // Finding 2: every receipt outcome lands in the audit trail (kind
    // legacy_import_receipt, host-owned) with the outcome and byte count
    // but NEVER the bag, and only the Recorded arm bumps the policy
    // epoch (which is what makes an open app re-probe and surface the
    // arrival through its import nav entry).
    let _dir = scratch_runtime_dir("native-host-legacy-receipt-audit");
    let out = Arc::new(Mutex::new(BufWriter::new(io::stdout())));
    let policy_epoch = || {
        crate::revocation::Revocation::current()
            .unwrap()
            .policy_epoch
    };
    let send = |bag: serde_json::Value| {
        let frame = serde_json::json!({ "type": "legacy_settings", "bag": bag });
        assert!(matches!(
            handle_control_frame(frame, &out).unwrap(),
            Inbound::Handled
        ));
    };

    // Recorded: audited, epoch bumped.
    send(serde_json::json!({ "pageEvalEnabled": true, "marker": "sekritbagvalue" }));
    let text = audit_text();
    assert!(text.contains("legacy_import_receipt"), "{text}");
    assert!(text.contains("\"outcome\":\"recorded\""), "{text}");
    assert!(
        !text.contains("sekritbagvalue") && !text.contains("pageEvalEnabled"),
        "the audit trail must never carry bag contents: {text}"
    );
    let after_record = policy_epoch();
    assert!(after_record > 0, "recording must bump the policy epoch");

    // First-bag-wins drop: audited, no bump.
    send(serde_json::json!({ "later": true }));
    assert!(audit_text().contains("\"outcome\":\"dropped_already_pending\""));
    assert_eq!(policy_epoch(), after_record);

    // Post-consume drop: audited, no bump (consume itself bumps nothing;
    // the policy write that drives it audits and bumps separately).
    crate::pending_import::consume().unwrap();
    let epoch_after_consume = policy_epoch();
    send(serde_json::json!({ "replant": true }));
    assert!(audit_text().contains("\"outcome\":\"dropped_consumed\""));
    assert_eq!(policy_epoch(), epoch_after_consume);

    // Oversize drop: audited with the byte count, no bump.
    let huge = "x".repeat(crate::pending_import::LEGACY_BAG_MAX_BYTES + 1);
    send(serde_json::json!({ "blob": huge }));
    let text = audit_text();
    assert!(text.contains("\"outcome\":\"dropped_oversize\""), "{text}");
    assert!(
        !text.contains("xxxxxxxxxx"),
        "no bag bytes in the trail: {text}"
    );
    assert_eq!(policy_epoch(), epoch_after_consume);

    // Unreadable store: the error outcome is audited too.
    std::fs::write(crate::pending_import::path(), b"{ not json").unwrap();
    send(serde_json::json!({ "after": "corruption" }));
    assert!(audit_text().contains("\"outcome\":\"error\""));

    // Malformed frame (no parsable bag): audited as dropped_malformed
    // with the size only - the unparsed content never reaches the trail.
    let malformed = serde_json::json!({ "type": "legacy_settings", "surprisemarker": true });
    assert!(matches!(
        handle_control_frame(malformed, &out).unwrap(),
        Inbound::Handled
    ));
    let text = audit_text();
    assert!(text.contains("\"outcome\":\"dropped_malformed\""), "{text}");
    assert!(
        !text.contains("surprisemarker"),
        "unparsed frame content must never reach the trail: {text}"
    );
}

#[test]
fn policy_get_answers_ok_false_when_no_store_exists() {
    // Fail closed (ADR-0032 decision 4/5): an absent store answers
    // ok:false with an error and no baseline claim, so the extension keeps
    // its deny baseline rather than trusting bytes nobody vouched for.
    let _dir = scratch_runtime_dir("native-host-policy-get-absent");
    match policy_current_reply() {
        PolicyControl::PolicyCurrent {
            ok: false,
            baseline: None,
            sig: None,
            reason: Some(reason),
            error: Some(_),
            ..
        } => assert_eq!(reason, "absent"),
        other => panic!("absent store must answer ok:false with no baseline: {other:?}"),
    }
}

#[test]
fn policy_get_answers_the_signed_baseline_from_the_store() {
    let _dir = scratch_runtime_dir("native-host-policy-get-present");
    let _reset = crate::presence::policy_test_hook::ResetOnDrop;
    crate::presence::policy_test_hook::set(crate::presence::policy_test_hook::Mock::Return(
        crate::presence::PolicySignOutcome::Signed {
            sig: [7; 64],
            key_id: "kid".into(),
            pubkey_b64: "pk".into(),
        },
    ));
    crate::policy::set_signed(
        crate::policy::PolicyValues {
            page_eval_enabled: true,
            ..Default::default()
        },
        vec![crate::policy::PolicyField::PageEvalEnabled],
        crate::audit::Surface::Core,
        crate::policy::PolicyGrantFloor::SignatureOnly,
    )
    .unwrap();
    match policy_current_reply() {
        PolicyControl::PolicyCurrent {
            ok: true,
            baseline: Some(baseline),
            sig: Some(_),
            error: None,
            ..
        } => assert!(!baseline.is_empty()),
        other => panic!("a present store must answer ok:true with a baseline: {other:?}"),
    }
}

#[test]
fn policy_get_answers_ok_false_on_a_damaged_or_tampered_store() {
    // ADR-0032 decision 5: an unreadable OR MALFORMED store answers
    // ok:false - the push must agree with the dispatch gate's deny-all
    // reading of the same state, never vouch ok:true for bytes the gate
    // refuses.
    let _dir = scratch_runtime_dir("native-host-policy-get-damaged");
    // Envelope parses, baseline bytes are garbage.
    let garbage = crate::policy::PolicyStore {
        version: 1,
        baseline_b64: crate::enclave::base64_encode(b"not a policy doc"),
        sig_b64: None,
        key_id: None,
        overlay: None,
    };
    std::fs::write(
        crate::policy::PolicyStore::path(),
        serde_json::to_vec(&garbage).unwrap(),
    )
    .unwrap();
    match policy_current_reply() {
        PolicyControl::PolicyCurrent {
            ok: false,
            baseline: None,
            sig: None,
            reason: Some(reason),
            error: Some(_),
            ..
        } => assert_eq!(reason, "damaged"),
        other => panic!("a damaged baseline must answer ok:false: {other:?}"),
    }
    // Valid baseline, tampered overlay relaxing it (direction-invalid).
    let doc = crate::policy::PolicyDoc::default();
    let tampered = crate::policy::PolicyStore {
        version: 1,
        baseline_b64: crate::enclave::base64_encode(&serde_json::to_vec(&doc).unwrap()),
        sig_b64: None,
        key_id: None,
        overlay: Some(crate::policy::PolicyOverlay {
            page_eval_enabled: Some(true),
            ..Default::default()
        }),
    };
    std::fs::write(
        crate::policy::PolicyStore::path(),
        serde_json::to_vec(&tampered).unwrap(),
    )
    .unwrap();
    match policy_current_reply() {
        PolicyControl::PolicyCurrent {
            ok: false,
            baseline: None,
            sig: None,
            reason: Some(reason),
            error: Some(e),
            ..
        } => {
            assert!(e.contains("damaged"));
            assert_eq!(reason, "damaged");
        }
        other => panic!("a tampered overlay must answer ok:false: {other:?}"),
    }
}

#[test]
fn policy_get_answers_ok_false_unreadable_on_a_damaged_store_envelope() {
    // ADR-0032 D-P4-2: a store whose ENVELOPE cannot be read (wrong
    // version here, an I/O failure in general) is distinct from an absent
    // or a content-damaged store - it answers reason=unreadable, so the
    // extension keeps its deny baseline and never mistakes it for the
    // absent state that triggers the legacy import.
    let _dir = scratch_runtime_dir("native-host-policy-get-unreadable");
    std::fs::write(
        crate::policy::PolicyStore::path(),
        br#"{"version":99,"baseline_b64":"e30="}"#,
    )
    .unwrap();
    match policy_current_reply() {
        PolicyControl::PolicyCurrent {
            ok: false,
            reason: Some(reason),
            error: Some(_),
            ..
        } => assert_eq!(reason, "unreadable"),
        other => panic!("an unreadable store envelope must answer ok:false: {other:?}"),
    }
}

#[test]
fn lang_get_answers_the_current_language() {
    let _dir = scratch_runtime_dir("native-host-lang-get");
    crate::lang::set("zh_TW").unwrap();
    match lang_current_frame().unwrap() {
        PolicyControl::LangCurrent { value, seq } => {
            assert_eq!(value, "zh_TW");
            assert_eq!(seq, 1);
        }
        other => panic!("lang_get must answer lang_current: {other:?}"),
    }
}

#[test]
fn lang_set_applies_a_valid_value_and_bumps_the_sequence() {
    let _dir = scratch_runtime_dir("native-host-lang-set-valid");
    match handle_lang_set("zh_CN".into()).unwrap() {
        PolicyControl::LangCurrent { value, seq } => {
            assert_eq!(value, "zh_CN");
            assert_eq!(seq, 1);
        }
        other => panic!("lang_set must answer the applied lang_current: {other:?}"),
    }
    assert_eq!(
        crate::lang::load_current().unwrap(),
        ("zh_CN".to_string(), 1)
    );
}

#[test]
fn an_out_of_enum_lang_set_replies_the_unchanged_current() {
    // ADR-0032 decision 7: a value outside the enum is refused and the
    // previous value stands - the reply is lang_current with the
    // UNCHANGED value+seq, and the store is untouched.
    let _dir = scratch_runtime_dir("native-host-lang-set-invalid");
    crate::lang::set("zh_CN").unwrap();
    match handle_lang_set("fr".into()).unwrap() {
        PolicyControl::LangCurrent { value, seq } => {
            assert_eq!(value, "zh_CN");
            assert_eq!(seq, 1);
        }
        other => panic!("a refused lang_set must reply the unchanged current: {other:?}"),
    }
    assert_eq!(
        crate::lang::load_current().unwrap(),
        ("zh_CN".to_string(), 1)
    );
}

#[test]
fn extension_kill_release_is_refused_audited_and_does_not_release() {
    // ADR-0032 decision 6: the extension's release path is retired. Engage
    // the kill switch, then attempt release from the extension: the reply
    // is a refusal (ok:false, no killed claim), the trail records it, and
    // the bridge stays killed - the refusal never calls kill::release.
    let _dir = scratch_runtime_dir("native-host-kill-release-refused");
    crate::kill::engage(crate::audit::Surface::Cli).unwrap();
    match handle_kill_release_refused() {
        AdminControl::KillStatusResult {
            ok: false,
            killed: None,
            error: Some(_),
        } => {}
        other => panic!("extension release must be refused with no killed claim: {other:?}"),
    }
    assert!(
        crate::kill::is_killed().unwrap(),
        "the refusal must NOT release the kill switch"
    );
    let trail = audit_text();
    assert!(trail.contains("kill_release"), "{trail}");
    assert!(trail.contains("\"outcome\":\"refused\""), "{trail}");
}

#[test]
fn malformed_admin_frames_get_a_matching_ok_false_reply() {
    // The reply frame type must match the request so the extension's
    // pending request resolves instead of timing out. Every AdminKind is
    // exercised; the builder itself is exhaustive, so a new kind fails to
    // compile until it gets a reply of its own type.
    for kind in [
        AdminKind::ClientList,
        AdminKind::ClientRevoke,
        AdminKind::KillStatus,
        AdminKind::KillEngage,
        AdminKind::KillRelease,
    ] {
        match (kind, malformed_admin_reply(kind)) {
            (
                AdminKind::ClientList,
                AdminControl::ClientListResult {
                    ok: false,
                    error: Some(_),
                    ..
                },
            ) => {}
            (
                AdminKind::ClientRevoke,
                AdminControl::ClientRevokeResult {
                    ok: false,
                    error: Some(_),
                },
            ) => {}
            // The kill frames all resolve to a kill_status_result whose
            // ok:false carries NO killed claim (unknown fails closed on
            // the extension side).
            (
                AdminKind::KillStatus | AdminKind::KillEngage | AdminKind::KillRelease,
                AdminControl::KillStatusResult {
                    ok: false,
                    killed: None,
                    error: Some(_),
                },
            ) => {}
            (kind, other) => {
                panic!("reply type does not match request kind {kind:?}: {other:?}")
            }
        }
    }
}

#[test]
fn kill_status_reply_never_claims_a_state_it_cannot_read() {
    // On a machine whose revocation record is absent (the unit-test
    // environment), the reply is ok with an explicit killed flag; the
    // ok:false shape is pinned by the malformed test above and the
    // adversarial suite (corrupt record).
    match kill_status_reply() {
        AdminControl::KillStatusResult {
            ok: true,
            killed: Some(_),
            error: None,
        } => {}
        AdminControl::KillStatusResult {
            ok: false,
            killed: None,
            error: Some(_),
        } => {}
        other => {
            panic!("kill_status_result must never pair ok:false with a killed claim: {other:?}")
        }
    }
}

#[test]
fn audit_events_with_host_side_kinds_are_dropped() {
    // The forgery gate now lives in classification (protocol/control.rs pins the
    // DropForeignAuditKind mapping); this exercises the host wiring: the
    // frame is Handled (never forwarded), no reply is written, and
    // nothing recordable is ever constructed - handle_audit_event only
    // accepts the typed AuditEventFields classification can produce.
    let out = Arc::new(Mutex::new(BufWriter::new(io::stdout())));
    for kind in ["kill_engage", "harness_admit"] {
        let verdict = handle_control_frame(
            serde_json::json!({ "type": "audit_event", "kind": kind }),
            &out,
        )
        .unwrap();
        assert!(matches!(verdict, Inbound::Handled));
    }
}

#[cfg(not(target_os = "macos"))]
#[test]
fn revoke_on_an_unsupported_platform_reports_the_stable_reason() {
    // Non-macOS: EnrollmentKey::revoke fails closed with Unsupported and
    // the reply carries the stable reason code, never a panic.
    match revoke_host_key() {
        EnclaveControl::EnclaveError { reason } => {
            assert_eq!(reason, "unsupported_platform");
        }
        other => panic!("expected enclave_error, got {other:?}"),
    }
}

// ---- ADR-0030: the control-plane unkill drain -----------------------------

#[test]
fn a_buffered_engage_across_unkill_is_drained_and_keeps_the_host_killed() {
    // The gap this pins: the extension is told ok:true for a kill_engage
    // the moment the frame is accepted for the pipe, so one can still be
    // buffered on stdin when the watch observes an in-flight release
    // landing. Exiting at that point (the old watch-thread process::exit)
    // dropped the acknowledged brake on the floor. The drain must hand
    // the frame to the control handler FIRST, and the re-engaged state it
    // produces must keep the host in control-plane mode.
    let (tx, rx) = mpsc::channel();
    tx.send(PlaneEvent::Frame(
        serde_json::json!({"type": "kill_engage"}),
    ))
    .unwrap();
    let _keep_stdin_open = tx;
    let killed = std::cell::Cell::new(false);
    let mut handled = Vec::new();
    let mut handle = |frame: Value| {
        killed.set(true); // the engage applies to the record
        handled.push(frame);
        Ok(())
    };
    let decision = drain_then_decide(&rx, &mut handle, &|| Ok(killed.get()));
    assert!(matches!(decision, UnkillDecision::Stay));
    assert_eq!(handled, vec![serde_json::json!({"type": "kill_engage"})]);
}

#[test]
fn a_quiet_pipe_with_an_alive_state_exits_for_the_bridge_mode_respawn() {
    let (tx, rx) = mpsc::channel::<PlaneEvent>();
    let _keep_stdin_open = tx;
    let decision = drain_then_decide(&rx, &mut |_| Ok(()), &|| Ok(false));
    assert!(matches!(
        decision,
        UnkillDecision::Exit(PlaneExit::Unkilled)
    ));
}

#[test]
fn an_unreadable_state_after_the_drain_stays_in_control_plane_mode() {
    // Leaving killed mode on an unreadable record would fail open: the
    // fresh host would dial the broker before anyone re-proved "alive".
    let (tx, rx) = mpsc::channel::<PlaneEvent>();
    let _keep_stdin_open = tx;
    let decision = drain_then_decide(&rx, &mut |_| Ok(()), &|| {
        Err(io::Error::other("corrupt record"))
    });
    assert!(matches!(decision, UnkillDecision::Stay));
}

#[test]
fn eof_during_the_drain_ends_the_host() {
    let (tx, rx) = mpsc::channel();
    tx.send(PlaneEvent::Eof).unwrap();
    let decision = drain_then_decide(&rx, &mut |_| Ok(()), &|| Ok(false));
    assert!(matches!(
        decision,
        UnkillDecision::Exit(PlaneExit::StdinClosed)
    ));
}

#[test]
fn the_loop_handles_buffered_frames_before_exiting_on_unkill() {
    // Loop-level wiring: with the watch's flag already raised and a frame
    // buffered, the loop must run the drain (handling the frame) before
    // its exit decision - never exit with the frame unread.
    let (tx, rx) = mpsc::channel();
    tx.send(PlaneEvent::Frame(
        serde_json::json!({"type": "kill_status"}),
    ))
    .unwrap();
    let _keep_stdin_open = tx;
    let flag = AtomicBool::new(true);
    let mut handled = Vec::new();
    let exit = control_plane_loop(
        &rx,
        &flag,
        &mut |frame| {
            handled.push(frame);
            Ok(())
        },
        &|| Ok(false),
    );
    assert_eq!(exit, PlaneExit::Unkilled);
    assert_eq!(handled, vec![serde_json::json!({"type": "kill_status"})]);
}
