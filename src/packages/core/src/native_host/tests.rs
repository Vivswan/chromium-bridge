use super::*;
use crate::protocol::BRIDGE_MAX_LINE;
use crate::trust::{Clients, Trust, TrustState};
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
    // The three extension-originated frames are ANSWERED by the host (policy_get, lang_get, lang_set):
    // each parses as a request, never Forward (a forward would tear the browser leg down on the MCP
    // server's strict BridgeResp parse). The two host->extension pushes (policy_current, lang_current)
    // arriving FROM the browser are malformed under their tag with nothing owed. All are Handled, never
    // forwarded. A scratch runtime dir isolates the store reads/writes the answers do.
    let _dir = scratch_runtime_dir("native-host-answered-or-dropped");
    let out = Arc::new(Mutex::new(BufWriter::new(io::stdout())));
    for (frame, is_push) in [
        (serde_json::json!({ "type": "policy_get" }), false),
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
        match classify_nm_frame(&frame) {
            FrameDisposition::Handle(_) => {
                assert!(
                    !is_push,
                    "a host->extension push must not parse as a request: {frame}"
                );
            }
            FrameDisposition::Malformed { tag, .. } => {
                assert!(
                    is_push,
                    "an extension-originated frame must be answered: {frame}"
                );
                assert!(
                    matches!(tag.malformed_reply(), MalformedReply::Drop),
                    "a bounced push owes nothing: {frame}"
                );
            }
            FrameDisposition::Forward => panic!("host control must never forward: {frame}"),
        }
        let verdict = handle_control_frame(frame, &out).unwrap();
        assert!(matches!(verdict, Inbound::Handled));
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
    )
    .unwrap();
    let reply = policy_current_reply();
    let PolicyControl::PolicyCurrent {
        ok: true,
        baseline: Some(baseline),
        sig: Some(_),
        error: None,
        ..
    } = reply
    else {
        panic!("a present store must answer ok:true with a baseline: {reply:?}");
    };
    assert!(!baseline.is_empty());
}

#[test]
fn policy_get_answers_ok_false_without_a_usable_store() {
    // Fail closed: every store state the dispatch gate reads as deny-all answers ok:false with an error and
    // no baseline claim, so the extension keeps its deny baseline rather than trusting bytes nobody vouched
    // for. The push must agree with the gate's reading, never vouch ok:true for bytes the gate refuses.
    fn store(baseline: &[u8], overlay: Option<crate::policy::PolicyOverlay>) -> Vec<u8> {
        crate::policy::PolicyStore {
            baseline_b64: crate::enclave::base64_encode(baseline),
            sig_b64: None,
            key_id: None,
            overlay,
        }
        .encode()
        .unwrap()
    }
    let default_doc = serde_json::to_vec(&crate::policy::PolicyDoc::default()).unwrap();
    let relaxing = crate::policy::PolicyOverlay {
        page_eval_enabled: Some(true),
        ..Default::default()
    };
    let cases: [(&str, Option<Vec<u8>>, &str); 4] = [
        ("absent store", None, "no policy baseline"),
        (
            "garbage baseline bytes",
            Some(store(b"not a policy doc", None)),
            "policy store damaged",
        ),
        (
            "overlay relaxing the baseline",
            Some(store(&default_doc, Some(relaxing))),
            "policy store damaged",
        ),
        (
            "unreadable envelope (unknown version)",
            Some(br#"{"version":99,"baseline_b64":"e30="}"#.to_vec()),
            "policy store unreadable",
        ),
    ];
    for (case, bytes, error_prefix) in cases {
        let _dir = scratch_runtime_dir("native-host-policy-get-unusable");
        if let Some(bytes) = bytes {
            std::fs::write(crate::policy::PolicyStore::path(), bytes).unwrap();
        }
        let reply = policy_current_reply();
        let PolicyControl::PolicyCurrent {
            ok: false,
            baseline: None,
            sig: None,
            overlay: None,
            error: Some(error),
        } = reply
        else {
            panic!("{case}: must answer ok:false with no baseline claim: {reply:?}");
        };
        assert!(error.starts_with(error_prefix), "{case}: {error}");
    }
}

#[test]
fn lang_get_answers_the_current_language() {
    let _dir = scratch_runtime_dir("native-host-lang-get");
    crate::lang::set("zh_TW").unwrap();
    let reply = lang_current_frame().unwrap();
    let PolicyControl::LangCurrent { value, seq } = reply else {
        panic!("lang_get must answer lang_current: {reply:?}");
    };
    assert_eq!(value, "zh_TW");
    assert_eq!(seq, 1);
}

#[test]
fn lang_set_applies_a_valid_value_and_bumps_the_sequence() {
    let _dir = scratch_runtime_dir("native-host-lang-set-valid");
    let reply = handle_lang_set("zh_CN".into()).unwrap();
    let PolicyControl::LangCurrent { value, seq } = reply else {
        panic!("lang_set must answer the applied lang_current: {reply:?}");
    };
    assert_eq!(value, "zh_CN");
    assert_eq!(seq, 1);
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
    let reply = handle_lang_set("fr".into()).unwrap();
    let PolicyControl::LangCurrent { value, seq } = reply else {
        panic!("a refused lang_set must reply the unchanged current: {reply:?}");
    };
    assert_eq!(value, "zh_CN");
    assert_eq!(seq, 1);
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
    let reply = handle_kill_release_refused();
    assert!(
        matches!(
            reply,
            AdminControl::KillStatusResult {
                ok: false,
                killed: None,
                error: Some(_),
            }
        ),
        "extension release must be refused with no killed claim: {reply:?}"
    );
    assert!(
        crate::kill::is_killed().unwrap(),
        "the refusal must NOT release the kill switch"
    );
    let trail = audit_text();
    assert!(trail.contains("kill_release"), "{trail}");
    assert!(trail.contains("\"outcome\":\"refused\""), "{trail}");
}

#[test]
fn kill_status_reply_never_claims_a_state_it_cannot_read() {
    // On a machine whose revocation record is absent (the unit-test
    // environment), the reply is ok with an explicit killed flag; the
    // ok:false shape is pinned by the malformed test above and the
    // adversarial suite (corrupt record).
    let reply = kill_status_reply();
    assert!(
        matches!(
            reply,
            AdminControl::KillStatusResult {
                ok: true,
                killed: Some(_),
                error: None,
            } | AdminControl::KillStatusResult {
                ok: false,
                killed: None,
                error: Some(_),
            }
        ),
        "kill_status_result must never pair ok:false with a killed claim: {reply:?}"
    );
}

#[test]
fn audit_events_with_host_side_kinds_are_dropped() {
    // The forgery gate lives in the parse (protocol/control.rs: a host-owned kind is not an
    // ExtensionAuditKind); this exercises the host wiring: the frame is Handled (never forwarded), no
    // reply is written, and nothing recordable is ever constructed.
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
    let reply = revoke_host_key();
    let EnclaveControl::EnclaveError { reason } = reply else {
        panic!("expected enclave_error, got {reply:?}");
    };
    assert_eq!(reason, "unsupported_platform");
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

/// The review incident: a host that started on an unreadable trust record (control-plane mode) saw the operator's
/// documented recovery, deleting the record, as a readable released bootstrap and pushed killed:false to the
/// extension, yet never handed the release to the control-plane loop, which kept dropping bridge frames until
/// Chrome respawned the host. The same gap followed killed -> unreadable -> released. A recovered record that is
/// still killed hands nothing over.
#[test]
fn a_released_record_recovered_after_an_unreadable_gap_hands_the_release_to_the_loop() {
    // The push helpers read the policy, language and trust stores from the runtime dir.
    let _dir = scratch_runtime_dir("native-host-recovered-release");
    let out = Mutex::new(BufWriter::new(io::stdout()));
    let released = || Ok(TrustState::from(Trust::default()));
    let killed = || {
        Ok(TrustState::from(Trust::fixture(
            1,
            true,
            Clients::NeverPaired,
        )))
    };
    let unreadable = || Err(io::Error::other("corrupt"));

    let flag = AtomicBool::new(false);
    let last = watch_tick(None, unreadable(), &out, Some(&flag));
    assert!(last.is_none() && !flag.load(Ordering::Acquire));
    let last = watch_tick(last, released(), &out, Some(&flag));
    assert!(last.is_some());
    assert!(
        flag.load(Ordering::Acquire),
        "unreadable at start, then released: the loop must be told"
    );

    let flag = AtomicBool::new(false);
    let last = watch_tick(None, killed(), &out, Some(&flag));
    let last = watch_tick(last, unreadable(), &out, Some(&flag));
    assert!(last.is_none() && !flag.load(Ordering::Acquire));
    watch_tick(last, released(), &out, Some(&flag));
    assert!(
        flag.load(Ordering::Acquire),
        "killed, unreadable, then released: the loop must be told"
    );

    let flag = AtomicBool::new(false);
    watch_tick(None, killed(), &out, Some(&flag));
    assert!(
        !flag.load(Ordering::Acquire),
        "a recovered record that is still killed hands nothing over"
    );
}
