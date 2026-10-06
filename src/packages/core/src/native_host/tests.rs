use super::*;
use crate::protocol::BRIDGE_MAX_LINE;
use crate::runtime_record::RuntimeRecord;
use crate::trust::{Clients, Trust, TrustState};
use std::io::Cursor;

fn exchange() -> Exchange {
    Exchange::new(BrowserLabel::default_label())
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
        "{\"type\":\"presence_confirm\",\"nonce\":\"n\"}\n",
        "{\"type\":\"presence_request\",\"challenge\":\"c\",\"nonce\":\"n\",\"action\":\"a\",\"allowed_credential_ids\":[]}\n",
        "{\"type\":\"presence_result\",\"ok\":true}\n",
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
    // The policy/language frames are host control, so a
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

/// A scratch runtime dir for the frame-answer tests (the policy
/// and language stores, the trust record, and the audit trail all
/// resolve their paths internally): the crate-wide
/// [`crate::test_support::scratch_runtime_dir`] guard, so no test reads
/// or writes the user's real state and no other module's tests race the
/// process-global env var under plain `cargo test`.
use crate::test_support::scratch_runtime_dir;

fn audit_text() -> String {
    std::fs::read_to_string(crate::audit::audit_path().unwrap()).unwrap_or_default()
}

#[test]
fn policy_frames_from_the_browser_are_answered_or_dropped() {
    // The three extension-originated frames are ANSWERED by the host (policy_get, lang_get, lang_set):
    // each parses as a request, never Forward (a forward would tear the browser leg down on the MCP
    // server's strict BridgeResp parse). The two host->extension pushes (policy_current, lang_current)
    // arriving FROM the browser are malformed under their tag with nothing owed. All are Handled, never
    // forwarded. A scratch runtime dir isolates the store reads/writes the answers do.
    let _dir = scratch_runtime_dir();
    let out = Mutex::new(Vec::new());
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
        let verdict = handle_control_frame(frame, &out, &mut exchange()).unwrap();
        assert!(matches!(verdict, Inbound::Handled));
    }
}

#[test]
fn policy_get_answers_the_signed_baseline_from_the_store() {
    let _dir = scratch_runtime_dir();
    crate::ipc::with_runtime_lock(|lock| {
        Ok(crate::enclave::EnrollmentKey::mint(
            lock,
            crate::enclave::KeyStore::File,
            crate::presence::PresenceAttestation::assume_for_tests(
                crate::presence::PresencePath::Tty,
            ),
        ))
    })
    .unwrap()
    .unwrap();
    crate::policy::set_signed(
        crate::policy::PolicyValues {
            page_eval_enabled: true,
            ..Default::default()
        },
        vec![crate::policy::PolicyField::PageEvalEnabled],
        crate::audit::Surface::Core,
        || {
            Ok(crate::presence::PresenceAttestation::assume_for_tests(
                crate::presence::PresencePath::Tty,
            ))
        },
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
        let _dir = scratch_runtime_dir();
        if let Some(bytes) = bytes {
            std::fs::write(crate::policy::PolicyStore::path().unwrap(), bytes).unwrap();
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
fn audit_read_answers_the_lines_the_cli_prints() {
    // The page reads the host trail through the same reader as `chromium-bridge audit`: the newest `limit`
    // lines, an unparsable line kept in its position, the older count, and the live path for the CLI's
    // empty state. Pinned at the frame, where the words leave the host.
    use crate::protocol::control::{AuditReadLimit, AuditTrailEntry};
    let _dir = scratch_runtime_dir();
    let live = crate::audit::audit_path().unwrap();
    let record = |ts_ms: u64, kind: &str| {
        format!("{{\"v\":1,\"ts_ms\":{ts_ms},\"event_kind\":\"{kind}\",\"surface\":\"cli\",\"outcome\":\"ok\"}}\n")
    };
    std::fs::write(
        &live,
        record(1_000, "kill_engage") + "{not json\n" + &record(3_000, "pair_client"),
    )
    .unwrap();
    let limit: AuditReadLimit = serde_json::from_value(serde_json::json!(2)).unwrap();
    assert_eq!(
        serde_json::to_value(audit_read_reply(Some(limit))).unwrap(),
        serde_json::to_value(
            AuditReport::Page {
                entries: vec![
                    AuditTrailEntry::Record {
                        ts_ms: crate::tools::args::JsInt::from(3_000),
                        kind: "pair_client".into(),
                        fields: "surface=cli outcome=ok".into(),
                    },
                    AuditTrailEntry::Unrecognized {
                        text: crate::audit::UNRECOGNIZED_RECORD.into(),
                    },
                ],
                older: 1,
                path: live.to_string_lossy().into_owned(),
            }
            .into_frame()
        )
        .unwrap()
    );
    // No limit named: the CLI's default page, which here is the whole trail.
    let AdminControl::AuditReadResult {
        ok: true,
        entries: Some(entries),
        older: Some(0),
        ..
    } = audit_read_reply(None)
    else {
        panic!("the default page did not answer ok with every line");
    };
    assert_eq!(entries.len(), 3);
}

#[test]
fn registration_report_carries_rows_exactly_when_the_resolver_ran() {
    // The row mapping doctor's `ManifestStatus` takes onto the wire, without a HOME: the browser key,
    // detection, state, and location all cross, and an unresolvable environment answers ok:false with the
    // reason and no rows (the extension shows the error instead of an empty healthy-looking table).
    use crate::browsers::{Scope, Scoped};
    use crate::doctor::{ManifestStatus, SlotStatus};
    use crate::protocol::control::RegistrationState;
    use crate::registration::RegState;
    let slot = |state: RegState, location: &str| SlotStatus {
        state,
        location: location.into(),
        owner: None,
    };
    let report = registration_report(Ok(vec![
        ManifestStatus {
            key: "chrome",
            detected: true,
            manifest: Scoped {
                user: slot(RegState::Ok, "/home/user/chrome/host.json"),
                system: slot(RegState::Missing, "/etc/chrome/host.json"),
            },
            effective_scope: Scope::User,
            pointer: None,
        },
        ManifestStatus {
            key: "brave",
            detected: false,
            manifest: Scoped {
                user: slot(
                    RegState::Foreign("another host's manifest".into()),
                    "/home/user/brave/host.json",
                ),
                system: slot(RegState::Missing, "/etc/brave/host.json"),
            },
            effective_scope: Scope::User,
            pointer: None,
        },
    ]));
    assert_eq!(
        report,
        RegistrationReport::Rows(vec![
            RegistrationRow {
                browser: "chrome".into(),
                detected: true,
                state: RegistrationState::Ok {},
                location: "/home/user/chrome/host.json".into(),
            },
            RegistrationRow {
                browser: "brave".into(),
                detected: false,
                state: RegistrationState::Foreign {
                    detail: "another host's manifest".into()
                },
                location: "/home/user/brave/host.json".into(),
            },
        ])
    );
    assert_eq!(
        registration_report(Err("HOME (or USERPROFILE) is not set".into())),
        RegistrationReport::Unavailable {
            error: "HOME (or USERPROFILE) is not set".into()
        }
    );
}

/// A signed baseline that grants `page_eval`, written the way the CLI's grant lane writes one: the host key
/// minted into the scratch runtime dir's file record, the test attestation standing in for the typed phrase.
fn signed_baseline_granting_page_eval() {
    use crate::presence::{PresenceAttestation, PresencePath};
    let mint_auth = PresenceAttestation::assume_for_tests(PresencePath::Tty);
    crate::ipc::with_runtime_lock(|lock| {
        Ok(crate::enclave::EnrollmentKey::mint(
            lock,
            crate::enclave::KeyStore::File,
            mint_auth,
        ))
    })
    .unwrap()
    .unwrap();
    crate::policy::set_signed(
        crate::policy::PolicyValues {
            page_eval_enabled: true,
            ..Default::default()
        },
        vec![crate::policy::PolicyField::PageEvalEnabled],
        crate::audit::Surface::Core,
        || Ok(PresenceAttestation::assume_for_tests(PresencePath::Tty)),
    )
    .unwrap();
}

#[test]
fn policy_restrict_tightens_the_store_and_refuses_a_relaxation() {
    // The extension's restriction lane rides the same seam as `policy restrict`: a tightening lands in the
    // store (and the next policy_current carries the overlay), a relaxation is refused with the seam's reason
    // and leaves the store untouched, and both verdicts are audited with the extension surface.
    let _dir = scratch_runtime_dir();
    signed_baseline_granting_page_eval();

    let tightened = policy_restrict_replies(crate::policy::PolicyOverlay {
        page_eval_enabled: Some(false),
        ..Default::default()
    });
    assert_eq!(
        serde_json::to_value(&tightened[0]).unwrap(),
        serde_json::json!({ "type": "policy_restrict_result", "ok": true })
    );
    let PolicyControl::PolicyCurrent {
        overlay: Some(overlay),
        ..
    } = policy_current_reply()
    else {
        panic!("the restriction must show in the next policy_current");
    };
    assert_eq!(overlay.page_eval_enabled, Some(false));

    let relaxed = policy_restrict_replies(crate::policy::PolicyOverlay {
        page_eval_enabled: Some(true),
        ..Default::default()
    });
    let [PolicyControl::PolicyRestrictResult {
        ok: false,
        error: Some(error),
    }] = relaxed.as_slice()
    else {
        panic!("a relaxation must be refused with nothing pushed: {relaxed:?}");
    };
    assert!(error.contains("relax"), "{error}");
    let PolicyControl::PolicyCurrent {
        overlay: Some(overlay),
        ..
    } = policy_current_reply()
    else {
        panic!("the refused relaxation must leave the overlay in place");
    };
    assert_eq!(overlay.page_eval_enabled, Some(false));
    // Both verdicts reach the trail under the extension surface: the tightening as ok, the relaxation as its
    // own refused record (deleting the seam's NotARestriction audit branch loses the second).
    let trail = audit_text();
    assert!(
        trail.contains("\"surface\":\"extension\"")
            && trail.contains("\"outcome\":\"ok\"")
            && trail.contains("restricted=pageEvalEnabled")
            && trail.contains("\"outcome\":\"refused\"")
            && trail.contains("refused: relaxes the effective policy"),
        "{trail}"
    );
}

#[test]
fn an_applied_restrict_pushes_policy_current_even_when_the_epoch_bump_fails() {
    // The store write and the epoch bump are two steps, and the bump is best-effort. A trust record whose
    // epoch cannot climb makes the bump fail after a successful write, so the watch sees nothing to push;
    // the restriction must still reach the extension as the reply that follows the result, since
    // confirmPageEval is enforced in the extension's mirror alone.
    let _dir = scratch_runtime_dir();
    signed_baseline_granting_page_eval();
    crate::ipc::with_runtime_lock(|lock| {
        Trust::fixture(u64::MAX, false, Clients::NeverPaired).write(lock)
    })
    .unwrap();

    let replies = policy_restrict_replies(crate::policy::PolicyOverlay {
        page_eval_enabled: Some(false),
        ..Default::default()
    });
    let [PolicyControl::PolicyRestrictResult { ok: true, .. }, PolicyControl::PolicyCurrent {
        overlay: Some(overlay),
        ..
    }] = replies.as_slice()
    else {
        panic!("an applied restriction must be followed by policy_current: {replies:?}");
    };
    assert_eq!(overlay.page_eval_enabled, Some(false));
    let trust = TrustState::current().unwrap();
    assert_eq!(
        (trust.epoch(), trust.policy_epoch()),
        (u64::MAX, 0),
        "the bump must have failed, so the reply above is the only push"
    );
}

#[test]
fn lang_get_answers_the_current_language() {
    let _dir = scratch_runtime_dir();
    crate::lang::set(crate::lang::UiLang::parse("zh_TW").unwrap()).unwrap();
    let reply = lang_current_frame().unwrap();
    let PolicyControl::LangCurrent { value, seq } = reply else {
        panic!("lang_get must answer lang_current: {reply:?}");
    };
    assert_eq!(value, "zh_TW");
    assert_eq!(seq, 1);
}

#[test]
fn lang_set_applies_a_valid_value_and_bumps_the_sequence() {
    let _dir = scratch_runtime_dir();
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
    // A value outside the enum is refused and the
    // previous value stands - the reply is lang_current with the
    // UNCHANGED value+seq, and the store is untouched.
    let _dir = scratch_runtime_dir();
    crate::lang::set(crate::lang::UiLang::parse("zh_CN").unwrap()).unwrap();
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
fn kill_status_reply_never_claims_a_state_it_cannot_read() {
    // On a machine whose trust record is absent (the unit-test
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
    let out = Mutex::new(Vec::new());
    for kind in ["kill_engage", "harness_admit"] {
        let verdict = handle_control_frame(
            serde_json::json!({ "type": "audit_event", "kind": kind }),
            &out,
            &mut exchange(),
        )
        .unwrap();
        assert!(matches!(verdict, Inbound::Handled));
    }
}

/// The extension's revoke on a machine with no host key answers `enclave_revoked` (the requested end state
/// holds), and a second one the same; a minted key is gone after it, with the host-key epoch moved.
#[test]
fn extension_revoke_reaches_the_end_state_and_moves_the_host_key_epoch() {
    let _dir = scratch_runtime_dir();
    assert!(matches!(
        revoke_host_key(),
        EnclaveControl::EnclaveRevoked {}
    ));
    crate::ipc::with_runtime_lock(|lock| {
        Ok(crate::enclave::EnrollmentKey::mint(
            lock,
            crate::enclave::KeyStore::File,
            crate::presence::PresenceAttestation::assume_for_tests(
                crate::presence::PresencePath::Tty,
            ),
        ))
    })
    .unwrap()
    .unwrap();
    let before = TrustState::current().unwrap().host_key_epoch();
    assert!(matches!(
        revoke_host_key(),
        EnclaveControl::EnclaveRevoked {}
    ));
    assert!(crate::enclave::EnrollmentKey::lookup().unwrap().is_none());
    assert!(TrustState::current().unwrap().host_key_epoch() > before);
}

// ---- the control-plane unkill drain -------------------------------------------

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
    let _dir = scratch_runtime_dir();
    let out = Mutex::new(Vec::new());
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
