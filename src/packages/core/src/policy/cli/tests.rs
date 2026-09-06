use super::*;
use crate::enclave::base64_encode;

/// A `PolicyStore` seeded in memory (no disk): a baseline document over
/// `values` at `revision`, optionally signed, with `overlay`.
fn store(
    revision: u64,
    values: &PolicyValues,
    signed: bool,
    overlay: Option<PolicyOverlay>,
) -> PolicyStore {
    let doc = PolicyDoc {
        revision,
        page_eval_enabled: values.page_eval_enabled,
        cdp_mode: values.cdp_mode,
        file_upload_enabled: values.file_upload_enabled,
        handle_dialog_enabled: values.handle_dialog_enabled,
        confirm_high_risk_click: values.confirm_high_risk_click,
        confirm_page_eval: values.confirm_page_eval,
        touch_id_confirm: values.touch_id_confirm,
        confirm_tab_close: values.confirm_tab_close,
        warn_precise_snapshot: values.warn_precise_snapshot,
        eval_mask: values.eval_mask,
        host_reverify_ms: values.host_reverify_ms,
        confirm_grace_ms: values.confirm_grace_ms,
        click_toast_timeout_ms: values.click_toast_timeout_ms,
        eval_toast_timeout_ms: values.eval_toast_timeout_ms,
        disabled_tools: values.disabled_tools.clone(),
        ..PolicyDoc::default()
    };
    let bytes = serde_json::to_vec(&doc).unwrap();
    PolicyStore {
        version: super::super::POLICY_STORE_VERSION,
        baseline_b64: base64_encode(&bytes),
        sig_b64: signed.then(|| base64_encode(b"sig")),
        key_id: signed.then(|| "kid".to_string()),
        overlay,
    }
}

#[test]
fn status_none_is_the_pre_cutover_state() {
    let r = PolicyStatusReport::none();
    assert_eq!(r.store(), PolicyStoreState::None);
    assert!(matches!(r, PolicyStatusReport::None { v: 1 }));
    // The wire form carries only the tag and the version: the sum cannot
    // smuggle present-arm fields onto the none arm.
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(v, serde_json::json!({ "store": "none", "v": 1 }));
}

#[test]
fn status_present_carries_revision_signed_overlay_and_effective() {
    let base = PolicyValues {
        page_eval_enabled: true,
        ..PolicyValues::default()
    };
    let overlay = PolicyOverlay {
        page_eval_enabled: Some(false),
        ..PolicyOverlay::default()
    };
    let r = status_from_store(&store(3, &base, true, Some(overlay)));
    assert_eq!(r.store(), PolicyStoreState::Present);
    let PolicyStatusReport::Present {
        v,
        revision,
        signed,
        overlay_active,
        ref effective,
    } = r
    else {
        panic!("expected Present, got {r:?}");
    };
    assert_eq!(v, 1);
    assert_eq!(revision, 3);
    assert!(signed);
    assert!(overlay_active);
    // Effective folds the overlay: pageEval restricted back off.
    assert!(!effective.page_eval_enabled);
    // The signed line never claims host-side verification.
    assert!(render_status(&r).contains("not verifiable here"));
}

#[test]
fn status_of_a_damaged_baseline_is_error_not_a_default() {
    let mut s = store(1, &PolicyValues::default(), false, None);
    s.baseline_b64 = "not base64!".into();
    let r = status_from_store(&s);
    assert_eq!(r.store(), PolicyStoreState::Error);
    assert!(matches!(r, PolicyStatusReport::Error { .. }));
    // An unsigned baseline reads as unsigned, never "invalid".
    let unsigned = status_from_store(&store(1, &PolicyValues::default(), false, None));
    assert!(matches!(
        unsigned,
        PolicyStatusReport::Present { signed: false, .. }
    ));
    assert!(render_status(&unsigned).contains("unsigned"));
}

#[test]
fn status_report_round_trips_and_rejects_unknown_fields() {
    let r = status_from_store(&store(2, &PolicyValues::default(), true, None));
    let json = serde_json::to_string(&r).unwrap();
    let back: PolicyStatusReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
    // deny_unknown_fields is the app's fail-closed guard.
    let bad = r#"{"v":1,"store":"none","surprise":1}"#;
    assert!(serde_json::from_str::<PolicyStatusReport>(bad).is_err());
    // The sum makes a contradictory mixture a parse error, not a value:
    // a none report cannot smuggle present-arm data, and a present one
    // cannot omit its payload.
    let smuggled = r#"{"v":1,"store":"none","revision":3}"#;
    assert!(serde_json::from_str::<PolicyStatusReport>(smuggled).is_err());
    let hollow = r#"{"v":1,"store":"present"}"#;
    assert!(serde_json::from_str::<PolicyStatusReport>(hollow).is_err());
}

#[test]
fn error_report_round_trips_and_rejects_unknown_fields() {
    // The write lanes' --json failure object: same frozen-wire posture
    // as the status report (the desktop app v-gates then strict-parses).
    let r = PolicyErrorReport {
        v: 1,
        error: "policy signing refused: user cancelled".into(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: PolicyErrorReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
    let bad = r#"{"v":1,"error":"x","surprise":1}"#;
    assert!(serde_json::from_str::<PolicyErrorReport>(bad).is_err());
}

#[test]
fn history_report_maps_entries_and_tolerates_a_damaged_one() {
    use super::super::{PolicyHistoryEntry, POLICY_HISTORY_VERSION};
    let good = PolicyDoc {
        revision: 5,
        ..PolicyDoc::default()
    };
    let history = PolicyHistory {
        version: POLICY_HISTORY_VERSION,
        entries: vec![
            PolicyHistoryEntry {
                baseline_b64: base64_encode(&serde_json::to_vec(&good).unwrap()),
                sig_b64: Some(base64_encode(b"s")),
                key_id: None,
                overlay: Some(PolicyOverlay {
                    page_eval_enabled: Some(false),
                    ..PolicyOverlay::default()
                }),
                superseded_unix: 111,
            },
            PolicyHistoryEntry {
                baseline_b64: "garbage!".into(),
                sig_b64: None,
                key_id: None,
                overlay: None,
                superseded_unix: 222,
            },
        ],
    };
    let r = history_report(&history);
    assert_eq!(r.entries[0].revision, Some(5));
    assert!(r.entries[0].signed);
    assert!(r.entries[0].overlay_active);
    // A damaged entry keeps its slot with a null revision.
    assert_eq!(r.entries[1].revision, None);
    assert!(!r.entries[1].signed);
    assert_eq!(r.entries[1].superseded_unix, 222);
}

#[test]
fn pending_import_prose_reports_every_state_without_the_bag() {
    use crate::pending_import::PendingImportReport;
    // Prose mode NEVER prints the bag - stdout is only the payload under
    // --json - so a secret-looking value in the recorded bag must not
    // appear in the rendering, only its size.
    let present = render_pending_import(&PendingImportReport::Present {
        v: 1,
        bag: serde_json::json!({ "secretish": "hunter2" }),
    });
    assert!(present.contains("present"), "got: {present}");
    assert!(!present.contains("hunter2"), "got: {present}");
    assert!(!present.contains("secretish"), "got: {present}");
    // The mid-consume arm retains a bag too (P4G-4): same no-content rule.
    let consuming = render_pending_import(&PendingImportReport::Consuming {
        v: 1,
        bag: serde_json::json!({ "secretish": "hunter2" }),
    });
    assert!(consuming.contains("consuming"), "got: {consuming}");
    assert!(consuming.contains("closed to new bags"), "got: {consuming}");
    assert!(!consuming.contains("hunter2"), "got: {consuming}");
    assert!(!consuming.contains("secretish"), "got: {consuming}");
    assert!(
        render_pending_import(&PendingImportReport::None { v: 1 }).contains("none"),
        "the healthy no-receipt state renders as none"
    );
    assert!(render_pending_import(&PendingImportReport::Consumed { v: 1 }).contains("consumed"));
    let error = render_pending_import(&PendingImportReport::Error {
        v: 1,
        detail: "version 99 is not supported".into(),
    });
    assert!(error.contains("UNREADABLE"), "got: {error}");
    assert!(error.contains("failing closed"), "got: {error}");
    assert!(error.contains("version 99"), "got: {error}");
}

#[test]
fn grant_gate_refuses_every_keyless_state_with_a_clear_message() {
    // The security-critical decision 5 mapping, driven purely (never the
    // real keychain): only a present key proceeds.
    assert!(grant_key_gate(GrantKey::Present).is_ok());
    assert!(grant_key_gate(GrantKey::Absent)
        .unwrap_err()
        .contains("signature-only"));
    assert!(grant_key_gate(GrantKey::Unsupported)
        .unwrap_err()
        .contains("no Secure Enclave"));
    assert!(grant_key_gate(GrantKey::Unusable("planted".into()))
        .unwrap_err()
        .contains("unusable"));
}

#[test]
fn an_unparsable_argv_still_counts_as_asking_for_json() {
    let args = |list: &[&str]| list.iter().map(ToString::to_string).collect::<Vec<_>>();
    // An empty `set` edit fails the parser, yet the raw argv names
    // --json: run_policy must emit the versioned error object for it.
    let bad = args(&["chromium-bridge", "policy", "set", "--json"]);
    assert!(policy_args(&bad).is_err());
    assert!(argv_wants_json(&bad));
    // No --json anywhere: the prose path.
    assert!(!argv_wants_json(&args(&[
        "chromium-bridge",
        "policy",
        "bogus"
    ])));
    // argv[0] and argv[1] are outside the scan, whatever they contain.
    assert!(!argv_wants_json(&args(&["--json", "--json"])));
}

#[test]
fn a_no_op_rollback_changes_nothing() {
    let v = PolicyValues::default();
    assert_eq!(plan_rollback(&v, &v, &v), RollbackPlan::NoChange);
}

#[test]
fn a_tightening_rollback_uses_the_free_lane() {
    // current has pageEval ON; target (a past revision) has it OFF: rolling
    // back only tightens, so it rides the free restrict lane.
    let current = PolicyValues {
        page_eval_enabled: true,
        ..PolicyValues::default()
    };
    let target = PolicyValues::default();
    match plan_rollback(&target, &current, &current) {
        RollbackPlan::Tighten { overlay, fields } => {
            assert_eq!(fields, vec![PolicyField::PageEvalEnabled]);
            assert_eq!(overlay.page_eval_enabled, Some(false));
            // Folding the diff overlay over current lands exactly on target.
            assert_eq!(fold(&current, &overlay), target);
        }
        other => panic!("expected Tighten, got {other:?}"),
    }
}

#[test]
fn a_relaxing_rollback_takes_the_signed_lane_with_the_changed_fields_touched() {
    // The current baseline and effective differ on confirmGraceMs (a
    // restriction overlay holds it at 30000 under a 45000 baseline).
    // Target (past revision) relaxes pageEval and evalMask but leaves
    // confirmGraceMs at its current effective value, so the plan must
    // build the fresh baseline over the CURRENT baseline - never the
    // historical effective wholesale - with only the changed fields
    // touched.
    let baseline = PolicyValues {
        confirm_grace_ms: 45_000,
        ..PolicyValues::default()
    };
    // The overlay restricts confirmGraceMs to 30000, so effective differs
    // from baseline on a field the rollback does NOT change.
    let current = PolicyValues {
        confirm_grace_ms: 30_000,
        ..PolicyValues::default()
    };
    let target = PolicyValues {
        page_eval_enabled: true,
        confirm_grace_ms: 30_000, // unchanged vs current effective
        eval_mask: false,         // also relax a second field
        ..PolicyValues::default()
    };
    match plan_rollback(&target, &current, &baseline) {
        RollbackPlan::Relax {
            values,
            touched,
            fields,
        } => {
            // Changed fields carry the target value; untouched fields
            // carry the BASELINE value (decision 3), so the overlay entry
            // on confirmGraceMs survives the write instead of being
            // silently folded into the signed baseline.
            assert!(values.page_eval_enabled);
            assert!(!values.eval_mask);
            assert_eq!(values.confirm_grace_ms, 45_000);
            assert!(touched.contains(&PolicyField::PageEvalEnabled));
            assert!(touched.contains(&PolicyField::EvalMask));
            assert!(!touched.contains(&PolicyField::ConfirmGraceMs));
            assert_eq!(touched, fields);
        }
        other => panic!("expected Relax, got {other:?}"),
    }
}

#[test]
fn diff_overlay_treats_disabled_tools_as_a_set() {
    let a = PolicyValues {
        disabled_tools: vec!["x".into(), "y".into()],
        ..PolicyValues::default()
    };
    let b = PolicyValues {
        disabled_tools: vec!["y".into(), "x".into()],
        ..PolicyValues::default()
    };
    // Reordered but equal as sets: no diff.
    let (_, fields) = diff_overlay(&a, &b);
    assert!(fields.is_empty());
    // A genuinely different set diffs.
    let c = PolicyValues {
        disabled_tools: vec!["x".into()],
        ..PolicyValues::default()
    };
    let (_, fields) = diff_overlay(&a, &c);
    assert_eq!(fields, vec![PolicyField::DisabledTools]);
}

#[test]
fn find_history_effective_folds_the_target_and_reports_misses() {
    use super::super::{PolicyHistoryEntry, POLICY_HISTORY_VERSION};
    let doc = PolicyDoc {
        revision: 4,
        page_eval_enabled: true,
        ..PolicyDoc::default()
    };
    let history = PolicyHistory {
        version: POLICY_HISTORY_VERSION,
        entries: vec![PolicyHistoryEntry {
            baseline_b64: base64_encode(&serde_json::to_vec(&doc).unwrap()),
            sig_b64: None,
            key_id: None,
            overlay: Some(PolicyOverlay {
                page_eval_enabled: Some(false),
                ..PolicyOverlay::default()
            }),
            superseded_unix: 1,
        }],
    };
    // The target effective folds the entry's overlay over its baseline.
    let effective = find_history_effective(&history, 4).unwrap();
    assert!(!effective.page_eval_enabled);
    // A miss names the available revisions.
    let err = find_history_effective(&history, 9).unwrap_err();
    assert!(err.contains("available revisions: [4]"));
}

#[test]
fn find_history_effective_refuses_an_ambiguous_revision() {
    use super::super::{PolicyHistoryEntry, POLICY_HISTORY_VERSION};
    // Every restriction while a baseline is current pushes a history
    // entry at the UNCHANGED revision, so one revision can name several
    // distinct effective states. Rolling back must land exactly one.
    let doc = PolicyDoc {
        revision: 4,
        page_eval_enabled: true,
        ..PolicyDoc::default()
    };
    let baseline_b64 = base64_encode(&serde_json::to_vec(&doc).unwrap());
    let entry = |overlay| PolicyHistoryEntry {
        baseline_b64: baseline_b64.clone(),
        sig_b64: None,
        key_id: None,
        overlay,
        superseded_unix: 1,
    };
    let history = PolicyHistory {
        version: POLICY_HISTORY_VERSION,
        entries: vec![
            entry(None),
            entry(Some(PolicyOverlay {
                page_eval_enabled: Some(false),
                ..PolicyOverlay::default()
            })),
        ],
    };
    let err = find_history_effective(&history, 4).unwrap_err();
    assert!(err.contains("ambiguous"), "got: {err}");
    // Identical duplicates are NOT ambiguous: same effective state.
    let history = PolicyHistory {
        version: POLICY_HISTORY_VERSION,
        entries: vec![entry(None), entry(None)],
    };
    assert!(
        find_history_effective(&history, 4)
            .unwrap()
            .page_eval_enabled
    );
}
