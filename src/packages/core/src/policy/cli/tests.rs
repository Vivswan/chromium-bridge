use super::*;
use crate::enclave::base64_encode;
use crate::policy::Ms;

/// A `PolicyStore` seeded in memory (no disk): a baseline document over
/// `values` at `revision`, optionally signed, with `overlay`.
fn store(
    revision: u64,
    values: &PolicyValues,
    signed: bool,
    overlay: Option<PolicyOverlay>,
) -> PolicyStore {
    let doc = PolicyDoc::from_values(values, revision, Vec::new());
    let bytes = serde_json::to_vec(&doc).unwrap();
    PolicyStore {
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
    // deny_unknown_fields is the consumer's fail-closed guard.
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
    // as the status report (a consumer v-gates then strict-parses).
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
    use super::super::PolicyHistoryEntry;
    let good = PolicyDoc {
        revision: 5,
        ..PolicyDoc::default()
    };
    let history = PolicyHistory {
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
    let plan = plan_rollback(&target, &current, &current);
    let RollbackPlan::Tighten { overlay, fields } = plan else {
        panic!("expected Tighten, got {plan:?}");
    };
    assert_eq!(fields, vec![PolicyField::PageEvalEnabled]);
    assert_eq!(overlay.page_eval_enabled, Some(false));
    // Folding the diff overlay over current lands exactly on target.
    assert_eq!(fold(&current, &overlay), target);
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
        confirm_grace_ms: Ms::from(45_000u32),
        ..PolicyValues::default()
    };
    // The overlay restricts confirmGraceMs to 30000, so effective differs
    // from baseline on a field the rollback does NOT change.
    let current = PolicyValues {
        confirm_grace_ms: Ms::from(30_000u32),
        ..PolicyValues::default()
    };
    let target = PolicyValues {
        page_eval_enabled: true,
        confirm_grace_ms: Ms::from(30_000u32), // unchanged vs current effective
        eval_mask: false,                      // also relax a second field
        ..PolicyValues::default()
    };
    let plan = plan_rollback(&target, &current, &baseline);
    let RollbackPlan::Relax {
        values,
        touched,
        fields,
    } = plan
    else {
        panic!("expected Relax, got {plan:?}");
    };
    // Changed fields carry the target value; untouched fields
    // carry the BASELINE value, so the overlay entry
    // on confirmGraceMs survives the write instead of being
    // silently folded into the signed baseline.
    assert!(values.page_eval_enabled);
    assert!(!values.eval_mask);
    assert_eq!(values.confirm_grace_ms, Ms::from(45_000u32));
    assert!(touched.contains(&PolicyField::PageEvalEnabled));
    assert!(touched.contains(&PolicyField::EvalMask));
    assert!(!touched.contains(&PolicyField::ConfirmGraceMs));
    assert_eq!(touched, fields);
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
    use super::super::PolicyHistoryEntry;
    let doc = PolicyDoc {
        revision: 4,
        page_eval_enabled: true,
        ..PolicyDoc::default()
    };
    let history = PolicyHistory {
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
    use super::super::PolicyHistoryEntry;
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
        entries: vec![entry(None), entry(None)],
    };
    assert!(
        find_history_effective(&history, 4)
            .unwrap()
            .page_eval_enabled
    );
}
