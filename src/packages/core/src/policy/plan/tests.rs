//! The pure planning both grant surfaces share: the rollback lattice decision, the set diff, and the history
//! fold. The disk-backed halves (`plan_grant`, `rollback_inputs`) are driven end to end by the CLI and
//! native-host suites.

use super::*;
use crate::enclave::base64_encode;
use crate::policy::Ms;

#[test]
fn a_tightening_rollback_uses_the_free_lane() {
    // current has pageEval ON; target (a past revision) has it OFF: rolling
    // back only tightens, so it rides the free restrict lane. Rolling back onto the current state is no plan.
    let current = PolicyValues {
        page_eval_enabled: true,
        ..PolicyValues::default()
    };
    let target = PolicyValues::default();
    assert_eq!(
        plan_rollback(&current, &current, &current),
        RollbackPlan::NoChange
    );
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
    let RollbackPlan::Relax(Grant { values, touched }) = plan else {
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
    // The recovery points at the flag that resolves the ambiguity, not at rebuilding the state by hand.
    assert!(
        err.contains("policy history") && err.contains("--entry <id>"),
        "got: {err}"
    );
    // Identical duplicates are NOT ambiguous: same effective state.
    let history = PolicyHistory {
        entries: vec![entry(None), entry(None)],
    };
    assert!(
        find_history_effective(&history, 4)
            .unwrap()
            .page_eval_enabled
    );
    // Nor are two records whose tool lists differ only in order: the list is a set everywhere the policy is
    // read, and the same judgment decides here.
    let tools = |names: &[&str]| {
        entry(Some(PolicyOverlay {
            disabled_tools: Some(names.iter().map(|n| n.to_string()).collect()),
            ..PolicyOverlay::default()
        }))
    };
    let history = PolicyHistory {
        entries: vec![tools(&["a", "b"]), tools(&["b", "a"])],
    };
    let effective = find_history_effective(&history, 4).unwrap();
    assert_eq!(effective.disabled_tools, vec!["a", "b"]);
}

/// A rollback names a record by its content identity, not its position: two records that share a revision and
/// a second but differ by their overlay have distinct ids, and the id still names its record after the ring
/// evicted the one before it, where a position would have named a neighbour.
#[test]
fn a_history_entry_is_named_by_its_content_and_survives_an_eviction() {
    use super::super::PolicyHistoryEntry;
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
        superseded_unix: 7,
    };
    let unrestricted = entry(None);
    let restricted = entry(Some(PolicyOverlay {
        page_eval_enabled: Some(false),
        ..PolicyOverlay::default()
    }));
    assert_ne!(unrestricted.id(), restricted.id());
    let mut history = PolicyHistory {
        entries: vec![unrestricted, restricted],
    };
    let named = HistoryEntryRef {
        id: history.entries[1].id(),
    };
    assert!(
        !find_history_entry(&history, 4, &named)
            .unwrap()
            .page_eval_enabled
    );
    history.entries.remove(0);
    assert!(
        !find_history_entry(&history, 4, &named)
            .unwrap()
            .page_eval_enabled
    );
    let gone = HistoryEntryRef { id: "0".repeat(64) };
    assert!(find_history_entry(&history, 4, &gone)
        .unwrap_err()
        .contains("no longer holds that record"));
}
