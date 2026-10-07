use super::*;
use crate::enclave::base64_encode;
use crate::policy::PolicyDoc;
use crate::test_support::scratch_runtime_dir;

/// The grant lane's order: the terminal witness, then the host key. With the witness refused (a piped stdin)
/// a keyless machine is refused as not interactive, never as keyless, so a background invocation cannot make
/// the credential-store lookup raise its unlock dialog for a grant that is refused anyway.
#[test]
fn a_piped_stdin_is_refused_before_the_host_key_is_looked_up() {
    let _dir = scratch_runtime_dir();
    let overlay = PolicyOverlay {
        page_eval_enabled: Some(true),
        ..PolicyOverlay::default()
    };
    let err = do_set(overlay, Err(crate::presence::PresenceError::NotInteractive)).unwrap_err();
    assert!(
        err.contains("stdin is not a terminal"),
        "refused by the witness, not the key: {err}"
    );
    assert!(PolicyStore::load().unwrap().is_none());
    let trail = std::fs::read_to_string(crate::audit::audit_path().unwrap()).unwrap_or_default();
    assert!(
        trail.contains("\"outcome\":\"refused\"") && trail.contains("touched=pageEvalEnabled"),
        "the refused grant leaves its record: {trail}"
    );
}

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
fn history_report_maps_entries_and_tolerates_a_damaged_one() {
    use super::super::PolicyHistoryEntry;
    let good = PolicyDoc {
        revision: 5,
        page_eval_enabled: true,
        ..PolicyDoc::default()
    };
    let good_b64 = base64_encode(&serde_json::to_vec(&good).unwrap());
    let history = PolicyHistory {
        entries: vec![
            PolicyHistoryEntry {
                baseline_b64: good_b64.clone(),
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
            // A readable baseline under an overlay the policy's own bounds refuse: the ring's parse admits
            // it, so the report must, or the extension's reader would refuse the whole frame over one row.
            PolicyHistoryEntry {
                baseline_b64: good_b64,
                sig_b64: None,
                key_id: None,
                overlay: Some(PolicyOverlay {
                    disabled_tools: Some(vec![String::new()]),
                    ..PolicyOverlay::default()
                }),
                superseded_unix: 333,
            },
        ],
    };
    let r = history_report(&history);
    assert_eq!(r.entries.len(), 3);
    assert_eq!(
        (r.entries[2].revision, r.entries[2].effective.as_ref()),
        (None, None)
    );
    assert_eq!(r.entries[0].revision, Some(5));
    assert!(r.entries[0].signed);
    assert!(r.entries[0].overlay_active);
    // The effective policy is the baseline under its overlay: pageEval restricted back off.
    assert_eq!(
        r.entries[0].effective,
        Some(PolicyValues {
            page_eval_enabled: false,
            ..good.values()
        })
    );
    // A damaged entry keeps its slot with a null revision and no effective policy.
    assert_eq!(r.entries[1].revision, None);
    assert_eq!(r.entries[1].effective, None);
    assert!(!r.entries[1].signed);
    assert_eq!(r.entries[1].superseded_unix, 222);
    // The prose names each row's record and the policy it held, so two records at one revision read apart.
    let text = render_history(&r);
    assert!(
        text.contains(&format!("entry={} effective=cdpMode=off,", r.entries[0].id)),
        "{text}"
    );
    assert!(text.contains("pageEvalEnabled=off,"), "{text}");
    assert!(
        text.contains("revision ?      unsigned no-overlay superseded_unix=222 entry="),
        "{text}"
    );
    assert!(text.contains(" effective=?\n"), "{text}");
}
