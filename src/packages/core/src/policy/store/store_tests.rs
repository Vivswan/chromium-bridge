use std::fs;

use super::*;
use crate::audit::Surface;
use crate::presence::policy_test_hook::{self, Mock};

use crate::test_support::scratch_runtime_dir;

/// A signed-looking store seeded directly on disk: a baseline document
/// with `revision` over `values`, plus `overlay`. Returns the store as
/// written.
fn seed_store(revision: u64, values: &PolicyValues, overlay: Option<PolicyOverlay>) -> PolicyStore {
    let doc = PolicyDoc::from_values(values, revision, vec![]);
    let bytes = serde_json::to_vec(&doc).unwrap();
    let store = PolicyStore {
        version: POLICY_STORE_VERSION,
        baseline_b64: base64_encode(&bytes),
        sig_b64: Some(base64_encode(b"seed-sig")),
        key_id: Some("seed-kid".into()),
        overlay,
    };
    ipc::with_runtime_lock(|lock| store.write(lock)).unwrap();
    store
}

fn signed_mock() -> Mock {
    Mock::Return(PolicySignOutcome::Signed {
        sig: [7; 64],
        key_id: "kid-1".into(),
        pubkey_b64: "pk".into(),
    })
}

/// The audit trail written into the scratch runtime dir, as one string.
fn audit_text() -> String {
    fs::read_to_string(crate::audit::audit_path()).unwrap_or_default()
}

#[test]
fn store_round_trips_the_exact_baseline_bytes() {
    let _dir = scratch_runtime_dir("policy-round-trip");
    let doc = PolicyDoc {
        revision: 7,
        touched: vec![PolicyField::PageEvalEnabled],
        page_eval_enabled: true,
        ..PolicyDoc::default()
    };
    let bytes = serde_json::to_vec(&doc).unwrap();
    let store = PolicyStore {
        version: POLICY_STORE_VERSION,
        baseline_b64: base64_encode(&bytes),
        sig_b64: Some("c2ln".into()),
        key_id: Some("kid".into()),
        overlay: Some(PolicyOverlay {
            confirm_grace_ms: Some(0),
            ..PolicyOverlay::default()
        }),
    };
    ipc::with_runtime_lock(|lock| store.write(lock)).unwrap();
    let back = PolicyStore::load().unwrap().unwrap();
    assert_eq!(back, store);
    // The signed artifact survives byte-for-byte: decode returns the
    // exact bytes, and the strict parse reads the same document back.
    assert_eq!(base64_decode(&back.baseline_b64).unwrap(), bytes);
    assert_eq!(back.baseline_doc().unwrap(), doc);
}

#[test]
fn a_flipped_baseline_byte_still_parses_but_changes_the_doc() {
    let _dir = scratch_runtime_dir("policy-tamper-flip");
    let store = seed_store(1, &PolicyValues::default(), None);
    let mut bytes = base64_decode(&store.baseline_b64).unwrap();
    // Flip the revision digit: still valid JSON, different document.
    let pos = bytes
        .windows(12)
        .position(|w| w == b"\"revision\":1")
        .unwrap()
        + 11;
    bytes[pos] = b'2';
    let tampered = PolicyStore {
        baseline_b64: base64_encode(&bytes),
        ..store
    };
    ipc::with_runtime_lock(|lock| tampered.write(lock)).unwrap();
    // The parse succeeding is fine, by design: this file is storage,
    // not authority. The signature stored beside the bytes no longer
    // covers them, and signature verification is the EXTENSION's job
    // against its own pinned key (ADR-0032 decision 5) - the host store
    // cannot self-certify, so the host does not pretend to.
    let doc = PolicyStore::load()
        .unwrap()
        .unwrap()
        .baseline_doc()
        .unwrap();
    assert_eq!(doc.revision, 2);
}

#[test]
fn a_flipped_byte_that_breaks_json_fails_baseline_doc_not_load() {
    let _dir = scratch_runtime_dir("policy-tamper-break");
    let store = seed_store(1, &PolicyValues::default(), None);
    let mut bytes = base64_decode(&store.baseline_b64).unwrap();
    bytes[0] = b'X';
    let tampered = PolicyStore {
        baseline_b64: base64_encode(&bytes),
        ..store
    };
    ipc::with_runtime_lock(|lock| tampered.write(lock)).unwrap();
    // The load/baseline_doc split: the store envelope is intact, so
    // load() passes; the byte authority refuses the damaged document.
    let back = PolicyStore::load().unwrap().unwrap();
    assert!(back.baseline_doc().is_err());
    assert!(back.effective().is_err());
}

#[test]
fn a_non_base64_baseline_fails_baseline_doc_not_load() {
    let _dir = scratch_runtime_dir("policy-tamper-b64");
    let store = PolicyStore {
        version: POLICY_STORE_VERSION,
        baseline_b64: "not base64!".into(),
        sig_b64: None,
        key_id: None,
        overlay: None,
    };
    ipc::with_runtime_lock(|lock| store.write(lock)).unwrap();
    let back = PolicyStore::load().unwrap().unwrap();
    assert!(back.baseline_doc().is_err());
}

#[test]
fn load_is_fail_closed_on_shape_size_and_version() {
    let _dir = scratch_runtime_dir("policy-load-fail-closed");
    // Absent -> Ok(None): the legitimate no-policy-yet state.
    assert!(PolicyStore::load().unwrap().is_none());
    // An unknown field is refused, never skimmed over.
    fs::write(
        PolicyStore::path(),
        br#"{"version":1,"baseline_b64":"e30=","surprise":true}"#,
    )
    .unwrap();
    assert!(PolicyStore::load().is_err());
    // A wrong version is refused.
    fs::write(
        PolicyStore::path(),
        br#"{"version":99,"baseline_b64":"e30="}"#,
    )
    .unwrap();
    assert!(PolicyStore::load().is_err());
    // An oversized file is refused without being slurped.
    fs::write(PolicyStore::path(), vec![b' '; POLICY_MAX_BYTES + 1]).unwrap();
    assert!(PolicyStore::load().is_err());
}

#[test]
fn the_first_signed_baseline_consumes_the_pending_import() {
    // ADR-0032 decision 8: signing revision 1 is the cutover the pending
    // legacy import fed, so the receipt is consumed in the same write -
    // and consuming writes the durable tombstone (P4H-1), so the window
    // is closed for good, not returned to absent.
    let _dir = scratch_runtime_dir("policy-consume-pending-import");
    let _reset = policy_test_hook::ResetOnDrop;
    crate::pending_import::record_if_absent(serde_json::json!({ "pageEvalEnabled": true }))
        .unwrap();
    policy_test_hook::set(signed_mock());
    set_signed(
        PolicyValues {
            page_eval_enabled: true,
            ..PolicyValues::default()
        },
        vec![PolicyField::PageEvalEnabled],
        Surface::Core,
        PolicyGrantFloor::SignatureOnly,
    )
    .unwrap();
    assert_eq!(
        crate::pending_import::load().unwrap(),
        crate::pending_import::StoreState::Consumed,
        "the first baseline must consume the pending import into the tombstone"
    );

    // Post-consume, a re-sent (possibly forged) bag is refused - the
    // tombstone, not baseline presence, is what keeps the window closed.
    assert_eq!(
        crate::pending_import::record_if_absent(serde_json::json!({ "later": true })).unwrap(),
        crate::pending_import::RecordOutcome::AlreadyConsumed
    );

    // A SUBSEQUENT baseline write (revision > 1) leaves the tombstone
    // standing: only revision 1 consumes, and nothing un-consumes.
    policy_test_hook::set(signed_mock());
    set_signed(
        PolicyValues::default(),
        vec![PolicyField::PageEvalEnabled],
        Surface::Core,
        PolicyGrantFloor::SignatureOnly,
    )
    .unwrap();
    assert_eq!(
        crate::pending_import::load().unwrap(),
        crate::pending_import::StoreState::Consumed
    );
}

#[test]
fn clearing_the_baseline_leaves_the_pending_import_intact() {
    // ADR-0032 D-P4-5: disposal (revoke / pair --reset / enclave_revoke)
    // clears the signed baseline through clear_baseline_locked, but the
    // pending import is user preference data, not a key artifact, so it
    // must survive - the policy-history precedent.
    let _dir = scratch_runtime_dir("policy-disposal-keeps-pending-import");
    seed_store(1, &PolicyValues::default(), None);
    crate::pending_import::record_if_absent(serde_json::json!({ "keepme": true })).unwrap();
    ipc::with_runtime_lock(clear_baseline_locked).unwrap();
    assert!(
        PolicyStore::load().unwrap().is_none(),
        "the baseline is cleared on disposal"
    );
    assert_eq!(
        crate::pending_import::load().unwrap(),
        crate::pending_import::StoreState::Pending {
            bag: serde_json::json!({ "keepme": true })
        },
        "the pending import survives disposal untouched"
    );
}

#[test]
fn a_crash_between_window_close_and_baseline_preserves_the_bag() {
    // P4G-4: the old single-phase ordering lost the bag if the process
    // died after the tombstone but before the baseline. Simulate exactly
    // that interleave - the window-close landed (Consuming), the baseline
    // write never did - and assert the three recovery properties: the
    // window is closed to plants, the bag is still readable, and the
    // user's re-tap (a fresh first-baseline write) resumes and finalizes.
    let _dir = scratch_runtime_dir("policy-consuming-crash-preserves-bag");
    let _reset = policy_test_hook::ResetOnDrop;
    let bag = serde_json::json!({ "pageEvalEnabled": true });
    crate::pending_import::record_if_absent(bag.clone()).unwrap();
    // Phase 1 alone = the crash point: window closed, baseline absent.
    ipc::with_runtime_lock(crate::pending_import::begin_consume_locked).unwrap();
    assert!(PolicyStore::load().unwrap().is_none());
    assert_eq!(
        crate::pending_import::load().unwrap(),
        crate::pending_import::StoreState::Consuming { bag: bag.clone() },
        "the bag survives the crash in the mid-consume record"
    );
    // Window closed for new bags, exactly like the tombstone.
    assert_eq!(
        crate::pending_import::record_if_absent(serde_json::json!({ "forged": true })).unwrap(),
        crate::pending_import::RecordOutcome::AlreadyConsumed
    );
    // The read surface still reports the retained bag for the app.
    assert_eq!(
        crate::pending_import::gather_pending_import(),
        crate::pending_import::PendingImportReport::Consuming {
            v: 1,
            bag: bag.clone()
        }
    );
    // The re-tap: a fresh first-baseline write consumes and finalizes.
    policy_test_hook::set(signed_mock());
    set_signed(
        PolicyValues {
            page_eval_enabled: true,
            ..PolicyValues::default()
        },
        vec![PolicyField::PageEvalEnabled],
        Surface::Core,
        PolicyGrantFloor::SignatureOnly,
    )
    .unwrap();
    assert!(PolicyStore::load().unwrap().is_some());
    assert_eq!(
        crate::pending_import::load().unwrap(),
        crate::pending_import::StoreState::Consumed,
        "the re-tap finalizes the mid-consume record to the bagless tombstone"
    );
}

#[test]
fn a_stranded_consuming_record_heals_once_its_baseline_landed() {
    // HYG-FIX-1: a Consuming record whose baseline landed but whose
    // finalize never ran (crash between the baseline write and the
    // finalize, or a swallowed finalize failure) has no later seam on the
    // write path (revision-2+ writes never revisit the store). The
    // reconcile - run at native-host startup and by the pending-import
    // read command - finalizes it: the baseline is fsynced (the durable
    // proof), the bag is disposed, and the window stays closed.
    let _dir = scratch_runtime_dir("policy-reconcile-heals-stranded-consuming");
    crate::pending_import::record_if_absent(serde_json::json!({ "a": 1 })).unwrap();
    ipc::with_runtime_lock(crate::pending_import::begin_consume_locked).unwrap();
    seed_store(1, &PolicyValues::default(), None); // the baseline "landed"
    assert!(
        crate::pending_import::reconcile_consuming().unwrap(),
        "a stranded Consuming record with a landed baseline must heal"
    );
    assert_eq!(
        crate::pending_import::load().unwrap(),
        crate::pending_import::StoreState::Consumed,
        "healed to the bagless tombstone"
    );
    // Idempotent: a second pass has nothing to do.
    assert!(!crate::pending_import::reconcile_consuming().unwrap());
    // And the window stays closed to plants, as ever.
    assert_eq!(
        crate::pending_import::record_if_absent(serde_json::json!({ "forged": true })).unwrap(),
        crate::pending_import::RecordOutcome::AlreadyConsumed
    );
}

#[test]
fn reconcile_refuses_to_dispose_the_bag_over_an_unusable_baseline() {
    // HYG-FIX-9: PolicyStore::load() validates only the file ENVELOPE;
    // the baseline bytes decode/parse/validate in baseline_doc(). A
    // valid envelope around an unusable baseline enforces nothing, so
    // the reconcile must NOT treat it as "the baseline landed" and
    // finalize away the user's only recoverable copy of the import -
    // the fail-closed Consuming record stays untouched, bag preserved.
    let _dir = scratch_runtime_dir("policy-reconcile-unusable-baseline");
    let bag = serde_json::json!({ "keep": true });
    crate::pending_import::record_if_absent(bag.clone()).unwrap();
    ipc::with_runtime_lock(crate::pending_import::begin_consume_locked).unwrap();
    // A store whose envelope loads but whose baseline cannot decode.
    let damaged = PolicyStore {
        version: POLICY_STORE_VERSION,
        baseline_b64: "not base64!".into(),
        sig_b64: None,
        key_id: None,
        overlay: None,
    };
    fs::write(PolicyStore::path(), serde_json::to_vec(&damaged).unwrap()).unwrap();
    assert!(PolicyStore::load().unwrap().is_some(), "the envelope loads");
    assert!(
        PolicyStore::load()
            .unwrap()
            .unwrap()
            .baseline_doc()
            .is_err(),
        "sanity: the baseline is unusable"
    );
    assert!(
        !crate::pending_import::reconcile_consuming().unwrap(),
        "no heal over an unusable baseline"
    );
    assert_eq!(
        crate::pending_import::load().unwrap(),
        crate::pending_import::StoreState::Consuming { bag },
        "the mid-consume record and its bag are preserved"
    );
}

#[test]
fn a_failed_tombstone_write_refuses_the_first_baseline() {
    // P4F-7: closing the import window is a PREREQUISITE of the first
    // signed baseline, not best-effort cleanup after it. Inject the
    // failure through the store's own fail-closed path: an unreadable
    // pending-import file makes begin_consume_locked refuse, which must
    // refuse the whole signed write (retryable Io - the user re-taps once
    // the file is dealt with), and no baseline may land while the window
    // cannot be closed.
    let _dir = scratch_runtime_dir("policy-tombstone-failure-refuses-baseline");
    let _reset = policy_test_hook::ResetOnDrop;
    std::fs::write(crate::pending_import::path(), b"{ not json").unwrap();
    policy_test_hook::set(signed_mock());
    let denied = set_signed(
        PolicyValues::default(),
        vec![PolicyField::PageEvalEnabled],
        Surface::Core,
        PolicyGrantFloor::SignatureOnly,
    );
    assert!(
        matches!(denied, Err(PolicyWriteError::Io(_))),
        "a failed tombstone write must refuse the signed write, got {denied:?}"
    );
    assert!(
        PolicyStore::load().unwrap().is_none(),
        "no baseline may land while the import window cannot be closed"
    );
    // The unreadable receipt is untouched evidence, not overwritten.
    assert!(crate::pending_import::load().is_err());
}

#[test]
fn the_consumed_tombstone_survives_disposal_and_still_refuses_a_plant() {
    // P4H-1, the attack the tombstone exists for: consume happens
    // (revision 1), then disposal clears the BASELINE - if consume had
    // deleted the file, the store would read absent again and a
    // compromised extension could plant a forged bag for the next
    // first-run import. The tombstone must outlive the baseline.
    let _dir = scratch_runtime_dir("policy-tombstone-survives-disposal");
    crate::pending_import::record_if_absent(serde_json::json!({ "real": true })).unwrap();
    seed_store(1, &PolicyValues::default(), None);
    ipc::with_runtime_lock(crate::pending_import::consume_locked).unwrap();
    ipc::with_runtime_lock(clear_baseline_locked).unwrap();
    assert!(
        PolicyStore::load().unwrap().is_none(),
        "the baseline is cleared on disposal"
    );
    assert_eq!(
        crate::pending_import::load().unwrap(),
        crate::pending_import::StoreState::Consumed,
        "the consumed tombstone survives disposal"
    );
    assert_eq!(
        crate::pending_import::record_if_absent(serde_json::json!({ "forged": true })).unwrap(),
        crate::pending_import::RecordOutcome::AlreadyConsumed,
        "a post-disposal plant is refused by the tombstone"
    );
}

#[test]
fn set_signed_writes_the_exact_signed_bytes_and_bumps_revisions() {
    let _dir = scratch_runtime_dir("policy-set-signed-happy");
    let _reset = policy_test_hook::ResetOnDrop;
    policy_test_hook::set(signed_mock());

    let values = PolicyValues {
        page_eval_enabled: true,
        ..PolicyValues::default()
    };
    let rung = set_signed(
        values.clone(),
        vec![PolicyField::PageEvalEnabled],
        Surface::Core,
        PolicyGrantFloor::SignatureOnly,
    )
    .unwrap();
    assert_eq!(rung, PresencePath::TouchId);

    let first = PolicyStore::load().unwrap().unwrap();
    let doc = first.baseline_doc().unwrap();
    assert_eq!(doc.revision, 1);
    assert_eq!(doc.touched, vec![PolicyField::PageEvalEnabled]);
    assert_eq!(doc.values(), values);
    assert_eq!(
        first.sig_b64.as_deref(),
        Some(base64_encode(&[7; 64]).as_str())
    );
    assert_eq!(first.key_id.as_deref(), Some("kid-1"));
    assert!(first.overlay.is_none());
    // No previous store existed, so nothing was pushed.
    assert!(load_history().unwrap().is_none());

    // The second write supersedes the first: revision 2, and the ring
    // holds the exact previous record.
    policy_test_hook::set(signed_mock());
    set_signed(
        PolicyValues::default(),
        vec![PolicyField::PageEvalEnabled],
        Surface::Core,
        PolicyGrantFloor::SignatureOnly,
    )
    .unwrap();
    let second = PolicyStore::load().unwrap().unwrap();
    assert_eq!(second.baseline_doc().unwrap().revision, 2);
    let history = load_history().unwrap().unwrap();
    assert_eq!(history.entries.len(), 1);
    let entry = &history.entries[0];
    assert_eq!(entry.baseline_b64, first.baseline_b64);
    assert_eq!(entry.sig_b64, first.sig_b64);
    assert_eq!(entry.key_id, first.key_id);
    assert_eq!(entry.overlay, first.overlay);
    assert!(entry.superseded_unix > 0);
    // The trail names the rung and the touched fields.
    let trail = audit_text();
    assert!(trail.contains("policy_write"), "{trail}");
    assert!(trail.contains("auth=touch_id"), "{trail}");
    assert!(trail.contains("touched=pageEvalEnabled"), "{trail}");
}

#[test]
fn set_signed_clears_touched_overlay_entries_and_keeps_the_rest() {
    let _dir = scratch_runtime_dir("policy-overlay-retention");
    let _reset = policy_test_hook::ResetOnDrop;
    let overlay = PolicyOverlay {
        confirm_grace_ms: Some(1_000),
        disabled_tools: Some(vec!["page_eval".into()]),
        ..PolicyOverlay::default()
    };
    seed_store(1, &PolicyValues::default(), Some(overlay));

    policy_test_hook::set(signed_mock());
    set_signed(
        PolicyValues {
            confirm_grace_ms: 1_000,
            ..PolicyValues::default()
        },
        vec![PolicyField::ConfirmGraceMs],
        Surface::Core,
        PolicyGrantFloor::SignatureOnly,
    )
    .unwrap();

    let store = PolicyStore::load().unwrap().unwrap();
    // The tapped edit superseded the overlay entry on its field; the
    // untouched entry survives as overlay.
    assert_eq!(
        store.overlay,
        Some(PolicyOverlay {
            disabled_tools: Some(vec!["page_eval".into()]),
            ..PolicyOverlay::default()
        })
    );
}

#[test]
fn folding_the_effective_values_leaves_effective_unchanged() {
    let _dir = scratch_runtime_dir("policy-overlay-fold");
    let _reset = policy_test_hook::ResetOnDrop;
    // A baseline with grants on, restricted by overlay.
    let baseline_values = PolicyValues {
        page_eval_enabled: true,
        ..PolicyValues::default()
    };
    let overlay = PolicyOverlay {
        page_eval_enabled: Some(false),
        confirm_grace_ms: Some(0),
        disabled_tools: Some(vec!["page_upload".into()]),
        ..PolicyOverlay::default()
    };
    let seeded = seed_store(3, &baseline_values, Some(overlay));
    let effective_before = seeded.effective().unwrap();

    // The explicit fold act (ADR-0032 decision 3): a new revision
    // carrying the folded fields' EFFECTIVE values with exactly those
    // fields touched.
    policy_test_hook::set(signed_mock());
    set_signed(
        effective_before.clone(),
        vec![
            PolicyField::PageEvalEnabled,
            PolicyField::ConfirmGraceMs,
            PolicyField::DisabledTools,
        ],
        Surface::Core,
        PolicyGrantFloor::SignatureOnly,
    )
    .unwrap();

    let store = PolicyStore::load().unwrap().unwrap();
    assert_eq!(store.effective().unwrap(), effective_before);
    assert_eq!(store.baseline_doc().unwrap().revision, 4);
    // Exactly the folded entries emptied - and they were the whole
    // overlay, so it normalizes away.
    assert!(store.overlay.is_none());
}

#[test]
fn set_signed_signs_exactly_the_bytes_it_stores() {
    let _dir = scratch_runtime_dir("policy-signed-bytes-identity");
    let _reset = policy_test_hook::ResetOnDrop;
    policy_test_hook::set(signed_mock());
    let values = PolicyValues {
        page_eval_enabled: true,
        ..PolicyValues::default()
    };
    let touched = vec![PolicyField::PageEvalEnabled];
    set_signed(
        values.clone(),
        touched.clone(),
        Surface::Core,
        PolicyGrantFloor::SignatureOnly,
    )
    .unwrap();
    // The bytes the signing primitive was called with are the bytes the
    // store persists, byte for byte: the signature can only ever cover
    // exactly what is stored.
    let signed = policy_test_hook::last_doc_bytes().unwrap();
    let store = PolicyStore::load().unwrap().unwrap();
    assert_eq!(base64_decode(&store.baseline_b64).unwrap(), signed);
    // And those bytes parse back to a document scoped by exactly the
    // touched set and values that were passed.
    let doc: PolicyDoc = serde_json::from_slice(&signed).unwrap();
    assert_eq!(doc.touched, touched);
    assert_eq!(doc.values(), values);
}

#[test]
fn an_empty_touched_set_refuses_before_any_prompt() {
    let _dir = scratch_runtime_dir("policy-empty-touched");
    let _reset = policy_test_hook::ResetOnDrop;
    // The mock panics if the signing primitive is reached: the refusal
    // must be promptless.
    policy_test_hook::set(Mock::PanicIfCalled);
    let err = set_signed(
        PolicyValues::default(),
        vec![],
        Surface::Core,
        PolicyGrantFloor::AppConfirm,
    )
    .unwrap_err();
    assert!(matches!(err, PolicyWriteError::Invalid(_)));
    assert!(PolicyStore::load().unwrap().is_none());
}

#[test]
fn revision_overflow_refuses_before_any_prompt() {
    let _dir = scratch_runtime_dir("policy-revision-overflow");
    let _reset = policy_test_hook::ResetOnDrop;
    seed_store(JS_SAFE_INT_MAX, &PolicyValues::default(), None);
    policy_test_hook::set(Mock::PanicIfCalled);
    let err = set_signed(
        PolicyValues::default(),
        vec![PolicyField::CdpMode],
        Surface::Core,
        PolicyGrantFloor::AppConfirm,
    )
    .unwrap_err();
    assert!(matches!(err, PolicyWriteError::RevisionOverflow));
}

#[test]
fn the_last_js_safe_revision_still_writes() {
    // The near-boundary through the full seam: MAX - 1 mints exactly
    // MAX, the last legal revision (the overflow test above pins that
    // MAX itself refuses).
    let _dir = scratch_runtime_dir("policy-revision-at-bound");
    let _reset = policy_test_hook::ResetOnDrop;
    seed_store(JS_SAFE_INT_MAX - 1, &PolicyValues::default(), None);
    policy_test_hook::set(signed_mock());
    set_signed(
        PolicyValues::default(),
        vec![PolicyField::CdpMode],
        Surface::Core,
        PolicyGrantFloor::SignatureOnly,
    )
    .unwrap();
    assert_eq!(
        PolicyStore::load()
            .unwrap()
            .unwrap()
            .baseline_doc()
            .unwrap()
            .revision,
        JS_SAFE_INT_MAX
    );
}

#[test]
fn the_revision_seam_covers_its_boundaries() {
    // Deterministic edges of next_revision (the proptest below sweeps
    // the range): no store mints 1, MAX - 1 mints MAX, MAX overflows.
    assert_eq!(next_revision(None).unwrap(), 1);
    assert_eq!(
        next_revision(Some(JS_SAFE_INT_MAX - 1)).unwrap(),
        JS_SAFE_INT_MAX
    );
    assert!(matches!(
        next_revision(Some(JS_SAFE_INT_MAX)),
        Err(PolicyWriteError::RevisionOverflow)
    ));
}

#[test]
fn a_refused_signature_never_falls_to_the_floor() {
    let _dir = scratch_runtime_dir("policy-refused-no-floor");
    let _reset = policy_test_hook::ResetOnDrop;
    let seeded = seed_store(1, &PolicyValues::default(), None);
    policy_test_hook::set(Mock::Return(PolicySignOutcome::Refused(
        "user cancelled".into(),
    )));
    // The APP floor is offered and must not be consulted: a refusal is
    // terminal (the no-downgrade rule), never an unsigned write.
    let err = set_signed(
        PolicyValues::default(),
        vec![PolicyField::CdpMode],
        Surface::Core,
        PolicyGrantFloor::AppConfirm,
    )
    .unwrap_err();
    assert!(matches!(err, PolicyWriteError::Refused(_)));
    assert_eq!(PolicyStore::load().unwrap().unwrap(), seeded);
    assert!(audit_text().contains("\"outcome\":\"refused\""));
}

#[test]
fn unavailable_hardware_refuses_a_signature_only_surface() {
    let _dir = scratch_runtime_dir("policy-signature-only");
    let _reset = policy_test_hook::ResetOnDrop;
    // The default mock is Unavailable: a keyless machine.
    let err = set_signed(
        PolicyValues::default(),
        vec![PolicyField::CdpMode],
        Surface::Cli,
        PolicyGrantFloor::SignatureOnly,
    )
    .unwrap_err();
    assert!(matches!(err, PolicyWriteError::NoSigningKey));
    assert!(PolicyStore::load().unwrap().is_none());
    assert!(audit_text().contains("no signing key"));
}

#[test]
fn unavailable_hardware_writes_unsigned_on_the_app_floor() {
    let _dir = scratch_runtime_dir("policy-app-floor");
    let _reset = policy_test_hook::ResetOnDrop;
    // Default Unavailable mock: the app's interactive floor stores the
    // SAME document bytes unsigned (ADR-0032 decision 3).
    let rung = set_signed(
        PolicyValues::default(),
        vec![PolicyField::ConfirmGraceMs],
        Surface::Core,
        PolicyGrantFloor::AppConfirm,
    )
    .unwrap();
    assert_eq!(rung, PresencePath::AppConfirm);
    let store = PolicyStore::load().unwrap().unwrap();
    assert!(store.sig_b64.is_none());
    assert!(store.key_id.is_none());
    assert_eq!(store.baseline_doc().unwrap().revision, 1);
    assert!(audit_text().contains("auth=app_confirm"));
}

#[test]
fn restrict_without_a_baseline_refuses() {
    let _dir = scratch_runtime_dir("policy-restrict-no-baseline");
    let err = restrict(
        PolicyOverlay {
            page_eval_enabled: Some(false),
            ..PolicyOverlay::default()
        },
        Surface::Cli,
    )
    .unwrap_err();
    assert!(matches!(err, PolicyWriteError::NoBaseline));
    // A promptless precondition stays unaudited (the pair_client
    // InvalidName precedent), unlike the direction refusal.
    assert_eq!(audit_text(), "");
}

#[test]
fn a_restricting_overlay_applies_and_pushes_history() {
    let _dir = scratch_runtime_dir("policy-restrict-applies");
    let seeded = seed_store(
        1,
        &PolicyValues {
            page_eval_enabled: true,
            ..PolicyValues::default()
        },
        None,
    );
    restrict(
        PolicyOverlay {
            page_eval_enabled: Some(false),
            ..PolicyOverlay::default()
        },
        Surface::Cli,
    )
    .unwrap();
    let store = PolicyStore::load().unwrap().unwrap();
    assert!(!store.effective().unwrap().page_eval_enabled);
    // The baseline itself is untouched; only the overlay moved.
    assert_eq!(store.baseline_b64, seeded.baseline_b64);
    let history = load_history().unwrap().unwrap();
    assert_eq!(history.entries.len(), 1);
    assert_eq!(history.entries[0].overlay, None);
    assert!(audit_text().contains("auth=none; restricted=pageEvalEnabled"));
}

#[test]
fn a_relaxing_overlay_is_refused_with_the_store_unchanged() {
    let _dir = scratch_runtime_dir("policy-restrict-relaxing");
    let seeded = seed_store(
        1,
        &PolicyValues {
            page_eval_enabled: true,
            ..PolicyValues::default()
        },
        Some(PolicyOverlay {
            page_eval_enabled: Some(false),
            ..PolicyOverlay::default()
        }),
    );
    // "Undo the restriction" equals the baseline value but RELAXES the
    // effective policy: the free lane refuses it (it is the signed
    // lane's business, ADR-0032 decision 3).
    let err = restrict(
        PolicyOverlay {
            page_eval_enabled: Some(true),
            ..PolicyOverlay::default()
        },
        Surface::Cli,
    )
    .unwrap_err();
    assert!(matches!(err, PolicyWriteError::NotARestriction));
    assert_eq!(PolicyStore::load().unwrap().unwrap(), seeded);
    assert!(load_history().unwrap().is_none());
    // The refusal is in the trail (log-after-decide), naming the
    // offending posture.
    let trail = audit_text();
    assert!(trail.contains("\"outcome\":\"refused\""), "{trail}");
    assert!(
        trail.contains(
            "auth=none; restricted=pageEvalEnabled; refused: relaxes the effective policy"
        ),
        "{trail}"
    );
}

#[test]
fn restrict_merges_entrywise_keeping_unnamed_entries() {
    let _dir = scratch_runtime_dir("policy-restrict-merge");
    seed_store(
        1,
        &PolicyValues {
            page_eval_enabled: true,
            ..PolicyValues::default()
        },
        Some(PolicyOverlay {
            page_eval_enabled: Some(false),
            ..PolicyOverlay::default()
        }),
    );
    restrict(
        PolicyOverlay {
            confirm_grace_ms: Some(0),
            ..PolicyOverlay::default()
        },
        Surface::Cli,
    )
    .unwrap();
    let store = PolicyStore::load().unwrap().unwrap();
    assert_eq!(
        store.overlay,
        Some(PolicyOverlay {
            page_eval_enabled: Some(false),
            confirm_grace_ms: Some(0),
            ..PolicyOverlay::default()
        })
    );
}

#[test]
fn history_evicts_oldest_entries_at_the_cap() {
    let entry = |tag: u64| PolicyHistoryEntry {
        baseline_b64: base64_encode(format!("baseline-{tag:04}").as_bytes()),
        sig_b64: None,
        key_id: None,
        overlay: None,
        superseded_unix: tag,
    };
    let mut history = PolicyHistory {
        version: POLICY_HISTORY_VERSION,
        entries: (0..20).map(entry).collect(),
    };
    // A cap that holds a handful of entries: the ring drops from the
    // FRONT (oldest) until it fits, keeping the newest.
    let bytes = history_bytes_capped(&mut history, 800).unwrap();
    assert!(bytes.len() <= 800);
    assert!(!history.entries.is_empty());
    assert!(history.entries.len() < 20);
    assert_eq!(history.entries.last().unwrap().superseded_unix, 19);
    assert_eq!(
        history.entries.first().unwrap().superseded_unix,
        20 - history.entries.len() as u64
    );
    // A cap below a single entry empties the ring but still serializes
    // the envelope.
    let mut tiny = PolicyHistory {
        version: POLICY_HISTORY_VERSION,
        entries: vec![entry(1)],
    };
    let bytes = history_bytes_capped(&mut tiny, 60).unwrap();
    assert!(tiny.entries.is_empty());
    assert!(serde_json::from_slice::<PolicyHistory>(&bytes).is_ok());
}

#[test]
fn a_corrupt_history_file_never_blocks_policy_writes() {
    let _dir = scratch_runtime_dir("policy-history-corrupt");
    let _reset = policy_test_hook::ResetOnDrop;
    seed_store(1, &PolicyValues::default(), None);
    fs::write(PolicyHistory::path(), b"garbage, not json").unwrap();
    // Reading it fails closed for the (future) rollback surface...
    assert!(load_history().is_err());
    // ...but the enforcement paths and both seams stay fully functional:
    // the writer logs, replaces the ring, and the policy writes land.
    assert!(PolicyStore::load().unwrap().is_some());
    policy_test_hook::set(signed_mock());
    set_signed(
        PolicyValues::default(),
        vec![PolicyField::CdpMode],
        Surface::Core,
        PolicyGrantFloor::SignatureOnly,
    )
    .unwrap();
    restrict(
        PolicyOverlay {
            confirm_grace_ms: Some(0),
            ..PolicyOverlay::default()
        },
        Surface::Cli,
    )
    .unwrap();
    // The fresh ring holds the records superseded after the corruption.
    assert_eq!(load_history().unwrap().unwrap().entries.len(), 2);
}

#[test]
fn a_moved_baseline_revision_conflicts_instead_of_overwriting() {
    let _dir = scratch_runtime_dir("policy-revision-guard");
    seed_store(2, &PolicyValues::default(), None);
    let doc = PolicyDoc::from_values(&PolicyValues::default(), 3, vec![PolicyField::CdpMode]);
    let bytes = serde_json::to_vec(&doc).unwrap();
    // The guard, staged directly at the locked write: a pre-prompt
    // observation that no longer matches the store refuses (the
    // concurrent write survives), a matching one lands.
    let observation = |revision| PrePromptObservation {
        store: Some(StoreObservation {
            revision,
            overlay: None,
        }),
        host_key_epoch: 0,
    };
    let stale = ipc::with_runtime_lock(|lock| {
        Ok(write_baseline_locked(
            lock,
            observation(1),
            &bytes,
            None,
            None,
            &[PolicyField::CdpMode],
        ))
    })
    .unwrap();
    assert!(matches!(stale, Err(PolicyWriteError::Conflict)));
    assert_eq!(
        PolicyStore::load()
            .unwrap()
            .unwrap()
            .baseline_doc()
            .unwrap()
            .revision,
        2
    );
    // An observation of "no store" while one exists is the same refusal.
    let stale_none = ipc::with_runtime_lock(|lock| {
        Ok(write_baseline_locked(
            lock,
            PrePromptObservation {
                store: None,
                host_key_epoch: 0,
            },
            &bytes,
            None,
            None,
            &[PolicyField::CdpMode],
        ))
    })
    .unwrap();
    assert!(matches!(stale_none, Err(PolicyWriteError::Conflict)));
    let fresh = ipc::with_runtime_lock(|lock| {
        Ok(write_baseline_locked(
            lock,
            observation(2),
            &bytes,
            None,
            None,
            &[PolicyField::CdpMode],
        ))
    })
    .unwrap();
    assert!(fresh.is_ok());
    assert_eq!(
        PolicyStore::load()
            .unwrap()
            .unwrap()
            .baseline_doc()
            .unwrap()
            .revision,
        3
    );
}

#[test]
fn an_overlay_moved_mid_prompt_conflicts_instead_of_clobbering() {
    let _dir = scratch_runtime_dir("policy-overlay-guard");
    seed_store(
        2,
        &PolicyValues {
            page_eval_enabled: true,
            ..PolicyValues::default()
        },
        None,
    );
    // The observation a prompt would cover: revision 2, no overlay.
    let observed = PrePromptObservation {
        store: Some(StoreObservation {
            revision: 2,
            overlay: None,
        }),
        host_key_epoch: 0,
    };
    // A restrict lands mid-prompt (staged through the internal fn, like
    // the revision test above): same revision, moved overlay.
    let restriction = PolicyOverlay {
        page_eval_enabled: Some(false),
        ..PolicyOverlay::default()
    };
    ipc::with_runtime_lock(|lock| Ok(restrict_locked(lock, restriction.clone())))
        .unwrap()
        .unwrap();
    let doc = PolicyDoc::from_values(&PolicyValues::default(), 3, vec![PolicyField::CdpMode]);
    let bytes = serde_json::to_vec(&doc).unwrap();
    let stale = ipc::with_runtime_lock(|lock| {
        Ok(write_baseline_locked(
            lock,
            observed,
            &bytes,
            None,
            None,
            &[PolicyField::CdpMode],
        ))
    })
    .unwrap();
    assert!(matches!(stale, Err(PolicyWriteError::Conflict)));
    // The concurrent restriction survives, un-clobbered.
    let store = PolicyStore::load().unwrap().unwrap();
    assert_eq!(store.baseline_doc().unwrap().revision, 2);
    assert_eq!(store.overlay, Some(restriction.clone()));
    // An observation carrying the moved overlay lands.
    let fresh = ipc::with_runtime_lock(|lock| {
        Ok(write_baseline_locked(
            lock,
            PrePromptObservation {
                store: Some(StoreObservation {
                    revision: 2,
                    overlay: Some(restriction),
                }),
                host_key_epoch: 0,
            },
            &bytes,
            None,
            None,
            &[PolicyField::CdpMode],
        ))
    })
    .unwrap();
    assert!(fresh.is_ok());
}

#[test]
fn a_disposal_during_the_prompt_conflicts_even_with_no_store_on_both_sides() {
    let _dir = scratch_runtime_dir("policy-dispose-guard");
    // A first write's pre-prompt observation: no store, and the host-key
    // epoch as it stood before the tap.
    let doc = PolicyDoc::from_values(&PolicyValues::default(), 1, vec![PolicyField::CdpMode]);
    let bytes = serde_json::to_vec(&doc).unwrap();
    let observed_epoch = crate::revocation::Revocation::current()
        .unwrap()
        .host_key_epoch;
    // The disposal seam runs to completion mid-prompt: key deleted,
    // baseline cleared (a no-op here, no store exists), host-key epoch
    // bumped inside its critical section.
    ipc::with_runtime_lock(|lock| {
        crate::revocation::bump_locked(lock, crate::revocation::Scope::HostKey)
    })
    .unwrap();
    // The store guard alone cannot see it (no store observed, no store
    // current); the epoch guard refuses, so a signature minted by the
    // just-deleted key never lands as a baseline.
    let stale = ipc::with_runtime_lock(|lock| {
        Ok(write_baseline_locked(
            lock,
            PrePromptObservation {
                store: None,
                host_key_epoch: observed_epoch,
            },
            &bytes,
            Some("c2ln".into()),
            Some("key-id".into()),
            &[PolicyField::CdpMode],
        ))
    })
    .unwrap();
    assert!(matches!(stale, Err(PolicyWriteError::Conflict)));
    assert!(PolicyStore::load().unwrap().is_none());
}

#[test]
fn a_tampered_overlay_that_relaxes_the_baseline_refuses_every_read() {
    let _dir = scratch_runtime_dir("policy-overlay-tamper");
    // No legitimate write produces this state (restrict only tightens,
    // set_signed carries baseline values on untouched fields), so a
    // schema-valid overlay flipping a grant ON over a denying baseline
    // is a hand-edited policy.json - and it reads as damage, never as
    // the relaxed values.
    seed_store(
        3,
        &PolicyValues::default(),
        Some(PolicyOverlay {
            page_eval_enabled: Some(true),
            ..PolicyOverlay::default()
        }),
    );
    let store = PolicyStore::load().unwrap().unwrap();
    let err = store.effective().unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("relaxes the signed baseline"));
    // The baseline itself still parses: the refusal is the direction
    // check, not collateral corruption.
    assert_eq!(store.baseline_doc().unwrap().revision, 3);
}

#[test]
fn clearing_the_baseline_bumps_the_policy_epoch_once() {
    let _dir = scratch_runtime_dir("policy-clear-epoch");
    seed_store(1, &PolicyValues::default(), None);
    let before = crate::revocation::Revocation::current()
        .unwrap()
        .policy_epoch;
    ipc::with_runtime_lock(clear_baseline_locked).unwrap();
    assert!(PolicyStore::load().unwrap().is_none());
    let after = crate::revocation::Revocation::current()
        .unwrap()
        .policy_epoch;
    assert!(
        after > before,
        "a connected host only pushes the cleared state if the epoch moved"
    );
    // Clearing an already-absent store is a no-op: no epoch churn.
    ipc::with_runtime_lock(clear_baseline_locked).unwrap();
    let again = crate::revocation::Revocation::current()
        .unwrap()
        .policy_epoch;
    assert_eq!(again, after);
}

#[test]
fn a_relaxation_outside_the_touched_set_refuses_before_any_prompt() {
    let _dir = scratch_runtime_dir("policy-touched-coverage");
    let _reset = policy_test_hook::ResetOnDrop;
    seed_store(1, &PolicyValues::default(), None);
    // page_eval_enabled: true relaxes the effective anchor, but touched
    // names only cdpMode: promptless refusal (the mock panics if the
    // signing primitive is reached).
    policy_test_hook::set(Mock::PanicIfCalled);
    let relaxing = PolicyValues {
        page_eval_enabled: true,
        ..PolicyValues::default()
    };
    let err = set_signed(
        relaxing.clone(),
        vec![PolicyField::CdpMode],
        Surface::Core,
        PolicyGrantFloor::AppConfirm,
    )
    .unwrap_err();
    assert!(matches!(err, PolicyWriteError::Invalid(_)));
    // With no store at all the anchor is the deny baseline: an
    // undeclared first-write grant refuses the same way.
    fs::remove_file(PolicyStore::path()).unwrap();
    let err = set_signed(
        relaxing,
        vec![PolicyField::CdpMode],
        Surface::Core,
        PolicyGrantFloor::AppConfirm,
    )
    .unwrap_err();
    assert!(matches!(err, PolicyWriteError::Invalid(_)));
    assert!(PolicyStore::load().unwrap().is_none());
}

#[test]
fn a_touched_superset_of_the_relaxations_passes() {
    let _dir = scratch_runtime_dir("policy-touched-superset");
    let _reset = policy_test_hook::ResetOnDrop;
    seed_store(1, &PolicyValues::default(), None);
    policy_test_hook::set(signed_mock());
    set_signed(
        PolicyValues {
            page_eval_enabled: true,
            ..PolicyValues::default()
        },
        vec![PolicyField::PageEvalEnabled, PolicyField::CdpMode],
        Surface::Core,
        PolicyGrantFloor::SignatureOnly,
    )
    .unwrap();
    assert!(
        PolicyStore::load()
            .unwrap()
            .unwrap()
            .effective()
            .unwrap()
            .page_eval_enabled
    );
}

#[test]
fn a_restriction_lands_when_named_and_refuses_as_untouched_drift() {
    let _dir = scratch_runtime_dir("policy-touched-restriction");
    let _reset = policy_test_hook::ResetOnDrop;
    seed_store(
        1,
        &PolicyValues {
            page_eval_enabled: true,
            ..PolicyValues::default()
        },
        None,
    );
    // Turning page_eval OFF is a restriction, but the signed document
    // carries baseline values on fields it does not touch (decision 3):
    // changing it under an unrelated touched field is an unnamed edit
    // and refuses promptless, in EITHER direction.
    policy_test_hook::set(Mock::PanicIfCalled);
    let drift = set_signed(
        PolicyValues::default(),
        vec![PolicyField::ConfirmGraceMs],
        Surface::Core,
        PolicyGrantFloor::SignatureOnly,
    );
    assert!(matches!(drift, Err(PolicyWriteError::Invalid(_))));
    // Named in touched, the same restriction lands (the coverage check
    // binds relaxations only; restrictions just need naming).
    policy_test_hook::set(signed_mock());
    set_signed(
        PolicyValues::default(),
        vec![PolicyField::PageEvalEnabled],
        Surface::Core,
        PolicyGrantFloor::SignatureOnly,
    )
    .unwrap();
    assert!(
        !PolicyStore::load()
            .unwrap()
            .unwrap()
            .effective()
            .unwrap()
            .page_eval_enabled
    );
}

#[test]
fn restrict_bounds_the_merged_disabled_tools() {
    use crate::policy::{DISABLED_TOOLS_MAX_ENTRIES, DISABLED_TOOL_NAME_MAX_BYTES};
    let _dir = scratch_runtime_dir("policy-restrict-tools-bounds");
    let seeded = seed_store(1, &PolicyValues::default(), None);
    // Growing the set restricts, so only the bounds can refuse these.
    let with_tools = |tools: Vec<String>| PolicyOverlay {
        disabled_tools: Some(tools),
        ..PolicyOverlay::default()
    };
    let err = restrict(
        with_tools(vec!["t".into(); DISABLED_TOOLS_MAX_ENTRIES + 1]),
        Surface::Cli,
    )
    .unwrap_err();
    assert!(matches!(err, PolicyWriteError::Invalid(_)));
    let err = restrict(
        with_tools(vec!["a".repeat(DISABLED_TOOL_NAME_MAX_BYTES + 1)]),
        Surface::Cli,
    )
    .unwrap_err();
    assert!(matches!(err, PolicyWriteError::Invalid(_)));
    assert_eq!(PolicyStore::load().unwrap().unwrap(), seeded);
    // At the bounds it applies - and the resulting store still loads,
    // which is what the bounds are for.
    restrict(
        with_tools(vec![
            "a".repeat(DISABLED_TOOL_NAME_MAX_BYTES);
            DISABLED_TOOLS_MAX_ENTRIES
        ]),
        Surface::Cli,
    )
    .unwrap();
    assert_eq!(
        PolicyStore::load()
            .unwrap()
            .unwrap()
            .effective()
            .unwrap()
            .disabled_tools
            .len(),
        DISABLED_TOOLS_MAX_ENTRIES
    );
}

#[test]
fn store_write_refuses_bytes_over_the_read_cap() {
    let _dir = scratch_runtime_dir("policy-write-cap");
    let store = PolicyStore {
        version: POLICY_STORE_VERSION,
        baseline_b64: "A".repeat(POLICY_MAX_BYTES),
        sig_b64: None,
        key_id: None,
        overlay: None,
    };
    let err = ipc::with_runtime_lock(|lock| store.write(lock)).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    // Nothing was persisted: load cannot be handed what it must refuse.
    assert!(PolicyStore::load().unwrap().is_none());
}

#[test]
fn clear_baseline_removes_the_store_and_keeps_history() {
    let _dir = scratch_runtime_dir("policy-clear-baseline");
    // A signed baseline plus a surviving restriction overlay.
    let seeded = seed_store(
        3,
        &PolicyValues {
            page_eval_enabled: true,
            ..PolicyValues::default()
        },
        Some(PolicyOverlay {
            confirm_grace_ms: Some(0),
            ..PolicyOverlay::default()
        }),
    );
    ipc::with_runtime_lock(clear_baseline_locked).unwrap();
    // The live store is gone (baseline/sig/key_id cleared): a baseline
    // signed by a now-deleted key must not outlive it.
    assert!(PolicyStore::load().unwrap().is_none());
    // The disposed record - baseline, sig, key id, AND overlay - survives
    // in the history ring as the re-signable draft.
    let history = load_history().unwrap().unwrap();
    assert_eq!(history.entries.len(), 1);
    let entry = &history.entries[0];
    assert_eq!(entry.baseline_b64, seeded.baseline_b64);
    assert_eq!(entry.sig_b64, seeded.sig_b64);
    assert_eq!(entry.key_id, seeded.key_id);
    assert_eq!(entry.overlay, seeded.overlay);
}

#[test]
fn clear_baseline_is_a_noop_without_a_store() {
    let _dir = scratch_runtime_dir("policy-clear-baseline-empty");
    ipc::with_runtime_lock(clear_baseline_locked).unwrap();
    assert!(PolicyStore::load().unwrap().is_none());
    assert!(load_history().unwrap().is_none());
}

#[test]
fn a_signed_write_bumps_the_policy_epoch() {
    let _dir = scratch_runtime_dir("policy-policy-epoch-signed");
    let _reset = policy_test_hook::ResetOnDrop;
    let before = crate::revocation::Revocation::current()
        .unwrap()
        .policy_epoch;
    policy_test_hook::set(signed_mock());
    set_signed(
        PolicyValues {
            page_eval_enabled: true,
            ..PolicyValues::default()
        },
        vec![PolicyField::PageEvalEnabled],
        Surface::Core,
        PolicyGrantFloor::SignatureOnly,
    )
    .unwrap();
    let after = crate::revocation::Revocation::current()
        .unwrap()
        .policy_epoch;
    assert!(after > before, "a signed write must bump the policy epoch");
}

#[test]
fn a_restriction_bumps_the_policy_epoch() {
    let _dir = scratch_runtime_dir("policy-policy-epoch-restrict");
    seed_store(
        1,
        &PolicyValues {
            page_eval_enabled: true,
            ..PolicyValues::default()
        },
        None,
    );
    let before = crate::revocation::Revocation::current()
        .unwrap()
        .policy_epoch;
    restrict(
        PolicyOverlay {
            page_eval_enabled: Some(false),
            ..PolicyOverlay::default()
        },
        Surface::Cli,
    )
    .unwrap();
    let after = crate::revocation::Revocation::current()
        .unwrap()
        .policy_epoch;
    assert!(after > before, "a restriction must bump the policy epoch");
}
