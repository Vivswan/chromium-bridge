use std::fs;

use super::*;
use crate::audit::Surface;
use crate::enclave::{policy_message, EnrollmentKey, KeyStore};
use crate::policy::Ms;
use crate::presence::{PresenceAttestation, PresenceError, PresencePath};
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};

use crate::test_support::scratch_runtime_dir;

/// A signed-looking store seeded directly on disk: a baseline document
/// with `revision` over `values`, plus `overlay`. Returns the store as
/// written.
fn seed_store(revision: u64, values: &PolicyValues, overlay: Option<PolicyOverlay>) -> PolicyStore {
    let doc = PolicyDoc::from_values(values, revision, vec![]);
    let bytes = serde_json::to_vec(&doc).unwrap();
    let store = PolicyStore {
        baseline_b64: base64_encode(&bytes),
        sig_b64: Some(base64_encode(b"seed-sig")),
        key_id: Some("seed-kid".into()),
        overlay,
    };
    ipc::with_runtime_lock(|lock| store.write(lock)).unwrap();
    store
}

/// The host key the grant lane signs with, minted into the scratch runtime dir's file record (a test build
/// reaches no credential store).
fn enroll_host_key() -> EnrollmentKey {
    let auth = PresenceAttestation::assume_for_tests(PresencePath::Tty);
    ipc::with_runtime_lock(|lock| Ok(EnrollmentKey::mint(lock, KeyStore::File, auth)))
        .unwrap()
        .unwrap()
}

fn attest() -> Result<PresenceAttestation, PresenceError> {
    Ok(PresenceAttestation::assume_for_tests(PresencePath::Tty))
}

/// The presence prompt a promptless refusal must never reach.
macro_rules! never_attest {
    () => {
        || -> Result<PresenceAttestation, PresenceError> {
            panic!("presence must not be requested by this test")
        }
    };
}

/// Whether `store`'s signature verifies under `key` over the policy-domain message of its stored bytes.
fn signature_verifies(key: &EnrollmentKey, store: &PolicyStore) -> bool {
    let verifier = VerifyingKey::from_sec1_bytes(key.public_key().as_bytes()).unwrap();
    let sig =
        Signature::from_slice(&base64_decode(store.sig_b64.as_deref().unwrap()).unwrap()).unwrap();
    let message = policy_message(&base64_decode(&store.baseline_b64).unwrap());
    verifier.verify(&message, &sig).is_ok()
}

/// The audit trail written into the scratch runtime dir, as one string.
fn audit_text() -> String {
    fs::read_to_string(crate::audit::audit_path().unwrap()).unwrap_or_default()
}

#[test]
fn store_round_trips_the_exact_baseline_bytes() {
    let _dir = scratch_runtime_dir();
    let doc = PolicyDoc {
        revision: 7,
        touched: vec![PolicyField::PageEvalEnabled],
        page_eval_enabled: true,
        ..PolicyDoc::default()
    };
    let bytes = serde_json::to_vec(&doc).unwrap();
    let store = PolicyStore {
        baseline_b64: base64_encode(&bytes),
        sig_b64: Some("c2ln".into()),
        key_id: Some("kid".into()),
        overlay: Some(PolicyOverlay {
            confirm_grace_ms: Some(Ms::ZERO),
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
    let _dir = scratch_runtime_dir();
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
    // against its own pinned key - the host store
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
    let _dir = scratch_runtime_dir();
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
    let _dir = scratch_runtime_dir();
    let store = PolicyStore {
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
fn set_signed_writes_the_exact_signed_bytes_and_bumps_revisions() {
    let _dir = scratch_runtime_dir();
    let key = enroll_host_key();

    let values = PolicyValues {
        page_eval_enabled: true,
        ..PolicyValues::default()
    };
    let rung = set_signed(
        values.clone(),
        vec![PolicyField::PageEvalEnabled],
        Surface::Core,
        attest,
    )
    .unwrap();
    assert_eq!(rung, PresencePath::Tty);

    let first = PolicyStore::load().unwrap().unwrap();
    let doc = first.baseline_doc().unwrap();
    assert_eq!(doc.revision, 1);
    assert_eq!(doc.touched, vec![PolicyField::PageEvalEnabled]);
    assert_eq!(doc.values(), values);
    assert!(
        signature_verifies(&key, &first),
        "the host key signed the stored bytes"
    );
    assert_eq!(
        first.key_id.as_deref(),
        Some(key.public_key().fingerprint_hex().as_str())
    );
    assert!(first.overlay.is_none());
    // No previous store existed, so nothing was pushed.
    assert!(PolicyHistory::load().unwrap().is_none());

    // The second write supersedes the first: revision 2, and the ring
    // holds the exact previous record.
    set_signed(
        PolicyValues::default(),
        vec![PolicyField::PageEvalEnabled],
        Surface::Core,
        attest,
    )
    .unwrap();
    let second = PolicyStore::load().unwrap().unwrap();
    assert_eq!(second.baseline_doc().unwrap().revision, 2);
    let history = PolicyHistory::load().unwrap().unwrap();
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
    assert!(trail.contains("auth=tty"), "{trail}");
    assert!(trail.contains("touched=pageEvalEnabled"), "{trail}");
}

#[test]
fn set_signed_clears_touched_overlay_entries_and_keeps_the_rest() {
    let _dir = scratch_runtime_dir();
    enroll_host_key();
    let overlay = PolicyOverlay {
        confirm_grace_ms: Some(Ms::from(1_000u32)),
        disabled_tools: Some(vec!["page_eval".into()]),
        ..PolicyOverlay::default()
    };
    seed_store(1, &PolicyValues::default(), Some(overlay));

    set_signed(
        PolicyValues {
            confirm_grace_ms: Ms::from(1_000u32),
            ..PolicyValues::default()
        },
        vec![PolicyField::ConfirmGraceMs],
        Surface::Core,
        attest,
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
    let _dir = scratch_runtime_dir();
    enroll_host_key();
    // A baseline with grants on, restricted by overlay.
    let baseline_values = PolicyValues {
        page_eval_enabled: true,
        ..PolicyValues::default()
    };
    let overlay = PolicyOverlay {
        page_eval_enabled: Some(false),
        confirm_grace_ms: Some(Ms::ZERO),
        disabled_tools: Some(vec!["page_upload".into()]),
        ..PolicyOverlay::default()
    };
    let seeded = seed_store(3, &baseline_values, Some(overlay));
    let effective_before = seeded.effective().unwrap();

    // The explicit fold act: a new revision
    // carrying the folded fields' EFFECTIVE values with exactly those
    // fields touched.
    set_signed(
        effective_before.clone(),
        vec![
            PolicyField::PageEvalEnabled,
            PolicyField::ConfirmGraceMs,
            PolicyField::DisabledTools,
        ],
        Surface::Core,
        attest,
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
    let _dir = scratch_runtime_dir();
    let key = enroll_host_key();
    let values = PolicyValues {
        page_eval_enabled: true,
        ..PolicyValues::default()
    };
    let touched = vec![PolicyField::PageEvalEnabled];
    set_signed(values.clone(), touched.clone(), Surface::Core, attest).unwrap();
    // The stored signature verifies over the stored bytes and over nothing else: the signature can only
    // ever cover exactly what is stored.
    let store = PolicyStore::load().unwrap().unwrap();
    assert!(signature_verifies(&key, &store));
    let mut tampered = store.clone();
    tampered.baseline_b64 = base64_encode(b"{}");
    assert!(!signature_verifies(&key, &tampered));
    // And those bytes parse back to a document scoped by exactly the
    // touched set and values that were passed.
    let signed = base64_decode(&store.baseline_b64).unwrap();
    let doc: PolicyDoc = serde_json::from_slice(&signed).unwrap();
    assert_eq!(doc.touched, touched);
    assert_eq!(doc.values(), values);
}

#[test]
fn an_empty_touched_set_refuses_before_any_prompt() {
    let _dir = scratch_runtime_dir();
    enroll_host_key();
    let err = set_signed(
        PolicyValues::default(),
        vec![],
        Surface::Core,
        never_attest!(),
    )
    .unwrap_err();
    assert!(matches!(err, PolicyWriteError::Invalid(_)));
    assert!(PolicyStore::load().unwrap().is_none());
}

#[test]
fn revision_overflow_refuses_before_any_prompt() {
    let _dir = scratch_runtime_dir();
    enroll_host_key();
    seed_store(JS_SAFE_INT_MAX, &PolicyValues::default(), None);
    let err = set_signed(
        PolicyValues::default(),
        vec![PolicyField::CdpMode],
        Surface::Core,
        never_attest!(),
    )
    .unwrap_err();
    assert!(matches!(err, PolicyWriteError::RevisionOverflow));
}

#[test]
fn the_last_js_safe_revision_still_writes() {
    // The near-boundary through the full seam: MAX - 1 mints exactly
    // MAX, the last legal revision (the overflow test above pins that
    // MAX itself refuses).
    let _dir = scratch_runtime_dir();
    enroll_host_key();
    seed_store(JS_SAFE_INT_MAX - 1, &PolicyValues::default(), None);
    set_signed(
        PolicyValues::default(),
        vec![PolicyField::CdpMode],
        Surface::Core,
        attest,
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
fn a_refused_presence_never_falls_to_the_floor() {
    let _dir = scratch_runtime_dir();
    enroll_host_key();
    let seeded = seed_store(1, &PolicyValues::default(), None);
    // A refusal is terminal (the no-downgrade rule): never an unsigned
    // write, never a softer prompt.
    let err = set_signed(
        PolicyValues::default(),
        vec![PolicyField::CdpMode],
        Surface::Core,
        || Err(PresenceError::Declined),
    )
    .unwrap_err();
    assert!(matches!(err, PolicyWriteError::Refused(_)));
    assert_eq!(PolicyStore::load().unwrap().unwrap(), seeded);
    assert!(audit_text().contains("\"outcome\":\"refused\""));
}

#[test]
fn a_keyless_machine_refuses_the_grant_before_any_prompt() {
    let _dir = scratch_runtime_dir();
    let err = set_signed(
        PolicyValues::default(),
        vec![PolicyField::CdpMode],
        Surface::Cli,
        never_attest!(),
    )
    .unwrap_err();
    assert!(matches!(err, PolicyWriteError::NoSigningKey));
    assert!(PolicyStore::load().unwrap().is_none());
    assert!(audit_text().contains("no signing key"));
}

#[test]
fn restrict_without_a_baseline_refuses() {
    let _dir = scratch_runtime_dir();
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
    let _dir = scratch_runtime_dir();
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
    let history = PolicyHistory::load().unwrap().unwrap();
    assert_eq!(history.entries.len(), 1);
    assert_eq!(history.entries[0].overlay, None);
    assert!(audit_text().contains("auth=none; restricted=pageEvalEnabled"));
}

#[test]
fn a_relaxing_overlay_is_refused_with_the_store_unchanged() {
    let _dir = scratch_runtime_dir();
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
    // lane's business).
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
    assert!(PolicyHistory::load().unwrap().is_none());
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
    let _dir = scratch_runtime_dir();
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
            confirm_grace_ms: Some(Ms::ZERO),
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
            confirm_grace_ms: Some(Ms::ZERO),
            ..PolicyOverlay::default()
        })
    );
}

#[test]
fn history_evicts_oldest_entries_until_the_ring_encodes_under_its_own_cap() {
    // Eviction and the read cap are two facts about one file: a ring written over the cap would
    // load back as an error at the rollback surface.
    let entry = |tag: u64, baseline_len: usize| PolicyHistoryEntry {
        baseline_b64: "A".repeat(baseline_len),
        sig_b64: None,
        key_id: None,
        overlay: None,
        superseded_unix: tag,
    };
    // Thirty-two entries of 16 KiB overflow the 256 KiB cap by about half.
    let mut history = PolicyHistory {
        entries: (0..32).map(|tag| entry(tag, 16 * 1024)).collect(),
    };
    evict_to_fit(&mut history);
    let bytes = history.encode().unwrap();
    assert!(bytes.len() <= <PolicyHistory as Record>::MAX_BYTES);
    assert_eq!(PolicyHistory::decode(&bytes).unwrap(), history);
    assert!(!history.entries.is_empty());
    assert!(history.entries.len() < 32);
    assert_eq!(history.entries.last().unwrap().superseded_unix, 31);
    assert_eq!(
        history.entries.first().unwrap().superseded_unix,
        32 - history.entries.len() as u64
    );
    // One entry alone over the cap empties the ring, and the empty ring still encodes.
    let mut oversized = PolicyHistory {
        entries: vec![entry(1, 300 * 1024)],
    };
    evict_to_fit(&mut oversized);
    assert!(oversized.entries.is_empty());
    assert_eq!(
        PolicyHistory::decode(&oversized.encode().unwrap()).unwrap(),
        oversized
    );
}

#[test]
fn a_corrupt_history_file_never_blocks_policy_writes() {
    let _dir = scratch_runtime_dir();
    enroll_host_key();
    seed_store(1, &PolicyValues::default(), None);
    fs::write(PolicyHistory::path().unwrap(), b"garbage, not json").unwrap();
    // Reading it fails closed for the (future) rollback surface...
    assert!(PolicyHistory::load().is_err());
    // ...but the enforcement paths and both seams stay fully functional:
    // the writer logs, replaces the ring, and the policy writes land.
    assert!(PolicyStore::load().unwrap().is_some());
    set_signed(
        PolicyValues::default(),
        vec![PolicyField::CdpMode],
        Surface::Core,
        attest,
    )
    .unwrap();
    restrict(
        PolicyOverlay {
            confirm_grace_ms: Some(Ms::ZERO),
            ..PolicyOverlay::default()
        },
        Surface::Cli,
    )
    .unwrap();
    // The fresh ring holds the records superseded after the corruption.
    assert_eq!(PolicyHistory::load().unwrap().unwrap().entries.len(), 2);
}

#[test]
fn a_moved_baseline_revision_conflicts_instead_of_overwriting() {
    let _dir = scratch_runtime_dir();
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
            "c2ln".into(),
            "key-id".into(),
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
            "c2ln".into(),
            "key-id".into(),
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
            "c2ln".into(),
            "key-id".into(),
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
    let _dir = scratch_runtime_dir();
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
            "c2ln".into(),
            "key-id".into(),
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
            "c2ln".into(),
            "key-id".into(),
            &[PolicyField::CdpMode],
        ))
    })
    .unwrap();
    assert!(fresh.is_ok());
}

#[test]
fn a_disposal_during_the_prompt_conflicts_even_with_no_store_on_both_sides() {
    let _dir = scratch_runtime_dir();
    // A first write's pre-prompt observation: no store, and the host-key
    // epoch as it stood before the tap.
    let doc = PolicyDoc::from_values(&PolicyValues::default(), 1, vec![PolicyField::CdpMode]);
    let bytes = serde_json::to_vec(&doc).unwrap();
    let observed_epoch = crate::trust::TrustState::current()
        .unwrap()
        .host_key_epoch();
    // The disposal seam runs to completion mid-prompt: key deleted,
    // baseline cleared (a no-op here, no store exists), host-key epoch
    // bumped inside its critical section.
    ipc::with_runtime_lock(|lock| {
        crate::trust::Trust::mutate_locked(lock, crate::trust::Scope::HostKey, |_| {})
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
            "c2ln".into(),
            "key-id".into(),
            &[PolicyField::CdpMode],
        ))
    })
    .unwrap();
    assert!(matches!(stale, Err(PolicyWriteError::Conflict)));
    assert!(PolicyStore::load().unwrap().is_none());
}

#[test]
fn a_tampered_overlay_that_relaxes_the_baseline_refuses_every_read() {
    let _dir = scratch_runtime_dir();
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
fn a_relaxation_outside_the_touched_set_refuses_before_any_prompt() {
    let _dir = scratch_runtime_dir();
    enroll_host_key();
    seed_store(1, &PolicyValues::default(), None);
    // page_eval_enabled: true relaxes the effective anchor, but touched names only cdpMode: promptless refusal.
    let relaxing = PolicyValues {
        page_eval_enabled: true,
        ..PolicyValues::default()
    };
    let err = set_signed(
        relaxing.clone(),
        vec![PolicyField::CdpMode],
        Surface::Core,
        never_attest!(),
    )
    .unwrap_err();
    assert!(matches!(err, PolicyWriteError::Invalid(_)));
    // With no store at all the anchor is the deny baseline: an
    // undeclared first-write grant refuses the same way.
    fs::remove_file(PolicyStore::path().unwrap()).unwrap();
    let err = set_signed(
        relaxing,
        vec![PolicyField::CdpMode],
        Surface::Core,
        never_attest!(),
    )
    .unwrap_err();
    assert!(matches!(err, PolicyWriteError::Invalid(_)));
    assert!(PolicyStore::load().unwrap().is_none());
}

#[test]
fn a_touched_superset_of_the_relaxations_passes() {
    let _dir = scratch_runtime_dir();
    enroll_host_key();
    seed_store(1, &PolicyValues::default(), None);
    set_signed(
        PolicyValues {
            page_eval_enabled: true,
            ..PolicyValues::default()
        },
        vec![PolicyField::PageEvalEnabled, PolicyField::CdpMode],
        Surface::Core,
        attest,
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
    let _dir = scratch_runtime_dir();
    enroll_host_key();
    seed_store(
        1,
        &PolicyValues {
            page_eval_enabled: true,
            ..PolicyValues::default()
        },
        None,
    );
    // Turning page_eval OFF is a restriction, but the signed document
    // carries baseline values on fields it does not touch:
    // changing it under an unrelated touched field is an unnamed edit
    // and refuses promptless, in EITHER direction.
    let drift = set_signed(
        PolicyValues::default(),
        vec![PolicyField::ConfirmGraceMs],
        Surface::Core,
        never_attest!(),
    );
    assert!(matches!(drift, Err(PolicyWriteError::Invalid(_))));
    // Named in touched, the same restriction lands (the coverage check
    // binds relaxations only; restrictions just need naming).
    set_signed(
        PolicyValues::default(),
        vec![PolicyField::PageEvalEnabled],
        Surface::Core,
        attest,
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
    let _dir = scratch_runtime_dir();
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
    let _dir = scratch_runtime_dir();
    let store = PolicyStore {
        baseline_b64: "A".repeat(<PolicyStore as Record>::MAX_BYTES),
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
    let _dir = scratch_runtime_dir();
    // A signed baseline plus a surviving restriction overlay.
    let seeded = seed_store(
        3,
        &PolicyValues {
            page_eval_enabled: true,
            ..PolicyValues::default()
        },
        Some(PolicyOverlay {
            confirm_grace_ms: Some(Ms::ZERO),
            ..PolicyOverlay::default()
        }),
    );
    ipc::with_runtime_lock(clear_baseline_locked).unwrap();
    // The live store is gone (baseline/sig/key_id cleared): a baseline
    // signed by a now-deleted key must not outlive it.
    assert!(PolicyStore::load().unwrap().is_none());
    // The disposed record - baseline, sig, key id, AND overlay - survives
    // in the history ring as the re-signable draft.
    let history = PolicyHistory::load().unwrap().unwrap();
    assert_eq!(history.entries.len(), 1);
    let entry = &history.entries[0];
    assert_eq!(entry.baseline_b64, seeded.baseline_b64);
    assert_eq!(entry.sig_b64, seeded.sig_b64);
    assert_eq!(entry.key_id, seeded.key_id);
    assert_eq!(entry.overlay, seeded.overlay);
}

#[test]
fn clear_baseline_is_a_noop_without_a_store() {
    let _dir = scratch_runtime_dir();
    ipc::with_runtime_lock(clear_baseline_locked).unwrap();
    assert!(PolicyStore::load().unwrap().is_none());
    assert!(PolicyHistory::load().unwrap().is_none());
}

#[test]
fn every_policy_write_moves_the_policy_epoch_and_a_noop_clear_holds_it() {
    // The native host pushes a policy change only when the epoch moved, so
    // each write that changes what the bridge enforces must move it, and a
    // clear of an already-cleared store must leave the moved marker exactly
    // where it was (no push churn).
    enum Epoch {
        Moves,
        Holds,
    }
    struct Case {
        name: &'static str,
        start: fn(),
        write: fn(),
        epoch: Epoch,
    }
    fn seed_relaxed() {
        seed_store(
            1,
            &PolicyValues {
                page_eval_enabled: true,
                ..PolicyValues::default()
            },
            None,
        );
    }
    fn seed_deny() {
        seed_store(1, &PolicyValues::default(), None);
    }
    fn clear() {
        ipc::with_runtime_lock(clear_baseline_locked).unwrap();
    }
    let cases = [
        Case {
            name: "signed write",
            start: || {},
            write: || {
                set_signed(
                    PolicyValues {
                        page_eval_enabled: true,
                        ..PolicyValues::default()
                    },
                    vec![PolicyField::PageEvalEnabled],
                    Surface::Core,
                    attest,
                )
                .unwrap();
            },
            epoch: Epoch::Moves,
        },
        Case {
            name: "restriction",
            start: seed_relaxed,
            write: || {
                restrict(
                    PolicyOverlay {
                        page_eval_enabled: Some(false),
                        ..PolicyOverlay::default()
                    },
                    Surface::Cli,
                )
                .unwrap();
            },
            epoch: Epoch::Moves,
        },
        Case {
            name: "clear with a store",
            start: seed_deny,
            write: clear,
            epoch: Epoch::Moves,
        },
        Case {
            name: "clear of an already-cleared store",
            start: || {
                seed_deny();
                clear();
            },
            write: clear,
            epoch: Epoch::Holds,
        },
    ];
    for case in cases {
        let _dir = scratch_runtime_dir();
        enroll_host_key();
        (case.start)();
        let before = crate::trust::TrustState::current().unwrap().policy_epoch();
        (case.write)();
        let after = crate::trust::TrustState::current().unwrap().policy_epoch();
        match case.epoch {
            Epoch::Moves => assert!(after > before, "{} must move the epoch", case.name),
            Epoch::Holds => {
                assert!(
                    before > 0,
                    "{}: the control marker must already have moved",
                    case.name
                );
                assert_eq!(after, before, "{} must hold the epoch", case.name);
            }
        }
    }
}
