#![no_main]
//! Fuzz the policy store parse surface (ADR-0032): runtime_dir()/policy.json
//! is a same-user-writable file, so every shape read from it - the store
//! envelope, the base64 baseline bytes, the strict PolicyDoc, the overlay,
//! and the history ring - must fail closed on hostile bytes, never panic.
//! Beyond crash-freedom this target asserts the semantic invariants the
//! store depends on: a parsed document serde-round-trips to an equal value,
//! the comparison lattice partitions every pair (relaxes XOR
//! restricts_or_equal), fold is idempotent, and the hand-rolled strict
//! base64 accepts exactly one spelling per byte string (decode then encode
//! reproduces the input).
use libfuzzer_sys::fuzz_target;

use chromium_bridge_core::enclave::{base64_decode, base64_encode};
use chromium_bridge_core::policy::{
    fold, relaxes, restricts_or_equal, PolicyDoc, PolicyHistory, PolicyOverlay, PolicyStore,
    PolicyValues,
};

/// The invariants every successfully parsed document must satisfy: validate
/// and values never panic, and the exact serialized bytes reparse to an
/// equal document (what the store's signed-byte round trip depends on).
fn check_doc(doc: &PolicyDoc) {
    let _ = doc.validate();
    let _ = doc.values();
    let bytes = serde_json::to_vec(doc).expect("a parsed PolicyDoc must serialize");
    let back: PolicyDoc =
        serde_json::from_slice(&bytes).expect("serialized PolicyDoc must reparse");
    assert_eq!(&back, doc, "PolicyDoc serde round trip must be identity");
}

/// Folding an overlay over a baseline never panics and is idempotent;
/// returns the folded values for the pairwise lattice check.
fn check_fold(baseline: &PolicyValues, overlay: &PolicyOverlay) -> PolicyValues {
    let once = fold(baseline, overlay);
    assert_eq!(fold(&once, overlay), once, "fold must be idempotent");
    once
}

fuzz_target!(|data: &[u8]| {
    // Every parsed shape contributes its values here; the lattice check at
    // the bottom runs over all pairs (including each value against itself).
    let mut values: Vec<PolicyValues> = Vec::new();

    if let Ok(doc) = serde_json::from_slice::<PolicyDoc>(data) {
        check_doc(&doc);
        values.push(doc.values());
    }

    if let Ok(overlay) = serde_json::from_slice::<PolicyOverlay>(data) {
        values.push(check_fold(&PolicyValues::default(), &overlay));
    }

    if let Ok(store) = serde_json::from_slice::<PolicyStore>(data) {
        // Mirror baseline_doc()'s byte path on the parsed envelope (pure:
        // it reads self.baseline_b64, never the filesystem) and cross-check
        // it against a by-hand decode of the same bytes.
        let by_hand = base64_decode(&store.baseline_b64)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<PolicyDoc>(&bytes).ok())
            .filter(|doc| doc.validate().is_ok());
        let via_store = store.baseline_doc().ok();
        assert_eq!(
            by_hand, via_store,
            "baseline_doc must equal strict base64 decode + strict parse + validate"
        );
        if let Some(doc) = via_store {
            check_doc(&doc);
            let baseline = doc.values();
            let overlay = store.overlay.clone().unwrap_or_default();
            let effective = check_fold(&baseline, &overlay);
            assert_eq!(
                store
                    .effective()
                    .expect("a store with a valid baseline must fold"),
                effective,
                "effective() must be the fold of the baseline and the stored overlay"
            );
            values.push(baseline);
            values.push(effective);
        } else {
            assert!(
                store.effective().is_err(),
                "a store whose baseline fails must fail effective() too"
            );
        }
    }

    // The history ring shares the fail-closed posture; parsing it must not
    // panic (its entries are data, never authority, so nothing more to hold).
    let _ = serde_json::from_slice::<PolicyHistory>(data);

    // The lattice partition (the store's direction check depends on it): a
    // pair either relaxes somewhere or restricts-or-holds everywhere, never
    // both, never neither. A violation here IS a finding.
    for a in &values {
        for b in &values {
            assert!(
                relaxes(a, b) != restricts_or_equal(a, b),
                "relaxes and restricts_or_equal must partition every pair"
            );
        }
    }

    // The strict base64 decoder directly: for every accepted input, encoding
    // the decode must reproduce the exact input - one spelling per byte
    // string, the canonicality the signed baseline depends on.
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(bytes) = base64_decode(text) {
            assert_eq!(
                base64_encode(&bytes),
                text,
                "base64_decode must accept only the canonical spelling"
            );
        }
    }
});
