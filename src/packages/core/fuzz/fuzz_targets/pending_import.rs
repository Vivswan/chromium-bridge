#![no_main]
//! Fuzz the pending-import parse surface (ADR-0032 decision 8):
//! runtime_dir()/pending-import.json is a same-user-writable file holding the
//! snapshotted legacy settings bag or the consumed tombstone, so every shape
//! read from it must fail closed on hostile bytes, never panic. The target
//! drives `parse_record`, the exact validation chain `load()` runs on the
//! file's bytes: the 128 KiB file cap, the state-tagged shape
//! (`deny_unknown_fields`), the version pin, and the 64 KiB bag cap. Beyond
//! crash-freedom it asserts the invariant the store depends on - an accepted
//! record serde-round-trips through the same validator to an equal value, so
//! what the store writes it can always read back.
use libfuzzer_sys::fuzz_target;

use chromium_bridge_core::pending_import::parse_record;

fuzz_target!(|data: &[u8]| {
    if let Ok(record) = parse_record(data) {
        // The record must re-serialize (the bag is arbitrary JSON) and the
        // exact bytes must revalidate to an equal record - the round trip the
        // atomic write/read-back relies on.
        let bytes = serde_json::to_vec(&record).expect("a validated record must serialize");
        let back = parse_record(&bytes).expect("a serialized record must revalidate");
        assert_eq!(back, record, "pending-import round trip must be identity");
    }
});
