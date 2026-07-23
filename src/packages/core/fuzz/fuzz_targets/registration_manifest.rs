#![no_main]
//! Fuzz the ours/foreign decision over attacker-controlled manifest JSON. The
//! security property is never-delete-foreign, so the oracle re-derives the
//! only accepted shape - our exact host id plus one of the two markers this
//! project has ever written (both aliased from the real constants, never
//! duplicated literals) - and requires everything else to come back Foreign.
use libfuzzer_sys::fuzz_target;

use chromium_bridge_core::identity::NATIVE_HOST_ID;
use chromium_bridge_core::registration::{fuzz_api, manifest_ownership, Ownership};

fuzz_target!(|data: &[u8]| {
    let contents = String::from_utf8_lossy(data);
    let expect_ours = serde_json::from_str::<serde_json::Value>(&contents)
        .ok()
        .is_some_and(|manifest| {
            manifest.get("name").and_then(|v| v.as_str()) == Some(NATIVE_HOST_ID)
                && manifest
                    .get("description")
                    .and_then(|v| v.as_str())
                    .is_some_and(|d| {
                        d == fuzz_api::MANIFEST_DESCRIPTION
                            || d == fuzz_api::MANIFEST_DESCRIPTION_LEGACY
                    })
        });
    match manifest_ownership(&contents) {
        Ownership::Ours => assert!(expect_ours, "claimed Ours outside the accepted shape"),
        Ownership::Foreign(_) => assert!(!expect_ours, "our own manifest judged Foreign"),
    }
});
