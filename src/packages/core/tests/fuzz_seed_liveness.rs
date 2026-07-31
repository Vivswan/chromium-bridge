//! Fuzz-seed liveness: the checked-in `registration_manifest` corpus must
//! keep exercising the branches it was minted for. The seeds are inert data
//! to every other gate, so after an identity or marker change the "ours"
//! seeds would silently start classifying as foreign and the fuzzer would
//! lose its targeted coverage of the never-delete-foreign decision - the most
//! security-relevant branch that target has - with no signal anywhere. This
//! test enumerates the whole seed directory (a new seed is covered the day it
//! lands) and replays each file through the real registration engine,
//! pinning the classification its `ours_` / `foreign_` filename prefix
//! claims, so a drift shows up in `cargo nextest` (in `moon run ci`) as a
//! demand to re-mint the seed.

use std::path::Path;

use chromium_bridge_core::identity::NATIVE_HOST_ID;
use chromium_bridge_core::registration::{manifest_ownership, Ownership};

#[test]
fn every_seed_still_classifies_as_its_prefix_claims() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/registration_manifest");
    let mut seen: u32 = 0;
    for entry in std::fs::read_dir(&dir).expect("fuzz/seeds/registration_manifest must exist") {
        let path = entry.expect("readable seed dir entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("seed filenames are UTF-8")
            .to_string();
        if name.starts_with('.') {
            continue; // editor/Finder droppings (.DS_Store), never corpus seeds
        }
        let contents = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("seed {name} must be readable text: {e}"));
        let ownership = manifest_ownership(&contents);
        if name.starts_with("ours_") {
            assert_eq!(
                ownership,
                Ownership::Ours,
                "fuzz seed {name} no longer classifies as Ours - the identity or \
                 manifest markers moved; re-mint the seed so the fuzzer keeps \
                 covering the ours branch"
            );
        } else if name.starts_with("foreign_") {
            assert!(
                matches!(ownership, Ownership::Foreign(_)),
                "fuzz seed {name} no longer classifies as Foreign - it stopped \
                 exercising the never-delete-foreign branch; re-mint it"
            );
        } else {
            panic!(
                "fuzz seed {name} has no ours_/foreign_ prefix, so its intended \
                 classification cannot be pinned; rename it to state its claim"
            );
        }
        seen = seen.saturating_add(1);
    }
    assert!(
        seen >= 6,
        "only {seen} registration_manifest seeds found - the corpus shrank below \
         the six this test was written against; restore the seeds or update this pin"
    );
}

#[test]
fn json_protocol_dictionary_carries_the_current_host_id() {
    let dict = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/dictionaries/json_protocol.dict");
    let dict = std::fs::read_to_string(dict).expect("json_protocol.dict must be readable");
    assert!(
        dict.contains(&format!("\"{NATIVE_HOST_ID}\"")),
        "fuzz/dictionaries/json_protocol.dict no longer contains the current \
         native host id {NATIVE_HOST_ID:?}; update the dictionary entry so \
         the fuzzer keeps synthesizing our-manifest inputs"
    );
}
