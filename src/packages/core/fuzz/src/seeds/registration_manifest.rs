//! `seeds/registration_manifest/`: the host manifest exactly as the registration engine writes it, under
//! synthetic paths, and the near-misses `manifest_ownership` must judge foreign.

use std::path::Path;

use chromium_bridge_core::identity::PINNED_EXTENSION_ID;
use chromium_bridge_core::registration::{fuzz_api, manifest_ownership, Ownership, Registrar};
use serde_json::{json, Value};

use super::{edited, without, Directory, Seed};
use crate::targets;

fn is_ours(bytes: &[u8]) -> bool {
    manifest_ownership(&String::from_utf8_lossy(bytes)) == Ownership::Ours
}

/// The manifest as a file: pretty-printed with a trailing newline, the engine's layout.
fn pretty(value: &Value) -> Vec<u8> {
    let mut text = serde_json::to_string_pretty(value).expect("a Value serializes");
    text.push('\n');
    text.into_bytes()
}

pub(super) fn directory() -> Directory {
    let registrar = Registrar {
        host_exe: "/opt/example/chromium-bridge".into(),
        install_dir: "/opt/example".into(),
        extension_id: PINNED_EXTENSION_ID.into(),
    };
    let written = fuzz_api::manifest_json(&registrar, Path::new("/opt/example/run-host.sh"))
        .expect("the engine renders a manifest for any path");
    let ours: Value = serde_json::from_str(&written).expect("the engine writes JSON");
    assert_eq!(
        pretty(&ours),
        written.as_bytes(),
        "pretty() is the engine's layout"
    );
    let legacy = edited(&ours, |v| {
        v["description"] = json!(fuzz_api::MANIFEST_DESCRIPTION_LEGACY);
    });
    Directory {
        target: targets::REGISTRATION_MANIFEST,
        seeds: vec![
            Seed::accepted("ours_current", pretty(&ours), is_ours),
            Seed::accepted("ours_legacy", pretty(&legacy), is_ours),
            Seed::refused(
                "foreign_name",
                pretty(&edited(&ours, |v| {
                    v["name"] = json!("com.example.other_host")
                })),
                is_ours,
            ),
            Seed::refused(
                "foreign_description_suffix",
                pretty(&edited(&ours, |v| {
                    v["description"] = json!(format!("{} v2", fuzz_api::MANIFEST_DESCRIPTION));
                })),
                is_ours,
            ),
            Seed::refused(
                "foreign_no_description",
                pretty(&without(&ours, "description")),
                is_ours,
            ),
            Seed::refused(
                "foreign_not_json",
                b"not a JSON manifest\n".to_vec(),
                is_ours,
            ),
        ],
    }
}
