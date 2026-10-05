//! `seeds/registration_manifest/`: the host manifest exactly as the registration engine writes it, under
//! synthetic paths, the extension pointer it writes, and the near-misses `manifest_ownership` and
//! `pointer_ownership` must judge foreign.

use std::path::Path;

use chromium_bridge_core::browsers::Scope;
use chromium_bridge_core::identity::PINNED_EXTENSION_ID;
use chromium_bridge_core::registration::{
    fuzz_api, manifest_ownership, pointer_json, pointer_ownership, Ownership, Registrar,
};
use serde_json::{json, Value};

use super::{edited, without, Directory, Seed};
use crate::targets;

fn is_ours(bytes: &[u8]) -> bool {
    manifest_ownership(&String::from_utf8_lossy(bytes)) == Ownership::Ours
}

fn is_pointer_ours(bytes: &[u8]) -> bool {
    pointer_ownership(&String::from_utf8_lossy(bytes)) == Ownership::Ours
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
        scope: Scope::User,
        system_root: "/".into(),
        extension_id: PINNED_EXTENSION_ID.into(),
    };
    let written = registrar
        .manifest_json(Path::new("/opt/example/run-host.sh"))
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
    let pointer_written = pointer_json();
    let pointer: Value = serde_json::from_str(&pointer_written).expect("the engine writes JSON");
    assert_eq!(
        pretty(&pointer),
        pointer_written.as_bytes(),
        "pretty() is the engine's pointer layout"
    );
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
            Seed::accepted("pointer_ours", pretty(&pointer), is_pointer_ours),
            // Our url beside a key this project never writes: another installer's pointer for our id.
            Seed::refused(
                "pointer_foreign_extra_key",
                pretty(&edited(&pointer, |v| {
                    v["supported_locales"] = json!(["en"]);
                })),
                is_pointer_ours,
            ),
            Seed::refused(
                "pointer_foreign_url",
                pretty(&edited(&pointer, |v| {
                    v["external_update_url"] = json!("https://updates.example.com/updates.xml");
                })),
                is_pointer_ours,
            ),
            Seed::refused(
                "pointer_foreign_crx",
                pretty(&json!({"external_crx": "/opt/example/x.crx", "external_version": "1.0"})),
                is_pointer_ours,
            ),
        ],
    }
}
