//! What sits at each location the engine may own, and whose it is: the manifest file, its Windows key, and the
//! extension pointer, each read once into a [`Slot`] that `register` and `uninstall` judge in opposite
//! directions, and the diagnosed states `doctor` reports from the same read.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::registry::{registry_default_value, registry_key, same_windows_path, RegistryKey};
use super::{ForeignManifest, MANIFEST_DESCRIPTION, POINTER_VALUE_NAME, WEB_STORE_UPDATE_URL};
use crate::browsers::{ExtensionPointer, Hive, Registration};
use crate::identity::NATIVE_HOST_ID;

/// Verdict on an existing manifest file's contents: ours or not.
#[derive(Debug, PartialEq, Eq)]
pub enum Ownership {
    Ours,
    Foreign(String),
}

/// The diagnosed state of one registration, as reported by `doctor` and
/// repaired by `--fix`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegState {
    /// No manifest file (and no registry key on Windows).
    Missing,
    /// Ours and its launch path exists.
    Ok,
    /// Ours, but broken: the reason says what (dangling launch path, or a
    /// Windows manifest file without its registry key).
    Stale(String),
    /// Present but not written by this project.
    Foreign(String),
    /// Could not be read/verified (permissions, not a file, ...).
    Unreadable(String),
}

impl RegState {
    /// Short human word(s) for reports.
    pub fn describe(&self) -> String {
        match self {
            RegState::Missing => "missing".into(),
            RegState::Ok => "ok".into(),
            RegState::Stale(why) => format!("stale ({why})"),
            RegState::Foreign(why) => format!("NOT OURS ({why})"),
            RegState::Unreadable(why) => format!("unreadable ({why})"),
        }
    }
}

/// The diagnosed state of one external-extension pointer, as reported by
/// `doctor` and repaired by `--fix`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PointerState {
    /// No pointer file (and no registry key on Windows).
    Missing,
    /// Ours: it names the Web Store, and nothing else.
    Ok,
    /// Present but not written by this project.
    Foreign(String),
    /// Could not be read/verified (permissions, not a file, ...).
    Unreadable(String),
}

impl PointerState {
    /// Short human word(s) for reports.
    pub fn describe(&self) -> String {
        match self {
            PointerState::Missing => "missing".into(),
            PointerState::Ok => "ok".into(),
            PointerState::Foreign(why) => format!("NOT OURS ({why})"),
            PointerState::Unreadable(why) => format!("unreadable ({why})"),
        }
    }
}

/// What a location this engine may own holds, and the rule for each, in both directions. A manifest at
/// our host id that another tool wrote (`Foreign`): `doctor` reports it foreign, an explicit `--fix`
/// overwrites it and reports what it launched ([`ForeignManifest`]: the extension's repair does not),
/// `uninstall` never removes it. An entry nobody can verify
/// (`Unreadable`: a directory, a dangling link) is refused both ways. The extension pointer is refused
/// both ways when foreign: it is another installer's claim on the extension, not a manifest of ours to
/// repair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Slot {
    Absent,
    /// Ours, with what was read (the file's bytes, or the key's value).
    Ours(String),
    /// Not ours: why, the launch path it carried (a manifest's `path`, a key's default), so a
    /// replacement can say what it displaced without echoing the rest of a file nobody here wrote, and
    /// whether `--fix` can replace it whole.
    Foreign {
        why: String,
        launched: Option<String>,
        shape: ForeignShape,
    },
    Unreadable(String),
}

/// Whether an explicit `--fix` can replace a foreign slot whole: a file or a flat key, yes; a key with
/// child keys, no (the non-recursive delete this engine allows itself fails on it), so it is refused in
/// preflight rather than after the manifest beside it has already changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ForeignShape {
    Replaceable,
    Rooted,
}

impl Slot {
    /// `Ok` when `register` may write a pointer here; the refusal names `what`.
    pub(super) fn writable(&self, what: &str) -> Result<(), String> {
        match self {
            Slot::Absent | Slot::Ours(_) => Ok(()),
            Slot::Foreign { why, .. } => Err(format!(
                "refusing to overwrite {what}: {why}. Inspect and remove it yourself if it is stale."
            )),
            Slot::Unreadable(why) => Err(format!(
                "cannot verify the existing {what}: {why} (left untouched)"
            )),
        }
    }

    /// `register`'s answer for a manifest slot: `Ok(None)` writes, `Ok(Some(line))` overwrites a foreign
    /// one and reports what it displaced, `Err` refuses what nobody can verify, or a foreign one when the
    /// caller may not replace it.
    pub(super) fn replaceable(
        &self,
        what: &str,
        foreign: ForeignManifest,
    ) -> Result<Option<String>, String> {
        match self {
            Slot::Absent | Slot::Ours(_) => Ok(None),
            Slot::Foreign { .. } if foreign == ForeignManifest::Refuse => {
                self.writable(what).map(|()| None)
            }
            Slot::Foreign {
                why,
                launched,
                shape: ForeignShape::Replaceable,
            } => Ok(Some(format!(
                "  replaced {what}, not written by genkan ({why}); it launched {}",
                launched
                    .as_deref()
                    .unwrap_or("nothing readable as a launch path")
            ))),
            Slot::Foreign {
                why,
                shape: ForeignShape::Rooted,
                ..
            } => Err(format!(
                "refusing to replace {what}: {why}; remove it yourself if you are sure"
            )),
            Slot::Unreadable(why) => Err(format!(
                "cannot verify the existing {what}: {why} (left untouched)"
            )),
        }
    }

    /// `Ok(true)` when `uninstall` must delete here, `Ok(false)` when there is
    /// nothing of ours; the refusal names `what`.
    pub(super) fn removable(&self, what: &str) -> Result<bool, String> {
        match self {
            Slot::Absent => Ok(false),
            Slot::Ours(_) => Ok(true),
            Slot::Foreign { why, .. } => Err(format!(
                "refusing to remove {what}: {why}. Not written by genkan; remove it yourself if you are sure."
            )),
            Slot::Unreadable(why) => Err(format!(
                "could not read {what} to verify it is ours: {why} (left in place)"
            )),
        }
    }
}

/// Read a file this engine may own. `Ok(None)` only when no directory entry
/// exists at all: a dangling symlink reads as NotFound too, and replacing it
/// would destroy an entry nobody verified, so it is an error like any other
/// read failure.
fn read_slot(path: &Path) -> Result<Option<String>, String> {
    match fs::read_to_string(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => match fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("could not look for an entry at this path: {e}")),
            Ok(_) => Err("a dangling symlink sits at this path".into()),
        },
        Err(e) => Err(e.to_string()),
    }
}

fn file_slot(path: &Path, ownership: fn(&str) -> Ownership) -> Slot {
    match read_slot(path) {
        Err(why) => Slot::Unreadable(why),
        Ok(None) => Slot::Absent,
        Ok(Some(contents)) => match ownership(&contents) {
            Ownership::Ours => Slot::Ours(contents),
            Ownership::Foreign(why) => Slot::Foreign {
                why,
                launched: serde_json::from_str::<serde_json::Value>(&contents)
                    .ok()
                    .and_then(|v| v.get("path").and_then(|p| p.as_str()).map(str::to_string)),
                shape: ForeignShape::Replaceable,
            },
        },
    }
}

/// A registry key this engine may own holds exactly one REG_SZ value, the one
/// it wrote, and no child key; `expected` judges that value. Any other shape
/// is someone else's key.
fn registry_slot(hive: Hive, key: &str, name: &str, expected: impl Fn(&str) -> bool) -> Slot {
    match registry_key(hive, key) {
        Err(why) => Slot::Unreadable(format!("registry key {hive}\\{key}: {why}")),
        Ok(None) => Slot::Absent,
        Ok(Some(RegistryKey { children, .. })) if children > 0 => Slot::Foreign {
            why: format!("registry key {hive}\\{key} carries child keys this project never writes"),
            launched: None,
            shape: ForeignShape::Rooted,
        },
        Ok(Some(RegistryKey { values, .. })) => match values.as_slice() {
            [(only, value)] if only == name && expected(value) => Slot::Ours(value.clone()),
            [(only, value)] if only == name => Slot::Foreign {
                why: format!("registry key {hive}\\{key} points at {value:?}, not ours"),
                launched: Some(value.clone()),
                shape: ForeignShape::Replaceable,
            },
            _ => Slot::Foreign {
                why: format!("registry key {hive}\\{key} carries values this project never writes"),
                launched: values
                    .iter()
                    .find(|(n, _)| n == name)
                    .map(|(_, v)| v.clone()),
                shape: ForeignShape::Replaceable,
            },
        },
    }
}

/// Decide whether pointer file `contents` were written by this project: a JSON
/// object whose only key is `external_update_url` naming the Web Store. A
/// pointer at a different source, or carrying any other key (`external_crx`,
/// `supported_locales`), is foreign and must never be deleted.
pub fn pointer_ownership(contents: &str) -> Ownership {
    let parsed: serde_json::Value = match serde_json::from_str(contents) {
        Ok(v) => v,
        Err(e) => return Ownership::Foreign(format!("not a JSON pointer ({e})")),
    };
    let Some(object) = parsed.as_object() else {
        return Ownership::Foreign("pointer is not a JSON object".into());
    };
    if object.len() != 1 {
        return Ownership::Foreign("pointer carries keys this project never writes".into());
    }
    match object.get("external_update_url").and_then(|v| v.as_str()) {
        Some(WEB_STORE_UPDATE_URL) => Ownership::Ours,
        other => Ownership::Foreign(format!(
            "pointer update url is {other:?}, expected {WEB_STORE_UPDATE_URL:?}"
        )),
    }
}

pub(super) fn pointer_slot(pointer: &ExtensionPointer) -> Slot {
    match pointer {
        ExtensionPointer::File(path) => file_slot(path, pointer_ownership),
        ExtensionPointer::Registry { hive, key } => {
            registry_slot(*hive, key, POINTER_VALUE_NAME, |url| {
                url == WEB_STORE_UPDATE_URL
            })
        }
    }
}

pub fn assess_pointer(pointer: &ExtensionPointer) -> PointerState {
    match pointer_slot(pointer) {
        Slot::Absent => PointerState::Missing,
        Slot::Ours(_) => PointerState::Ok,
        Slot::Foreign { why, .. } => PointerState::Foreign(why),
        Slot::Unreadable(why) => PointerState::Unreadable(why),
    }
}

/// Decide whether manifest `contents` were written by this project. Ours
/// means: valid JSON whose `name` is our host id and whose `description` is
/// EXACTLY the marker this engine writes. Anything else -- unparsable, another
/// host id, another description -- is foreign and must never be deleted.
pub fn manifest_ownership(contents: &str) -> Ownership {
    let parsed: serde_json::Value = match serde_json::from_str(contents) {
        Ok(v) => v,
        Err(e) => return Ownership::Foreign(format!("not a JSON manifest ({e})")),
    };
    match parsed.get("name").and_then(|v| v.as_str()) {
        Some(name) if name == NATIVE_HOST_ID => {}
        other => {
            return Ownership::Foreign(format!(
                "manifest name is {other:?}, expected {NATIVE_HOST_ID:?}"
            ))
        }
    }
    match parsed.get("description").and_then(|v| v.as_str()) {
        Some(MANIFEST_DESCRIPTION) => Ownership::Ours,
        _ => Ownership::Foreign("manifest description does not match the Genkan marker".into()),
    }
}

/// The two locations a registration occupies, each judged once: the manifest
/// file and, on Windows, the key whose default value must name that file.
pub(super) struct ManifestSlots {
    pub(super) file: Slot,
    /// `None` for a directory registration, which has no key.
    pub(super) key: Option<Slot>,
}

pub(super) fn manifest_slots(reg: &Registration) -> ManifestSlots {
    let manifest_path = reg.manifest_path();
    ManifestSlots {
        file: file_slot(&manifest_path, manifest_ownership),
        key: match reg {
            Registration::ManifestDir(_) => None,
            Registration::Registry { hive, key, .. } => Some(registry_slot(*hive, key, "", |v| {
                same_windows_path(v, &manifest_path)
            })),
        },
    }
}

/// Diagnose one registration (read-only). This is what `doctor` prints per
/// browser and what decides whether `--fix` has anything to repair.
pub fn assess(reg: &Registration) -> RegState {
    let key_name = match reg {
        Registration::ManifestDir(_) => String::new(),
        Registration::Registry { hive, key, .. } => format!("{hive}\\{key}"),
    };
    classify(manifest_slots(reg), &key_name)
}

/// The state the two slots amount to. A Windows registration IS its key: Chromium selects the manifest
/// through the key alone, and the file sits in a store every browser's registration shares, so without
/// the key the browser has nothing here whatever the file holds (a key alone reads stale, a file alone
/// reads missing; `register` still judges the file before writing).
pub(super) fn classify(slots: ManifestSlots, key_name: &str) -> RegState {
    // A re-pointed or unreadable key must never be summarized as merely "missing".
    match &slots.key {
        Some(Slot::Foreign { why, .. }) => return RegState::Foreign(why.clone()),
        Some(Slot::Unreadable(why)) => return RegState::Unreadable(why.clone()),
        Some(Slot::Absent) => return RegState::Missing,
        Some(Slot::Ours(_)) | None => {}
    }
    let contents = match slots.file {
        Slot::Absent => {
            return match slots.key {
                Some(_) => RegState::Stale(format!(
                    "manifest file missing but registry key {key_name} present"
                )),
                None => RegState::Missing,
            };
        }
        Slot::Unreadable(why) => return RegState::Unreadable(why),
        Slot::Foreign { why, .. } => return RegState::Foreign(why),
        Slot::Ours(contents) => contents,
    };
    // Ours: the registration is healthy only if what it launches exists.
    let launch = serde_json::from_str::<serde_json::Value>(&contents)
        .ok()
        .and_then(|v| v.get("path").and_then(|p| p.as_str()).map(PathBuf::from));
    match launch {
        Some(p) if p.is_file() => RegState::Ok,
        Some(p) => RegState::Stale(format!("launch path missing: {}", p.display())),
        None => RegState::Stale("manifest has no launch path".into()),
    }
}

/// Whether Chromium's manifest lookup stops at this registration: on macOS and Linux an existence probe of
/// the per-user file that follows symlinks (a dangling link is skipped, a directory is not), on Windows a
/// string default value in the key ([`registry_lookup_hit`]). What `register` may write is a separate
/// question ([`Slot`]): a dangling link is refused there and skipped here.
pub fn lookup_hit(reg: &Registration) -> bool {
    match reg {
        Registration::ManifestDir(_) => reg.manifest_path().exists(),
        Registration::Registry { hive, key, .. } => {
            registry_lookup_hit(&registry_default_value(*hive, key))
        }
    }
}

/// Chromium's Windows lookup reads the key's default value alone and stops there whatever it holds (an
/// empty string is read, then rejected as a path, with no fall-through); it moves to the next hive only
/// when the key is missing or unreadable or has no default. Other values and their types play no part,
/// unlike in the ownership read ([`registry_key`]).
pub(super) fn registry_lookup_hit(default: &Result<Option<String>, String>) -> bool {
    matches!(default, Ok(Some(_)))
}
