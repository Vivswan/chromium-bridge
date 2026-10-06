//! Native-messaging registration: the write/repair/remove engine behind `doctor --fix` and `uninstall`; browser
//! locations come from [`crate::browsers`], the resolver `doctor`
//! diagnoses with. Fail closed: `uninstall` removes only files this project verifiably wrote, and `--fix` refuses an
//! entry it cannot read; a manifest another tool wrote at our host id is the one thing an explicit `--fix` replaces
//! (the rule, with the pointer's refusal, is on [`Slot`]). That keeps OUR tooling from destroying someone else's
//! registration but does not stop a same-user attacker who can write the user's config dirs directly (that boundary
//! is the IPC layer's).
//!
//! ```text
//! target         -> THIS binary (current_exe); nothing is built, downloaded, or copied, and repairing is idempotent
//!                   re-registration, so on a fresh machine `doctor --fix` IS the install
//! scope          -> one per command: the account's own locations, or with `--system` the root-owned ones every
//!                   account's browser reads (the .deb's post-install, which runs as root); the command's privilege
//!                   must match the scope ([`Privilege`]), so root never writes into a home and a user never into /etc
//! macOS / Linux  -> Chrome's manifest has no `args` field, so it launches a wrapper script: `run-host-<browser>.sh`
//!                   baking in `--native-host --label <browser>` when one browser alone launches that manifest (the
//!                   label rides the bridge handshake), or `run-host.sh` with no label when several browsers read
//!                   it; the rule is [`Target`]'s
//! Windows        -> Chrome appends the extension origin to the command line, which selects native-host mode, so the
//!                   manifest points straight at the binary and registration is an HKCU registry key; compiles but is
//!                   unverified on a real Windows machine (docs/cli.md)
//! pointer        -> beside the manifest, the external-extension pointer the browser reads on its next start and
//!                   answers with "Enable Chromium Bridge?" (macOS a file, Windows a key, Linux none: see
//!                   [`ExtensionPointer`]); removing it makes the browser drop the extension it installed from it
//! ```

use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::browsers::{
    self, BaseDirs, Browser, BrowserEntry, ExtensionPointer, Hive, Lookup, Os, Registration, Scope,
};
use crate::cli::{FixTargets, UninstallArgs};
use crate::identity::{NATIVE_HOST_ID, PINNED_EXTENSION_ID};
use serde::Serialize;

/// The `description` the legacy `install.sh` / `install.ps1` wrote, verbatim.
const MANIFEST_DESCRIPTION_LEGACY: &str = "Chromium Bridge native messaging host";

/// The `description` this engine writes: the ownership marker.
const MANIFEST_DESCRIPTION: &str =
    "Chromium Bridge native messaging host (managed by chromium-bridge)";

/// First line of every wrapper this project writes.
const WRAPPER_SHEBANG: &str = "#!/usr/bin/env bash";

/// The only update source Chrome accepts for an externally installed extension on macOS and Windows: the
/// Web Store, which serves the extension under [`PINNED_EXTENSION_ID`].
const WEB_STORE_UPDATE_URL: &str = "https://clients2.google.com/service/update2/crx";

/// The Windows pointer key's value name, the one Chrome's registry loader reads before any other.
const POINTER_VALUE_NAME: &str = "update_url";

/// Fuzz-only aliases of the two ownership markers and the Web Store url, for the
/// cargo-fuzz workspace's ownership oracles and seed generator (see the `fuzzing`
/// feature in Cargo.toml). Aliases of the real constants, so none can drift from
/// what this module actually writes; they stay private otherwise.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzz_api {
    pub const MANIFEST_DESCRIPTION: &str = super::MANIFEST_DESCRIPTION;
    pub const MANIFEST_DESCRIPTION_LEGACY: &str = super::MANIFEST_DESCRIPTION_LEGACY;
    pub const WEB_STORE_UPDATE_URL: &str = super::WEB_STORE_UPDATE_URL;
}

/// Everything the engine needs to lay a registration down. Paths are injected
/// so tests drive it against temp trees, never real browser dirs, and so the
/// app can point it at the same places the CLI does.
pub struct Registrar {
    /// The host binary every registration points at (resolved `current_exe`
    /// in the CLI; an explicit path in tests).
    pub host_exe: PathBuf,
    /// Where wrapper scripts live (Unix). Same directory the shell installer
    /// used, so re-registering over a legacy `install.sh` install converges.
    pub install_dir: PathBuf,
    pub scope: RegistrarScope,
    pub foreign: ForeignManifest,
    /// The extension ID trusted in `allowed_origins`.
    pub extension_id: String,
}

/// What `register` does with a manifest another tool wrote at our host id. Only the CLI's explicit
/// `--fix` replaces it: the extension's `registration_repair` frame is not presence-gated
/// (docs/security/trust-boundaries.md), so a repair it asks for keeps the refusal, or a compromised
/// extension could displace another host's registration with nobody at the keyboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForeignManifest {
    Replace,
    Refuse,
}

/// Whose registrations a [`Registrar`] writes: an account's own (the install dir private, 0700) or every
/// account's (0755, since other accounts' browsers traverse it), which alone needs the directory whose
/// reachability by every account is taken as given: `/` on a real machine, the fixture root in tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrarScope {
    User,
    System { root: PathBuf },
}

/// One registration to write or remove. The label rides the wrapper as `--label` so the broker files the
/// connection under that browser; it exists only when exactly one browser launches the manifest. An
/// explicit `--manifest-dir` cannot name its browser, and a directory several browsers read (Chrome's,
/// which Brave and Opera read) cannot either: a label there would file Brave's connection in Chrome's
/// slot and route a call aimed at Chrome to Brave, so those connections take the broker's default slot
/// instead.
pub struct Target {
    pub label: Option<Browser>,
    /// What reports call it: the browser key, or the location of an explicit dir.
    pub name: String,
    pub registration: Registration,
    /// The external-extension pointer of every browser launching this manifest, each prompting from its
    /// own; empty where none is written (Linux, and explicit dirs, whose browser we cannot name).
    pub pointers: Vec<ExtensionPointer>,
}

impl Target {
    /// The browser's target in one scope. A browser that reads another's directory
    /// ([`Lookup::ReadsFrom`]) yields the owner's target.
    pub fn for_browser(entry: &BrowserEntry, scope: Scope) -> Target {
        let pointers = entry
            .pointer
            .as_ref()
            .map(|p| p.get(scope).clone())
            .into_iter()
            .collect();
        match entry.manifest.get(scope) {
            Lookup::Own {
                registration,
                readers,
            } => Target {
                label: readers.is_empty().then_some(entry.browser),
                name: entry.browser.key().to_string(),
                registration: registration.clone(),
                pointers,
            },
            Lookup::ReadsFrom {
                owner,
                registration,
            } => Target {
                label: None,
                name: owner.key().to_string(),
                registration: registration.clone(),
                pointers,
            },
        }
    }

    pub fn for_explicit_dir(dir: &Path) -> Target {
        let registration = browsers::explicit_dir_registration(dir);
        Target {
            label: None,
            name: registration.location(),
            registration,
            pointers: Vec::new(),
        }
    }

    fn label(&self) -> Option<&'static str> {
        self.label.map(Browser::key)
    }
}

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

/// The pointer file's bytes, which the fuzz seeds take as the one accepted shape.
pub fn pointer_json() -> String {
    format!("{{\n  \"external_update_url\": \"{WEB_STORE_UPDATE_URL}\"\n}}\n")
}

/// What a location this engine may own holds, and the rule for each, in both directions. A manifest at
/// our host id that another tool wrote (`Foreign`): `doctor` reports it foreign, an explicit `--fix`
/// overwrites it and reports what it launched ([`ForeignManifest`]: the extension's repair does not),
/// `uninstall` never removes it. An entry nobody can verify
/// (`Unreadable`: a directory, a dangling link) is refused both ways. The extension pointer is refused
/// both ways when foreign: it is another installer's claim on the extension, not a manifest of ours to
/// repair.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Slot {
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
enum ForeignShape {
    Replaceable,
    Rooted,
}

impl Slot {
    /// `Ok` when `register` may write a pointer here; the refusal names `what`.
    fn writable(&self, what: &str) -> Result<(), String> {
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
    fn replaceable(&self, what: &str, foreign: ForeignManifest) -> Result<Option<String>, String> {
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
                "  replaced {what}, not written by chromium-bridge ({why}); it launched {}",
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
    fn removable(&self, what: &str) -> Result<bool, String> {
        match self {
            Slot::Absent => Ok(false),
            Slot::Ours(_) => Ok(true),
            Slot::Foreign { why, .. } => Err(format!(
                "refusing to remove {what}: {why}. Not written by chromium-bridge; remove it yourself if you are sure."
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

fn pointer_slot(pointer: &ExtensionPointer) -> Slot {
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
/// EXACTLY one of the two strings this project has ever written (the legacy
/// shell installers' and this engine's). Anything else -- unparsable, another
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
        Some(MANIFEST_DESCRIPTION_LEGACY) | Some(MANIFEST_DESCRIPTION) => Ownership::Ours,
        _ => Ownership::Foreign(
            "manifest description does not match any Chromium Bridge marker".into(),
        ),
    }
}

/// The two locations a registration occupies, each judged once: the manifest
/// file and, on Windows, the key whose default value must name that file.
struct ManifestSlots {
    file: Slot,
    /// `None` for a directory registration, which has no key.
    key: Option<Slot>,
}

fn manifest_slots(reg: &Registration) -> ManifestSlots {
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
fn classify(slots: ManifestSlots, key_name: &str) -> RegState {
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

impl Registrar {
    /// The JSON manifest for `launch_path` (the wrapper on Unix, the binary
    /// itself on Windows); the fuzz seeds take it as the accepted shape.
    pub fn manifest_json(&self, launch_path: &Path) -> Result<String, String> {
        let manifest = serde_json::json!({
            "name": NATIVE_HOST_ID,
            "description": MANIFEST_DESCRIPTION,
            "path": launch_path,
            "type": "stdio",
            "allowed_origins": [format!("chrome-extension://{}/", self.extension_id)],
        });
        // to_string_pretty on a json! literal cannot fail; propagate rather
        // than panic if serde_json ever finds a way.
        let mut text = serde_json::to_string_pretty(&manifest)
            .map_err(|e| format!("could not serialize the host manifest: {e}"))?;
        text.push('\n');
        Ok(text)
    }

    /// Wrapper script content: exec the host in native-host mode, optionally
    /// with the browser label.
    fn wrapper_script(&self, label: Option<&str>) -> String {
        let mut exec_line = format!(
            "exec {} --native-host",
            shell_quote(&self.host_exe.to_string_lossy())
        );
        if let Some(key) = label {
            exec_line.push_str(&format!(" --label {}", shell_quote(key)));
        }
        format!("{WRAPPER_SHEBANG}\n# managed by chromium-bridge; safe to delete\n{exec_line}\n")
    }

    fn wrapper_path(&self, label: Option<&str>) -> PathBuf {
        match label {
            Some(key) => self.install_dir.join(format!("run-host-{key}.sh")),
            None => self.install_dir.join("run-host.sh"),
        }
    }

    /// Write one registration. Returns the human report lines for stdout.
    /// Idempotent: re-running overwrites our own artifacts in place. Every
    /// slot the target occupies (manifest file, its Windows key, the pointer)
    /// is judged before the first write ([`Slot`]): an unreadable one or a
    /// foreign pointer fails the target with nothing changed, a foreign
    /// manifest is replaced and reported, or refused, per [`ForeignManifest`].
    pub fn register(&self, target: &Target) -> Result<Vec<String>, String> {
        // A registry registration is impossible from a non-Windows build;
        // refuse before writing anything at all.
        if let Registration::Registry { hive, key, .. } = &target.registration {
            registry_supported(*hive, key)?;
        }
        let manifest_path = target.registration.manifest_path();
        let slots = manifest_slots(&target.registration);
        // Every slot is judged before anything changes, so a refusal leaves the target as it was.
        let mut replaced = Vec::new();
        replaced.extend(slots.file.replaceable(
            &format!("manifest {}", manifest_path.display()),
            self.foreign,
        )?);
        let foreign_key = match (&slots.key, &target.registration) {
            (
                Some(key),
                Registration::Registry {
                    hive, key: name, ..
                },
            ) => key.replaceable(&format!("registry key {hive}\\{name}"), self.foreign)?,
            _ => None,
        };
        for pointer in &target.pointers {
            pointer_slot(pointer).writable(&format!("extension pointer {}", pointer.location()))?;
        }

        // Every directory before any file: a machine-wide refusal (a system directory other accounts
        // cannot traverse) leaves nothing written.
        let mut browser_dirs: Vec<&Path> = Vec::new();
        if let Registration::ManifestDir(dir) = &target.registration {
            browser_dirs.push(dir);
        }
        for path in target.pointers.iter().filter_map(|p| match p {
            ExtensionPointer::File(path) => Some(path),
            ExtensionPointer::Registry { .. } => None,
        }) {
            browser_dirs.push(
                path.parent()
                    .ok_or_else(|| format!("{} has no parent directory", path.display()))?,
            );
        }
        self.create_dirs(&browser_dirs)?;

        let mut lines = Vec::new();
        // What was done before a later step failed still reaches the report: the displaced launch path of
        // an overwritten foreign manifest must not be hidden by a pointer write that failed after it.
        let written: Result<(), String> = (|| {
            let launch_path = match &target.registration {
                Registration::ManifestDir(_) => {
                    // Unix: wrapper first, then the manifest that points at it.
                    let label = target.label();
                    let wrapper = self.wrapper_path(label);
                    write_atomic(&wrapper, self.wrapper_script(label).as_bytes(), true)
                        .map_err(|e| format!("could not write {}: {e}", wrapper.display()))?;
                    lines.push(format!(
                        "  launches {}{}",
                        wrapper.display(),
                        label.map(|k| format!(" (label: {k})")).unwrap_or_default()
                    ));
                    wrapper
                }
                Registration::Registry { .. } => {
                    // Windows: manifest in our own store dir, registry key points
                    // at it, binary launched directly (origin argv selects mode).
                    self.host_exe.clone()
                }
            };

            write_atomic(
                &manifest_path,
                self.manifest_json(&launch_path)?.as_bytes(),
                false,
            )
            .map_err(|e| format!("could not write {}: {e}", manifest_path.display()))?;
            lines.insert(
                0,
                format!(
                    "{}: manifest written to {}",
                    target.name,
                    manifest_path.display()
                ),
            );
            lines.extend(replaced);

            if let Registration::Registry { hive, key, .. } = &target.registration {
                if let Some(line) = foreign_key {
                    // Replaced whole, in the write phase: a key that kept the values that made it foreign
                    // would be refused by `uninstall`.
                    delete_registry_key(*hive, key)?;
                    lines.push(line);
                }
                set_registry_value(*hive, key, "", &manifest_path.to_string_lossy())?;
                lines.push(format!("  registry key {hive}\\{key}"));
            }
            for pointer in &target.pointers {
                match pointer {
                    ExtensionPointer::File(path) => {
                        write_atomic(path, pointer_json().as_bytes(), false)
                            .map_err(|e| format!("could not write {}: {e}", path.display()))?;
                    }
                    ExtensionPointer::Registry { hive, key } => {
                        set_registry_value(*hive, key, POINTER_VALUE_NAME, WEB_STORE_UPDATE_URL)?;
                    }
                }
                lines.push(format!("  extension pointer {}", pointer.location()));
            }
            Ok(())
        })();
        match written {
            Ok(()) => Ok(lines),
            Err(e) if lines.is_empty() => Err(e),
            Err(e) => Err(format!("{e}; already done: {}", lines.join("; "))),
        }
    }

    /// Machine-wide, every directory is judged before any is made, so a system directory other accounts
    /// cannot traverse, under whichever of them, refuses with nothing created; an account's own tree
    /// takes its umask. The wrapper dir is made first either way: a refused repair that left an empty
    /// browser directory would make an absent browser read as detected.
    fn create_dirs(&self, browser_dirs: &[&Path]) -> Result<(), String> {
        let could_not =
            |dir: &Path, e: std::io::Error| format!("could not create {}: {e}", dir.display());
        let RegistrarScope::System { root } = &self.scope else {
            self.ensure_install_dir()?;
            return browser_dirs
                .iter()
                .try_for_each(|dir| fs::create_dir_all(dir).map_err(|e| could_not(dir, e)));
        };
        let plan = |dir: &Path| plan_traversable_dirs(dir, root).map_err(|e| could_not(dir, e));
        let above_wrapper = match self.install_dir.parent() {
            Some(parent) => plan(parent)?,
            None => Vec::new(),
        };
        let mut under_browsers: Vec<PathBuf> = Vec::new();
        for dir in browser_dirs {
            for path in plan(dir)? {
                if !above_wrapper.contains(&path) && !under_browsers.contains(&path) {
                    under_browsers.push(path);
                }
            }
        }
        create_traversable_dirs(&above_wrapper)?;
        self.ensure_install_dir()?;
        create_traversable_dirs(&under_browsers)
    }

    /// The wrapper dir, with the scope's mode: private (0700) for an account's own, since only its browser
    /// reads it; 0755 machine-wide, since every account's browser must traverse a root-owned one. The
    /// symlink refusal is `fsguard`'s either way.
    fn ensure_install_dir(&self) -> Result<(), String> {
        let create = || -> std::io::Result<()> {
            crate::fsguard::ensure_private_dir(&self.install_dir)?;
            #[cfg(unix)]
            if matches!(self.scope, RegistrarScope::System { .. }) {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&self.install_dir, fs::Permissions::from_mode(0o755))?;
            }
            Ok(())
        };
        create().map_err(|e| format!("could not create {}: {e}", self.install_dir.display()))
    }

    /// Reverse one registration. Each slot (the Windows key, the manifest
    /// file, the pointer) is verified and then removed on its own, so a
    /// foreign or unreadable one is refused and left while the others of ours
    /// still go; a refusal never leaves an artifact of ours behind that the
    /// wrapper cleanup would then orphan. The browser drops the extension the
    /// pointer installed on its next start; an unpacked extension is untouched.
    pub fn uninstall(target: &Target) -> Removal {
        let mut removal = Removal::default();
        let manifest_path = target.registration.manifest_path();
        let slots = manifest_slots(&target.registration);

        if let (
            Some(key),
            Registration::Registry {
                hive, key: name, ..
            },
        ) = (&slots.key, &target.registration)
        {
            match key.removable(&format!("registry key {hive}\\{name}")) {
                Ok(true) => {
                    if let Err(e) = delete_registry_key(*hive, name) {
                        removal.failed.push(e);
                    }
                }
                Ok(false) => {}
                Err(e) => removal.refused.push(e),
            }
        }
        match slots.file.removable(&manifest_path.display().to_string()) {
            Ok(true) => match fs::remove_file(&manifest_path) {
                Ok(()) => removal.lines.push(format!(
                    "{}: removed manifest {}",
                    target.name,
                    manifest_path.display()
                )),
                Err(e) => removal
                    .failed
                    .push(format!("could not remove {}: {e}", manifest_path.display())),
            },
            Ok(false) => removal
                .lines
                .push(format!("{}: not registered", target.name)),
            Err(e) => removal.refused.push(e),
        }
        for pointer in &target.pointers {
            let what = format!("extension pointer {}", pointer.location());
            match pointer_slot(pointer).removable(&what) {
                Ok(false) => {}
                Ok(true) => {
                    let removed = match pointer {
                        ExtensionPointer::File(path) => fs::remove_file(path)
                            .map_err(|e| format!("could not remove {}: {e}", path.display())),
                        ExtensionPointer::Registry { hive, key } => delete_registry_key(*hive, key),
                    };
                    match removed {
                        Ok(()) => removal.lines.push(format!("  removed {what}")),
                        Err(e) => removal.failed.push(e),
                    }
                }
                Err(e) => removal.refused.push(e),
            }
        }
        removal
    }
}

/// What one removal did and left. A refusal is an artifact not verified as ours (foreign, or unreadable
/// to us), left in place as a warning: a package removal must complete over a manifest another tool
/// wrote at our id. A failure is an artifact verified as ours that could not be removed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Removal {
    pub lines: Vec<String>,
    pub refused: Vec<String>,
    pub failed: Vec<String>,
}

/// `uninstall`'s exit code over everything it removed: 1 only when a verified artifact of ours could not
/// be removed.
fn uninstall_exit_code(removals: &[Removal]) -> i32 {
    if removals.iter().any(|r| !r.failed.is_empty()) {
        1
    } else {
        0
    }
}

/// The directories missing for `dir` to exist, outermost first, once its existing ancestor passed the
/// reachability rule. Directories that already exist are not ours to loosen: one that other accounts
/// cannot traverse (a root-made 0700 `/etc/opt/chrome`) is refused here, before anything is created,
/// since a manifest under it would read healthy and be unreachable for every other account.
fn plan_traversable_dirs(dir: &Path, root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut missing = Vec::new();
    let mut cursor = dir;
    while !cursor.as_os_str().is_empty() && fs::symlink_metadata(cursor).is_err() {
        missing.push(cursor.to_path_buf());
        match cursor.parent() {
            Some(parent) => cursor = parent,
            None => break,
        }
    }
    traversable_by_every_account(cursor, root).map_err(std::io::Error::other)?;
    missing.reverse();
    Ok(missing)
}

/// Make the planned directories, each 0755 whatever the umask (a maintainer script may run under 077),
/// since other accounts' browsers read what sits under them.
fn create_traversable_dirs(planned: &[PathBuf]) -> Result<(), String> {
    for path in planned {
        let could_not = |e: std::io::Error| format!("could not create {}: {e}", path.display());
        fs::create_dir(path).map_err(could_not)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(could_not)?;
        }
    }
    Ok(())
}

/// Split one line of wrapper shell into its literal tokens. Understands only
/// what our generators ever emit: bare words, backslash escapes, and
/// single-quoted segments. Any construct with evaluation semantics in an
/// unquoted context (`$`, backticks, `;`, `&`, `|`, parens, redirection,
/// double quotes) returns `None`: the line is not shell-literal, so it cannot
/// be one of ours.
fn split_shell_literal(line: &str) -> Option<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_token = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_token = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(ch) => current.push(ch),
                        None => return None, // unterminated quote
                    }
                }
            }
            '\\' => {
                in_token = true;
                current.push(chars.next()?);
            }
            // Evaluation semantics (substitution, control operators,
            // redirection) and word expansion (glob, brace, tilde, history):
            // any of these unquoted means the line is not shell-literal.
            '$' | '`' | ';' | '&' | '|' | '(' | ')' | '<' | '>' | '"' | '*' | '?' | '[' | ']'
            | '{' | '}' | '~' | '!' => return None,
            c if c.is_whitespace() => {
                if in_token {
                    tokens.push(std::mem::take(&mut current));
                    in_token = false;
                }
            }
            c => {
                in_token = true;
                current.push(c);
            }
        }
    }
    if in_token {
        tokens.push(current);
    }
    Some(tokens)
}

/// Whether wrapper-script `contents` are something this project wrote: the
/// bash shebang, optionally comment/blank lines, and exactly ONE payload
/// line whose literal tokens are exactly
/// `exec <path> --native-host [--label <valid-label>]` -- the trampoline
/// shape this engine generates, and nothing that does more than launch the host.
fn wrapper_is_ours(contents: &str) -> bool {
    let mut lines = contents.lines();
    if lines.next() != Some(WRAPPER_SHEBANG) {
        return false;
    }
    let mut seen_trampoline = false;
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some(tokens) = split_shell_literal(trimmed) else {
            return false;
        };
        let is_trampoline = match tokens.as_slice() {
            [exec, _path, flag] => exec == "exec" && flag == "--native-host",
            [exec, _path, flag, label_flag, label] => {
                exec == "exec"
                    && flag == "--native-host"
                    && label_flag == "--label"
                    && crate::ipc::validate_label(label)
            }
            _ => false,
        };
        if !is_trampoline || seen_trampoline {
            return false;
        }
        seen_trampoline = true;
    }
    seen_trampoline
}

/// Remove the wrapper scripts this engine writes (exact, project-unique names
/// only), each verified by [`wrapper_is_ours`] before deletion.
pub fn remove_wrappers(install_dir: &Path) -> Removal {
    let mut removal = Removal::default();
    let mut names = vec!["run-host.sh".to_string()];
    names.extend(
        Browser::ALL
            .iter()
            .map(|b| format!("run-host-{}.sh", b.key())),
    );
    for name in names {
        let path = install_dir.join(name);
        let contents = match fs::read_to_string(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                removal.refused.push(format!(
                    "could not read {}: {e} (left in place)",
                    path.display()
                ));
                continue;
            }
            Ok(c) => c,
        };
        if wrapper_is_ours(&contents) {
            match fs::remove_file(&path) {
                Ok(()) => removal
                    .lines
                    .push(format!("removed wrapper {}", path.display())),
                Err(e) => removal
                    .failed
                    .push(format!("could not remove {}: {e}", path.display())),
            }
        } else {
            removal.refused.push(format!(
                "refusing to remove {}: not a chromium-bridge wrapper (left in place)",
                path.display()
            ));
        }
    }
    // Drop the dir only when now empty; remove_dir never deletes contents.
    let _ = fs::remove_dir(install_dir);
    removal
}

/// `doctor --fix`: [`fix`] with its report printed. Returns the process exit
/// code: [`NOTHING_TO_REGISTER`] when detection found no browser, 1 when the
/// repair could not start for any other reason or any target failed.
pub fn run_fix(targets: &FixTargets, scope: Scope) -> i32 {
    let outcomes = match fix(targets, scope, ForeignManifest::Replace) {
        Ok(outcomes) => outcomes,
        Err(e) => {
            let code = fix_exit_code(&e);
            if code == NOTHING_TO_REGISTER {
                log_warn!("doctor", "{}", cli_guidance(&e, scope));
            } else {
                log_error!("doctor", "{}", cli_guidance(&e, scope));
            }
            return code;
        }
    };
    println!("chromium-bridge doctor --fix (host id {NATIVE_HOST_ID})");
    // The failure count only feeds the exit message, so clamping on
    // (unreachable) overflow is fine.
    let mut failures: usize = 0;
    for outcome in &outcomes {
        match &outcome.result {
            Ok(lines) => {
                for line in lines {
                    println!("{line}");
                }
            }
            Err(e) => {
                log_error!("doctor", "{}: {e}", outcome.target);
                failures = failures.saturating_add(1);
            }
        }
    }
    println!("allowed origin: chrome-extension://{PINNED_EXTENSION_ID}/");
    println!(
        "next: restart the browser so it re-reads its registrations. Until the extension's Web Store\n\
         listing is published, load the extension unpacked (chrome://extensions, Developer mode:\n\
         extension/dist from the release archive, build/extension/chrome-mv3 from a source build);\n\
         once it is, browsers registered by name on macOS and Windows offer to enable Chromium\n\
         Bridge (no pointer is written on Linux or for --manifest-dir). Re-check with\n\
         `chromium-bridge doctor`."
    );
    if failures > 0 {
        log_error!("doctor", "{failures} target(s) failed; see above");
        1
    } else {
        0
    }
}

/// `doctor --fix`'s exit code when nothing was detected to register: distinct from a failure (1) so the
/// .deb's post-install can treat a machine with no browser yet as a valid install, and not clap's 2 (a
/// usage error), which that script must not swallow.
pub const NOTHING_TO_REGISTER: i32 = 3;

/// The exit code for a repair that could not start.
fn fix_exit_code(error: &FixError) -> i32 {
    match error {
        FixError::NoTargets(_) => NOTHING_TO_REGISTER,
        FixError::Environment(_)
        | FixError::Privilege(_)
        | FixError::HostExe(_)
        | FixError::Unlaunchable(_) => 1,
    }
}

/// The CLI's rendering of a refusal: the host's reason, which the options page
/// shows as is, plus the flags a terminal can act on in this scope.
pub fn cli_guidance(error: &FixError, scope: Scope) -> String {
    match error {
        FixError::NoTargets(reason) => {
            // `--manifest-dir` names a per-user directory, so `--system` conflicts with it at the argv
            // boundary; offering it here would send the user into a usage error.
            let flags = match scope {
                Scope::User => "--browser <keys>, --all, or --manifest-dir <dir>",
                Scope::System => "--browser <keys> or --all",
            };
            format!("{reason}; or pass {flags}")
        }
        FixError::Environment(_)
        | FixError::Privilege(_)
        | FixError::HostExe(_)
        | FixError::Unlaunchable(_) => error.to_string(),
    }
}

/// Why a repair could not start. Every variant is decided before the first
/// manifest write, so an `Err` left every registration as it was.
#[derive(Debug)]
pub enum FixError {
    /// The platform's home variable is missing or not absolute.
    Environment(String),
    /// The process's privilege does not match the scope ([`Privilege::admit`]).
    Privilege(String),
    /// The targeting mode resolved to no browser; the message carries the
    /// guidance the CLI prints.
    NoTargets(String),
    /// This binary's own path could not be resolved.
    HostExe(std::io::Error),
    /// A machine-wide registration would point at a binary other accounts cannot launch
    /// ([`launchable_by_every_account`]).
    Unlaunchable(String),
}

impl fmt::Display for FixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FixError::Environment(e) | FixError::Privilege(e) | FixError::NoTargets(e) => {
                f.write_str(e)
            }
            FixError::HostExe(e) => write!(f, "cannot resolve this binary's path: {e}"),
            FixError::Unlaunchable(why) => f.write_str(why),
        }
    }
}

/// One target's registration: the engine's report lines on success, its
/// refusal otherwise. Per-target failures travel here, not as the seam's
/// `Err`, so one broken browser never hides the others' results.
#[derive(Debug)]
pub struct TargetOutcome {
    /// The browser key, or the manifest path of an explicit `--manifest-dir`
    /// target.
    pub target: String,
    pub result: Result<Vec<String>, String>,
}

/// The repair `doctor --fix` runs, with nothing printed: admit the scope,
/// resolve the environment and the targets, then register each. Idempotent,
/// so a fresh machine gets its first registration and a broken one its repair
/// through this one path. `run_fix` prints the outcomes for the CLI; the
/// native host logs them when the extension asks for a repair, since stdout
/// is its protocol. Diagnostics (the ephemeral-path warning) still go to the log.
pub fn fix(
    targets: &FixTargets,
    scope: Scope,
    foreign: ForeignManifest,
) -> Result<Vec<TargetOutcome>, FixError> {
    Privilege::current()
        .admit(scope)
        .map_err(FixError::Privilege)?;
    let dirs = BaseDirs::from_env(scope).map_err(FixError::Environment)?;
    let os = Os::current();
    let entries = browsers::resolve(os, &dirs);
    let targets = select_targets(targets, &entries, scope)?;
    let host_exe = resolve_host_exe().map_err(FixError::HostExe)?;
    if scope == Scope::System {
        launchable_by_every_account(&host_exe, &dirs.system_root)
            .map_err(FixError::Unlaunchable)?;
    }
    let registrar = Registrar {
        host_exe,
        install_dir: browsers::install_dir(os, &dirs, scope),
        scope: match scope {
            Scope::User => RegistrarScope::User,
            Scope::System => RegistrarScope::System {
                root: dirs.system_root.clone(),
            },
        },
        foreign,
        extension_id: PINNED_EXTENSION_ID.to_string(),
    };
    Ok(targets
        .iter()
        .map(|target| TargetOutcome {
            target: target.name.clone(),
            result: registrar.register(target),
        })
        .collect())
}

/// `chromium-bridge uninstall`: entry point. Removes the registrations of one
/// scope for every known browser plus any re-passed `--manifest-dir`, and the
/// wrapper scripts -- exactly what this project writes, nothing else. The
/// binary, the browser, and the loaded extension are never touched.
pub fn run_uninstall(args: &UninstallArgs) -> i32 {
    if let Err(e) = Privilege::current().admit(args.scope) {
        log_error!("uninstall", "{e}");
        return 1;
    }
    let (os, dirs) = match resolve_env(args.scope) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let entries = browsers::resolve(os, &dirs);

    let mut targets = browser_targets(entries.iter(), args.scope);
    for dir in &args.manifest_dirs {
        targets.push(Target::for_explicit_dir(dir));
    }

    println!("chromium-bridge uninstall (host id {NATIVE_HOST_ID})");
    let mut removals: Vec<Removal> = targets
        .iter()
        .map(|target| {
            let removal = Registrar::uninstall(target);
            for line in &removal.lines {
                println!("{line}");
            }
            for e in &removal.refused {
                log_warn!("uninstall", "{}: {e}", target.name);
            }
            for e in &removal.failed {
                log_error!("uninstall", "{}: {e}", target.name);
            }
            removal
        })
        .collect();
    let wrappers = remove_wrappers(&browsers::install_dir(os, &dirs, args.scope));
    for line in &wrappers.lines {
        println!("{line}");
    }
    for e in &wrappers.refused {
        log_warn!("uninstall", "{e}");
    }
    for e in &wrappers.failed {
        log_error!("uninstall", "{e}");
    }
    removals.push(wrappers);
    println!(
        "left untouched: this binary and your browsers. A browser drops the extension its pointer\n\
         installed on its next start; remove an unpacked extension yourself via chrome://extensions."
    );
    uninstall_exit_code(&removals)
}

/// Shared CLI preamble: pick the OS layout and read the base dirs, failing
/// closed (exit 1) when a per-user command's environment cannot name a home directory.
pub(crate) fn resolve_env(scope: Scope) -> Result<(Os, BaseDirs), i32> {
    match BaseDirs::from_env(scope) {
        Ok(dirs) => Ok((Os::current(), dirs)),
        Err(e) => {
            log_error!("doctor", "{e}");
            Err(1)
        }
    }
}

/// Whether every account can launch `exe`: the file readable and executable by others, and each
/// directory from it up to (not including) `root` traversable by them. A machine-wide registration that
/// points into one account's home (`sudo ~/.local/lib/chromium-bridge/chromium-bridge doctor --fix
/// --system`) reads healthy and fails for everyone else at launch, so it is refused before any write.
/// `root` is the directory whose reachability is the caller's premise: `/` for a real install, the
/// fixture root in tests. Windows ACLs are not inspected (residual: the .msi installs per user).
fn launchable_by_every_account(exe: &Path, root: &Path) -> Result<(), String> {
    if unix_mode(exe)? & 0o005 != 0o005 {
        return Err(format!(
            "{} is not readable and executable by other accounts, so a machine-wide registration \
             would fail for them; install the binary under /usr/local/bin, or drop --system",
            exe.display()
        ));
    }
    match exe.parent() {
        Some(dir) => traversable_by_every_account(dir, root),
        None => Ok(()),
    }
}

/// Whether other accounts can traverse `dir` and every directory above it, up to (not including) `root`.
fn traversable_by_every_account(dir: &Path, root: &Path) -> Result<(), String> {
    for dir in dir.ancestors().take_while(|d| *d != root) {
        if unix_mode(dir)? & 0o001 == 0 {
            return Err(format!(
                "{} is not traversable by other accounts, so their browsers cannot reach what sits \
                 under it; fix its mode, or drop --system",
                dir.display()
            ));
        }
    }
    Ok(())
}

/// The Unix permission bits of `path`; off Unix every bit reads set, so the reachability checks pass
/// (Windows ACLs are not inspected: a residual, the .msi installs per user).
fn unix_mode(path: &Path) -> Result<u32, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o777)
            .map_err(|e| format!("cannot inspect {}: {e}", path.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(0o777)
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
fn registry_lookup_hit(default: &Result<Option<String>, String>) -> bool {
    matches!(default, Ok(Some(_)))
}

/// Resolve and sanity-check the path registrations will launch. An ephemeral
/// path (AppImage FUSE mount, temp dir) gets a loud warning: the manifest
/// would dangle after exit, so the binary should be copied somewhere stable
/// first (docs/cli.md shows the Linux AppImage recipe).
fn resolve_host_exe() -> std::io::Result<PathBuf> {
    let exe = std::env::current_exe()?.canonicalize()?;
    let looks_ephemeral = exe.starts_with(std::env::temp_dir())
        || exe
            .components()
            .any(|c| c.as_os_str().to_string_lossy().starts_with(".mount_"));
    if looks_ephemeral {
        log_warn!(
            "doctor",
            "this binary runs from an ephemeral path ({}); the registration will break \
             when it disappears. Copy the binary to a stable location (e.g. \
             ~/.local/lib/chromium-bridge/) and run `doctor --fix` from there.",
            exe.display()
        );
    }
    Ok(exe)
}

/// Who runs the command, read once per command. Unix root is a different account from the one whose
/// browser is to be registered (its HOME is `/root`, or a sudo caller's with root as owner), with no browser
/// of its own; a Windows elevated token is the same account with HKLM writable as well.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privilege {
    User,
    Root,
    Elevated,
}

impl Privilege {
    #[cfg(unix)]
    pub fn current() -> Privilege {
        if nix::unistd::geteuid().is_root() {
            Privilege::Root
        } else {
            Privilege::User
        }
    }

    /// Elevation is judged by the capability the scope needs: a handle on HKLM with write access, which UAC's
    /// filtered token is refused. Any failure to open it reads as not elevated, so the check fails closed.
    #[cfg(windows)]
    pub fn current() -> Privilege {
        use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_SET_VALUE};
        match winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey_with_flags("SOFTWARE", KEY_SET_VALUE)
        {
            Ok(_) => Privilege::Elevated,
            Err(_) => Privilege::User,
        }
    }

    /// Whether this privilege may write `scope`, with the refusal that names the way out. Both mismatches
    /// fail closed: a user cannot write the system directories, and root must not write into a home (the
    /// macOS .pkg's post-install mirrors this by refusing to run `doctor --fix` as root).
    pub fn admit(self, scope: Scope) -> Result<(), String> {
        match (self, scope) {
            (Privilege::User, Scope::User)
            | (Privilege::Root, Scope::System)
            | (Privilege::Elevated, Scope::User | Scope::System) => Ok(()),
            (Privilege::User, Scope::System) => Err(
                "--system writes the root-owned directories every account's browser reads; run it as \
                 root (sudo), or drop --system to register for this account"
                    .into(),
            ),
            (Privilege::Root, Scope::User) => Err(
                "running as root, which has no browser of its own: pass --system for the machine-wide \
                 registration, or run this as the account whose browser it is"
                    .into(),
            ),
        }
    }
}

/// The targets of one scope for these browsers, each registration once: browsers that read another's
/// directory resolve to the owner's target ([`Target::for_browser`]), so Chrome and Brave together yield
/// Chrome's manifest once rather than two writes of the same file with different labels, and that one
/// target carries both browsers' pointers, since each prompts from its own. The registration, not the
/// manifest path, is the identity: on Windows every browser's manifest sits in the one store file while
/// each has its own key.
fn browser_targets<'a>(
    entries: impl Iterator<Item = &'a BrowserEntry>,
    scope: Scope,
) -> Vec<Target> {
    let mut out: Vec<Target> = Vec::new();
    for entry in entries {
        let target = Target::for_browser(entry, scope);
        match out
            .iter_mut()
            .find(|t| t.registration == target.registration)
        {
            Some(shared) => {
                for pointer in target.pointers {
                    if !shared.pointers.contains(&pointer) {
                        shared.pointers.push(pointer);
                    }
                }
            }
            None => out.push(target),
        }
    }
    out
}

/// Resolve the typed `--fix` targeting mode into concrete targets. Unknown
/// `--browser` keys were already refused at the argv boundary
/// ([`crate::cli::parse`] resolves them into [`Browser`]s), so the match
/// here is exhaustive, with no priority chain to order wrongly.
fn select_targets(
    targets: &FixTargets,
    entries: &[BrowserEntry],
    scope: Scope,
) -> Result<Vec<Target>, FixError> {
    match targets {
        FixTargets::ManifestDirs(dirs) => Ok(dirs
            .iter()
            .map(|dir| Target::for_explicit_dir(dir))
            .collect()),
        FixTargets::All => Ok(browser_targets(entries.iter(), scope)),
        FixTargets::Browsers(browsers) => {
            let mut selected = Vec::new();
            for browser in browsers {
                let Some(entry) = entries.iter().find(|e| e.browser == *browser) else {
                    // resolve() enumerates every Browser variant, so this
                    // cannot be reached; refuse with a typed error rather than
                    // panic if that invariant is ever broken.
                    return Err(FixError::NoTargets(format!(
                        "browser {:?} missing from the resolved set",
                        browser.key()
                    )));
                };
                selected.push(entry);
            }
            Ok(browser_targets(selected.into_iter(), scope))
        }
        FixTargets::Detected => {
            let detected = browser_targets(entries.iter().filter(|e| e.detected(scope)), scope);
            if detected.is_empty() {
                // Read on two surfaces: the CLI (which appends its flags, see cli_guidance) and the
                // extension's options page, so no flag belongs here.
                return Err(FixError::NoTargets(format!(
                    "no Chromium-family browser detected (looked for {}): install Chrome, Brave or \
                     Edge and open it once, then repair again",
                    known_keys()
                )));
            }
            Ok(detected)
        }
    }
}

pub(crate) fn known_keys() -> String {
    Browser::ALL
        .iter()
        .map(|b| b.key())
        .collect::<Vec<_>>()
        .join(",")
}

/// Quote `s` for safe inclusion in the wrapper's bash `exec` line: wrapped in
/// single quotes, embedded single quotes escaped as `'\''`.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Write `bytes` to `path` atomically: a uniquely named temp file is created
/// exclusively beside it (so a planted entry is never adopted or followed),
/// given its mode, fsynced, and renamed over the destination; the directory
/// is then fsynced so the entry survives a crash. The final path is replaced,
/// never written through: rename replaces even a symlink at the final
/// component without following it. On any failure the temp file is removed.
fn write_atomic(path: &Path, bytes: &[u8], executable: bool) -> std::io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("target path has no parent directory"))?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if executable { 0o755 } else { 0o644 };
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = executable;
    tmp.as_file().sync_all()?;
    tmp.persist(path)?;
    // Directories cannot be fsynced on Windows.
    #[cfg(unix)]
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}

// ---- Windows registry (compiles cross-OS; the real reads and writes are cfg(windows)).
// The non-Windows stubs fail closed: a registry registration or pointer cannot be
// performed or observed from a Unix build.

/// Whether registry `v` names our manifest. Windows paths are case-insensitive and accept either
/// separator; we wrote the value ourselves, but normalize before comparing so a round-tripped
/// registration is never misreported as re-pointed.
fn same_windows_path(v: &str, manifest_path: &Path) -> bool {
    let normalize = |p: &str| p.replace('/', "\\").to_ascii_lowercase();
    normalize(v) == normalize(&manifest_path.to_string_lossy())
}

#[cfg(windows)]
fn registry_supported(_hive: Hive, _key: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(not(windows))]
fn registry_supported(hive: Hive, key: &str) -> Result<(), String> {
    Err(format!(
        "registry registration ({hive}\\{key}) requires a Windows build of chromium-bridge"
    ))
}

#[cfg(windows)]
fn hive_root(hive: Hive) -> winreg::RegKey {
    winreg::RegKey::predef(match hive {
        Hive::CurrentUser => winreg::enums::HKEY_CURRENT_USER,
        Hive::LocalMachine => winreg::enums::HKEY_LOCAL_MACHINE,
    })
}

/// One registry key, read whole so ownership is judged on all of it.
struct RegistryKey {
    /// Every value as (name, text), `""` naming the default value.
    values: Vec<(String, String)>,
    /// How many child keys hang under it.
    children: u32,
}

/// `<hive>\{key}` whole, or `None` when the key is absent. This engine writes
/// REG_SZ alone, so a value of any other type was never ours: it reads as its
/// type name in place of a text, which the ownership judgment calls foreign (a
/// shape an explicit `--fix` replaces whole), never as an error.
#[cfg(windows)]
fn registry_key(hive: Hive, key: &str) -> Result<Option<RegistryKey>, String> {
    use winreg::types::FromRegValue;
    let subkey = match hive_root(hive).open_subkey(key) {
        Ok(k) => k,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let mut values = Vec::new();
    for entry in subkey.enum_values() {
        let (name, value) = entry.map_err(|e| format!("could not list its values: {e}"))?;
        let text = if value.vtype == winreg::enums::RegType::REG_SZ {
            String::from_reg_value(&value)
                .map_err(|e| format!("value {name:?} is not readable text: {e}"))?
        } else {
            format!("<{:?}>", value.vtype)
        };
        values.push((name, text));
    }
    let children = subkey
        .query_info()
        .map_err(|e| format!("could not count its child keys: {e}"))?
        .sub_keys;
    Ok(Some(RegistryKey { values, children }))
}

#[cfg(not(windows))]
fn registry_key(_hive: Hive, _key: &str) -> Result<Option<RegistryKey>, String> {
    Err("registry access requires a Windows build of chromium-bridge".into())
}

/// The key's default value as the browser reads it: opened with the one right Chromium asks for
/// (KEY_QUERY_VALUE, so an ACL that denies enumeration does not hide a value the browser can read), and
/// `None` when the key or the value is absent or the value is of a type Chromium's string read refuses
/// (anything but REG_SZ and REG_EXPAND_SZ, REG_MULTI_SZ included, which winreg's String read would accept).
#[cfg(windows)]
fn registry_default_value(hive: Hive, key: &str) -> Result<Option<String>, String> {
    use winreg::enums::{RegType, KEY_QUERY_VALUE};
    use winreg::types::FromRegValue;
    let subkey = match hive_root(hive).open_subkey_with_flags(key, KEY_QUERY_VALUE) {
        Ok(k) => k,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let raw = match subkey.get_raw_value("") {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    if raw.vtype != RegType::REG_SZ && raw.vtype != RegType::REG_EXPAND_SZ {
        return Ok(None);
    }
    String::from_reg_value(&raw)
        .map(Some)
        .map_err(|e| e.to_string())
}

#[cfg(not(windows))]
fn registry_default_value(_hive: Hive, _key: &str) -> Result<Option<String>, String> {
    Err("registry access requires a Windows build of chromium-bridge".into())
}

#[cfg(windows)]
fn set_registry_value(hive: Hive, key: &str, name: &str, value: &str) -> Result<(), String> {
    let (subkey, _) = hive_root(hive)
        .create_subkey(key)
        .map_err(|e| format!("could not create {hive}\\{key}: {e}"))?;
    subkey
        .set_value(name, &value)
        .map_err(|e| format!("could not set {hive}\\{key}: {e}"))
}

#[cfg(not(windows))]
fn set_registry_value(hive: Hive, key: &str, _name: &str, _value: &str) -> Result<(), String> {
    Err(format!(
        "registry registration ({hive}\\{key}) requires a Windows build of chromium-bridge"
    ))
}

/// Delete `<hive>\{key}` once its slot was judged ours. delete_subkey (not _all):
/// our keys have no children, and failing on an unexpected child is the
/// fail-closed behavior we want.
#[cfg(windows)]
fn delete_registry_key(hive: Hive, key: &str) -> Result<(), String> {
    match hive_root(hive).delete_subkey(key) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("could not delete {hive}\\{key}: {e}")),
    }
}

#[cfg(not(windows))]
fn delete_registry_key(hive: Hive, key: &str) -> Result<(), String> {
    Err(format!(
        "registry removal ({hive}\\{key}) requires a Windows build of chromium-bridge"
    ))
}

#[cfg(test)]
mod tests;
