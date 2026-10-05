//! Native-messaging registration: the write/repair/remove engine behind `doctor --fix` and `uninstall`; browser
//! locations come from [`crate::browsers`], the resolver `doctor`
//! diagnoses with. Fail closed: `uninstall` removes only files this project verifiably wrote and `--fix` refuses to
//! overwrite a manifest it cannot verify as ours (reported and left in place), which keeps OUR tooling from destroying
//! someone else's registration but does not stop a same-user attacker who can write the user's config dirs directly
//! (that boundary is the IPC layer's).
//!
//! ```text
//! target         -> THIS binary (current_exe); nothing is built, downloaded, or copied, and repairing is idempotent
//!                   re-registration, so on a fresh machine `doctor --fix` IS the install
//! macOS / Linux  -> Chrome's manifest has no `args` field, so each browser gets a wrapper script baking in
//!                   `--native-host --label <browser>` (the label rides the bridge handshake)
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

use crate::browsers::{self, BaseDirs, Browser, BrowserEntry, ExtensionPointer, Os, Registration};
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

/// Fuzz-only aliases of the two ownership markers and the manifest writer, for the
/// cargo-fuzz workspace's [`manifest_ownership`] oracle and seed generator (see the
/// `fuzzing` feature in Cargo.toml). Aliases of the real items, so neither can drift
/// from what this module actually writes; they stay private otherwise.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzz_api {
    pub const MANIFEST_DESCRIPTION: &str = super::MANIFEST_DESCRIPTION;
    pub const MANIFEST_DESCRIPTION_LEGACY: &str = super::MANIFEST_DESCRIPTION_LEGACY;
    pub const WEB_STORE_UPDATE_URL: &str = super::WEB_STORE_UPDATE_URL;

    pub fn pointer_json() -> String {
        super::pointer_json()
    }

    pub fn manifest_json(
        registrar: &super::Registrar,
        launch_path: &std::path::Path,
    ) -> Result<String, String> {
        registrar.manifest_json(launch_path)
    }
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
    /// The extension ID trusted in `allowed_origins`.
    pub extension_id: String,
}

/// One registration to write or remove: a known browser (labeled) or an
/// explicit `--manifest-dir` (unlabeled).
pub struct Target {
    /// The browser whose key is baked into the wrapper as `--label`; `None`
    /// for explicit dirs, whose browser we cannot name.
    pub browser: Option<Browser>,
    pub registration: Registration,
    /// The browser's external-extension pointer; `None` where none is written
    /// (Linux, and explicit dirs, whose browser we cannot name).
    pub pointer: Option<ExtensionPointer>,
}

impl Target {
    pub fn for_browser(entry: &BrowserEntry) -> Target {
        Target {
            browser: Some(entry.browser),
            registration: entry.registration.clone(),
            pointer: entry.pointer.clone(),
        }
    }

    pub fn for_explicit_dir(dir: &Path) -> Target {
        Target {
            browser: None,
            registration: browsers::explicit_dir_registration(dir),
            pointer: None,
        }
    }

    fn label(&self) -> Option<&'static str> {
        self.browser.map(Browser::key)
    }

    fn describe(&self) -> String {
        match self.browser {
            Some(b) => b.key().to_string(),
            None => self.registration.location(),
        }
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

fn pointer_json() -> String {
    format!("{{\n  \"external_update_url\": \"{WEB_STORE_UPDATE_URL}\"\n}}\n")
}

/// What a location this engine may own holds. `register` writes only into
/// `Absent` or `Ours`, `uninstall` deletes only `Ours`; the other two are
/// reported and left in place, whichever command met them.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Slot {
    Absent,
    /// Ours, with what was read (the file's bytes, or the key's value).
    Ours(String),
    Foreign(String),
    Unreadable(String),
}

impl Slot {
    /// `Ok` when `register` may write here; the refusal names `what`.
    fn writable(&self, what: &str) -> Result<(), String> {
        match self {
            Slot::Absent | Slot::Ours(_) => Ok(()),
            Slot::Foreign(why) => Err(format!(
                "refusing to overwrite {what}: {why}. Inspect and remove it yourself if it is stale."
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
            Slot::Foreign(why) => Err(format!(
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
            Ownership::Foreign(why) => Slot::Foreign(why),
        },
    }
}

/// A registry key this engine may own holds exactly one REG_SZ value, the one
/// it wrote, and no child key; `expected` judges that value. Any other shape
/// is someone else's key.
fn registry_slot(key: &str, name: &str, expected: impl Fn(&str) -> bool) -> Slot {
    match registry_key(key) {
        Err(why) => Slot::Unreadable(format!("registry key HKCU\\{key}: {why}")),
        Ok(None) => Slot::Absent,
        Ok(Some(RegistryKey { children, .. })) if children > 0 => Slot::Foreign(format!(
            "registry key HKCU\\{key} carries child keys this project never writes"
        )),
        Ok(Some(RegistryKey { values, .. })) => match values.as_slice() {
            [(only, value)] if only == name && expected(value) => Slot::Ours(value.clone()),
            [(only, value)] if only == name => Slot::Foreign(format!(
                "registry key HKCU\\{key} points at {value:?}, not ours"
            )),
            _ => Slot::Foreign(format!(
                "registry key HKCU\\{key} carries values this project never writes"
            )),
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
        ExtensionPointer::Registry { key } => {
            registry_slot(key, POINTER_VALUE_NAME, |url| url == WEB_STORE_UPDATE_URL)
        }
    }
}

pub fn assess_pointer(pointer: &ExtensionPointer) -> PointerState {
    match pointer_slot(pointer) {
        Slot::Absent => PointerState::Missing,
        Slot::Ours(_) => PointerState::Ok,
        Slot::Foreign(why) => PointerState::Foreign(why),
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
            Registration::Registry { key, .. } => Some(registry_slot(key, "", |v| {
                same_windows_path(v, &manifest_path)
            })),
        },
    }
}

/// Diagnose one registration (read-only). This is what `doctor` prints per
/// browser and what decides whether `--fix` has anything to repair.
pub fn assess(reg: &Registration) -> RegState {
    let slots = manifest_slots(reg);
    let key_name = match reg {
        Registration::ManifestDir(_) => "",
        Registration::Registry { key, .. } => key.as_str(),
    };
    // On Windows the key is half the registration: a surviving key must be
    // reported even when the manifest file is gone, and a re-pointed or
    // unreadable key must never be summarized as merely "missing".
    match &slots.key {
        Some(Slot::Foreign(why)) => return RegState::Foreign(why.clone()),
        Some(Slot::Unreadable(why)) => return RegState::Unreadable(why.clone()),
        Some(Slot::Absent | Slot::Ours(_)) | None => {}
    }
    let contents = match slots.file {
        Slot::Absent => {
            return match slots.key {
                Some(Slot::Ours(_)) => RegState::Stale(format!(
                    "manifest file missing but registry key HKCU\\{key_name} present"
                )),
                _ => RegState::Missing,
            };
        }
        Slot::Unreadable(why) => return RegState::Unreadable(why),
        Slot::Foreign(why) => return RegState::Foreign(why),
        Slot::Ours(contents) => contents,
    };
    // Ours: the registration is healthy only if what it launches exists.
    let launch = serde_json::from_str::<serde_json::Value>(&contents)
        .ok()
        .and_then(|v| v.get("path").and_then(|p| p.as_str()).map(PathBuf::from));
    match launch {
        Some(p) if p.is_file() => {}
        Some(p) => return RegState::Stale(format!("launch path missing: {}", p.display())),
        None => return RegState::Stale("manifest has no launch path".into()),
    }
    if let Some(Slot::Absent) = slots.key {
        return RegState::Stale(format!("registry key HKCU\\{key_name} missing"));
    }
    RegState::Ok
}

impl Registrar {
    /// The JSON manifest for `launch_path` (the wrapper on Unix, the binary
    /// itself on Windows).
    fn manifest_json(&self, launch_path: &Path) -> Result<String, String> {
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
    /// is verified before the first write, so a foreign or unreadable one
    /// fails the target with nothing changed.
    pub fn register(&self, target: &Target) -> Result<Vec<String>, String> {
        // A registry registration is impossible from a non-Windows build;
        // refuse before writing anything at all.
        if let Registration::Registry { key, .. } = &target.registration {
            registry_supported(key)?;
        }
        let manifest_path = target.registration.manifest_path();
        let slots = manifest_slots(&target.registration);
        slots.file.writable(&manifest_path.display().to_string())?;
        if let (Some(key), Registration::Registry { key: name, .. }) =
            (&slots.key, &target.registration)
        {
            key.writable(&format!("registry key HKCU\\{name}"))?;
        }
        if let Some(pointer) = &target.pointer {
            pointer_slot(pointer).writable(&format!("extension pointer {}", pointer.location()))?;
        }

        let mut lines = Vec::new();
        let launch_path = match &target.registration {
            Registration::ManifestDir(dir) => {
                // Unix: wrapper first, then the manifest that points at it.
                crate::fsguard::ensure_private_dir(&self.install_dir)
                    .map_err(|e| format!("could not create {}: {e}", self.install_dir.display()))?;
                let label = target.label();
                let wrapper = self.wrapper_path(label);
                write_atomic(&wrapper, self.wrapper_script(label).as_bytes(), true)
                    .map_err(|e| format!("could not write {}: {e}", wrapper.display()))?;
                fs::create_dir_all(dir)
                    .map_err(|e| format!("could not create {}: {e}", dir.display()))?;
                lines.push(format!(
                    "  launches {}{}",
                    wrapper.display(),
                    label.map(|k| format!(" (label: {k})")).unwrap_or_default()
                ));
                wrapper
            }
            Registration::Registry { key, .. } => {
                // Windows: manifest in our own store dir, registry key points
                // at it, binary launched directly (origin argv selects mode).
                crate::fsguard::ensure_private_dir(&self.install_dir)
                    .map_err(|e| format!("could not create {}: {e}", self.install_dir.display()))?;
                lines.push(format!("  registry key HKCU\\{key}"));
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
                target.describe(),
                manifest_path.display()
            ),
        );

        if let Registration::Registry { key, .. } = &target.registration {
            set_registry_value(key, "", &manifest_path.to_string_lossy())?;
        }
        if let Some(pointer) = &target.pointer {
            match pointer {
                ExtensionPointer::File(path) => {
                    let dir = path
                        .parent()
                        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
                    fs::create_dir_all(dir)
                        .map_err(|e| format!("could not create {}: {e}", dir.display()))?;
                    write_atomic(path, pointer_json().as_bytes(), false)
                        .map_err(|e| format!("could not write {}: {e}", path.display()))?;
                }
                ExtensionPointer::Registry { key } => {
                    set_registry_value(key, POINTER_VALUE_NAME, WEB_STORE_UPDATE_URL)?;
                }
            }
            lines.push(format!("  extension pointer {}", pointer.location()));
        }
        Ok(lines)
    }

    /// Reverse one registration: (report lines, refusals). Each slot (the
    /// Windows key, the manifest file, the pointer) is verified and then
    /// removed on its own, so a foreign or unreadable one is refused and left
    /// while the others of ours still go; a refusal never leaves an artifact
    /// of ours behind that the wrapper cleanup would then orphan. The browser
    /// drops the extension the pointer installed on its next start; an
    /// unpacked extension is untouched.
    pub fn uninstall(target: &Target) -> (Vec<String>, Vec<String>) {
        let mut lines = Vec::new();
        let mut errors = Vec::new();
        let manifest_path = target.registration.manifest_path();
        let slots = manifest_slots(&target.registration);

        if let (Some(key), Registration::Registry { key: name, .. }) =
            (&slots.key, &target.registration)
        {
            match key
                .removable(&format!("registry key HKCU\\{name}"))
                .and_then(|remove| {
                    if remove {
                        delete_registry_key(name)
                    } else {
                        Ok(())
                    }
                }) {
                Ok(()) => {}
                Err(e) => errors.push(e),
            }
        }
        match slots.file.removable(&manifest_path.display().to_string()) {
            Ok(true) => match fs::remove_file(&manifest_path) {
                Ok(()) => lines.push(format!(
                    "{}: removed manifest {}",
                    target.describe(),
                    manifest_path.display()
                )),
                Err(e) => errors.push(format!("could not remove {}: {e}", manifest_path.display())),
            },
            Ok(false) => lines.push(format!("{}: not registered", target.describe())),
            Err(e) => errors.push(e),
        }
        if let Some(pointer) = &target.pointer {
            let what = format!("extension pointer {}", pointer.location());
            match pointer_slot(pointer).removable(&what) {
                Ok(false) => {}
                Ok(true) => {
                    let removed = match pointer {
                        ExtensionPointer::File(path) => fs::remove_file(path)
                            .map_err(|e| format!("could not remove {}: {e}", path.display())),
                        ExtensionPointer::Registry { key } => delete_registry_key(key),
                    };
                    match removed {
                        Ok(()) => lines.push(format!("  removed {what}")),
                        Err(e) => errors.push(e),
                    }
                }
                Err(e) => errors.push(e),
            }
        }
        (lines, errors)
    }
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
/// only), each verified by [`wrapper_is_ours`] before deletion. Returns
/// (report lines, errors).
pub fn remove_wrappers(install_dir: &Path) -> (Vec<String>, Vec<String>) {
    let mut removed = Vec::new();
    let mut errors = Vec::new();
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
                errors.push(format!(
                    "could not read {}: {e} (left in place)",
                    path.display()
                ));
                continue;
            }
            Ok(c) => c,
        };
        if wrapper_is_ours(&contents) {
            match fs::remove_file(&path) {
                Ok(()) => removed.push(format!("removed wrapper {}", path.display())),
                Err(e) => errors.push(format!("could not remove {}: {e}", path.display())),
            }
        } else {
            errors.push(format!(
                "refusing to remove {}: not a chromium-bridge wrapper (left in place)",
                path.display()
            ));
        }
    }
    // Drop the dir only when now empty; remove_dir never deletes contents.
    let _ = fs::remove_dir(install_dir);
    (removed, errors)
}

/// `doctor --fix`: [`fix`] with its report printed. Returns the process exit
/// code: 1 when the repair could not start or any target failed.
pub fn run_fix(targets: &FixTargets) -> i32 {
    let outcomes = match fix(targets) {
        Ok(outcomes) => outcomes,
        Err(e) => {
            log_error!("doctor", "{e}");
            return 1;
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

/// Why a repair could not start. Every variant is decided before the first
/// manifest write, so an `Err` left every registration as it was.
#[derive(Debug)]
pub enum FixError {
    /// The platform's home variable is missing or not absolute.
    Environment(String),
    /// The targeting mode resolved to no browser; the message carries the
    /// guidance the CLI prints.
    NoTargets(String),
    /// This binary's own path could not be resolved.
    HostExe(std::io::Error),
}

impl fmt::Display for FixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FixError::Environment(e) | FixError::NoTargets(e) => f.write_str(e),
            FixError::HostExe(e) => write!(f, "cannot resolve this binary's path: {e}"),
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

/// The repair `doctor --fix` runs, with nothing printed: resolve the
/// environment and the targets, then register each. Idempotent, so a fresh
/// machine gets its first registration and a broken one its repair through
/// this one path. `run_fix` prints the outcomes for the CLI; the native host
/// logs them when the extension asks for a repair, since stdout is its
/// protocol. Diagnostics (the ephemeral-path warning) still go to the log.
pub fn fix(targets: &FixTargets) -> Result<Vec<TargetOutcome>, FixError> {
    let dirs = BaseDirs::from_env().map_err(FixError::Environment)?;
    let os = Os::current();
    let entries = browsers::resolve(os, &dirs);
    let targets = select_targets(targets, &entries)?;
    let host_exe = resolve_host_exe().map_err(FixError::HostExe)?;
    let registrar = Registrar {
        host_exe,
        install_dir: browsers::install_dir(os, &dirs),
        extension_id: PINNED_EXTENSION_ID.to_string(),
    };
    Ok(targets
        .iter()
        .map(|target| TargetOutcome {
            target: target.describe(),
            result: registrar.register(target),
        })
        .collect())
}

/// `chromium-bridge uninstall`: entry point. Removes the registrations for
/// every known browser plus any re-passed `--manifest-dir`, and the wrapper
/// scripts -- exactly what this project writes, nothing else. The binary, the
/// browser, and the loaded extension are never touched.
pub fn run_uninstall(args: &UninstallArgs) -> i32 {
    let (os, dirs) = match resolve_env() {
        Ok(v) => v,
        Err(code) => return code,
    };
    let entries = browsers::resolve(os, &dirs);

    let mut targets: Vec<Target> = entries.iter().map(Target::for_browser).collect();
    for dir in &args.manifest_dirs {
        targets.push(Target::for_explicit_dir(dir));
    }

    println!("chromium-bridge uninstall (host id {NATIVE_HOST_ID})");
    let mut failed = false;
    for target in &targets {
        let (lines, errors) = Registrar::uninstall(target);
        for line in lines {
            println!("{line}");
        }
        for e in &errors {
            log_error!("uninstall", "{}: {e}", target.describe());
        }
        failed = failed || !errors.is_empty();
    }
    let (removed, errors) = remove_wrappers(&browsers::install_dir(os, &dirs));
    for line in removed {
        println!("{line}");
    }
    for e in &errors {
        log_error!("uninstall", "{e}");
    }
    failed = failed || !errors.is_empty();
    println!(
        "left untouched: this binary and your browsers. A browser drops the extension its pointer\n\
         installed on its next start; remove an unpacked extension yourself via chrome://extensions."
    );
    if failed {
        1
    } else {
        0
    }
}

/// Shared CLI preamble: pick the OS layout and read the base dirs, failing
/// closed (exit 1) when the environment cannot name a home directory.
pub(crate) fn resolve_env() -> Result<(Os, BaseDirs), i32> {
    match BaseDirs::from_env() {
        Ok(dirs) => Ok((Os::current(), dirs)),
        Err(e) => {
            log_error!("doctor", "{e}");
            Err(1)
        }
    }
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

/// Resolve the typed `--fix` targeting mode into concrete targets. Unknown
/// `--browser` keys were already refused at the argv boundary
/// ([`crate::cli::parse`] resolves them into [`Browser`]s), so the match
/// here is exhaustive, with no priority chain to order wrongly.
fn select_targets(targets: &FixTargets, entries: &[BrowserEntry]) -> Result<Vec<Target>, FixError> {
    match targets {
        FixTargets::ManifestDirs(dirs) => Ok(dirs
            .iter()
            .map(|dir| Target::for_explicit_dir(dir))
            .collect()),
        FixTargets::All => Ok(entries.iter().map(Target::for_browser).collect()),
        FixTargets::Browsers(browsers) => {
            let mut out = Vec::new();
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
                out.push(Target::for_browser(entry));
            }
            Ok(out)
        }
        FixTargets::Detected => {
            let detected: Vec<Target> = entries
                .iter()
                .filter(|e| e.detected())
                .map(Target::for_browser)
                .collect();
            if detected.is_empty() {
                return Err(FixError::NoTargets(format!(
                    "no Chromium-family browser detected for this user: install Chrome, Brave or Edge, \
                     then run: chromium-bridge doctor --fix (or pass --browser <keys> (known: {}), \
                     --all, or --manifest-dir <dir>)",
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
fn registry_supported(_key: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(not(windows))]
fn registry_supported(key: &str) -> Result<(), String> {
    Err(format!(
        "registry registration (HKCU\\{key}) requires a Windows build of chromium-bridge"
    ))
}

/// One registry key, read whole so ownership is judged on all of it.
struct RegistryKey {
    /// Every value as (name, text), `""` naming the default value.
    values: Vec<(String, String)>,
    /// How many child keys hang under it.
    children: u32,
}

/// `HKCU\{key}` whole, or `None` when the key is absent. A value that is not
/// REG_SZ is an error rather than a lossy conversion: this engine writes
/// REG_SZ alone, so anything else was never ours.
#[cfg(windows)]
fn registry_key(key: &str) -> Result<Option<RegistryKey>, String> {
    use winreg::types::FromRegValue;
    let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    let subkey = match hkcu.open_subkey(key) {
        Ok(k) => k,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let mut values = Vec::new();
    for entry in subkey.enum_values() {
        let (name, value) = entry.map_err(|e| format!("could not list its values: {e}"))?;
        if value.vtype != winreg::enums::RegType::REG_SZ {
            return Err(format!("value {name:?} is not a REG_SZ string"));
        }
        let text = String::from_reg_value(&value)
            .map_err(|e| format!("value {name:?} is not readable text: {e}"))?;
        values.push((name, text));
    }
    let children = subkey
        .query_info()
        .map_err(|e| format!("could not count its child keys: {e}"))?
        .sub_keys;
    Ok(Some(RegistryKey { values, children }))
}

#[cfg(not(windows))]
fn registry_key(_key: &str) -> Result<Option<RegistryKey>, String> {
    Err("registry access requires a Windows build of chromium-bridge".into())
}

#[cfg(windows)]
fn set_registry_value(key: &str, name: &str, value: &str) -> Result<(), String> {
    let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    let (subkey, _) = hkcu
        .create_subkey(key)
        .map_err(|e| format!("could not create HKCU\\{key}: {e}"))?;
    subkey
        .set_value(name, &value)
        .map_err(|e| format!("could not set HKCU\\{key}: {e}"))
}

#[cfg(not(windows))]
fn set_registry_value(key: &str, _name: &str, _value: &str) -> Result<(), String> {
    Err(format!(
        "registry registration (HKCU\\{key}) requires a Windows build of chromium-bridge"
    ))
}

/// Delete `HKCU\{key}` once its slot was judged ours. delete_subkey (not _all):
/// our keys have no children, and failing on an unexpected child is the
/// fail-closed behavior we want.
#[cfg(windows)]
fn delete_registry_key(key: &str) -> Result<(), String> {
    let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    match hkcu.delete_subkey(key) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("could not delete HKCU\\{key}: {e}")),
    }
}

#[cfg(not(windows))]
fn delete_registry_key(key: &str) -> Result<(), String> {
    Err(format!(
        "registry removal (HKCU\\{key}) requires a Windows build of chromium-bridge"
    ))
}

#[cfg(test)]
mod tests;
