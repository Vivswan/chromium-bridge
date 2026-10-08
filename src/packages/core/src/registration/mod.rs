//! Native-messaging registration: the write/repair/remove engine behind `doctor --fix` and `uninstall`; browser
//! locations come from [`crate::browsers`], the resolver `doctor`
//! diagnoses with. Fail closed: `uninstall` removes only files this project verifiably wrote, and `--fix` refuses an
//! entry it cannot read; a manifest another tool wrote at our host id is the one thing an explicit `--fix` replaces
//! (the rule, with the pointer's refusal, is on [`Slot`](slot::Slot)). That keeps OUR tooling from destroying someone else's
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
//!                   answers with "Enable Genkan?" (macOS a file, Windows a key, Linux none: see
//!                   [`ExtensionPointer`]); removing it makes the browser drop the extension it installed from it
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use crate::browsers::{self, Browser, BrowserEntry, ExtensionPointer, Lookup, Registration, Scope};
use crate::identity::NATIVE_HOST_ID;

mod command;
mod files;
mod privilege;
mod registry;
mod slot;
mod wrapper;

pub use command::{
    cli_guidance, fix, run_fix, run_uninstall, FixError, TargetOutcome, NOTHING_TO_REGISTER,
};
pub(crate) use command::{known_keys, resolve_env};
pub use privilege::Privilege;
pub use slot::{
    assess, assess_pointer, lookup_hit, manifest_ownership, pointer_ownership, Ownership,
    PointerState, RegState,
};
pub use wrapper::remove_wrappers;

use files::{create_traversable_dirs, plan_traversable_dirs, write_atomic};
use registry::{delete_registry_key, registry_supported, set_registry_value};
use slot::{manifest_slots, pointer_slot};
use wrapper::shell_quote;

/// The `description` this engine writes: the ownership marker.
const MANIFEST_DESCRIPTION: &str = "Genkan native messaging host (managed by genkan)";

/// First line of every wrapper this project writes.
const WRAPPER_SHEBANG: &str = "#!/usr/bin/env bash";

/// Second line of every wrapper this project writes: the ownership marker.
const WRAPPER_MARKER: &str = "# managed by genkan; safe to delete";

/// The only update source Chrome accepts for an externally installed extension on macOS and Windows: the
/// Web Store, which serves the extension under [`PINNED_EXTENSION_ID`](crate::identity::PINNED_EXTENSION_ID).
const WEB_STORE_UPDATE_URL: &str = "https://clients2.google.com/service/update2/crx";

/// The Windows pointer key's value name, the one Chrome's registry loader reads before any other.
const POINTER_VALUE_NAME: &str = "update_url";

/// Fuzz-only aliases of the ownership marker and the Web Store url, for the
/// cargo-fuzz workspace's ownership oracles and seed generator (see the `fuzzing`
/// feature in Cargo.toml). Aliases of the real constants, so none can drift from
/// what this module actually writes; they stay private otherwise.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzz_api {
    pub const MANIFEST_DESCRIPTION: &str = super::MANIFEST_DESCRIPTION;
    pub const WEB_STORE_UPDATE_URL: &str = super::WEB_STORE_UPDATE_URL;
}

/// The pointer file's bytes, which the fuzz seeds take as the one accepted shape.
pub fn pointer_json() -> String {
    format!("{{\n  \"external_update_url\": \"{WEB_STORE_UPDATE_URL}\"\n}}\n")
}

/// Everything the engine needs to lay a registration down. Paths are injected
/// so tests drive it against temp trees, never real browser dirs, and so the
/// app can point it at the same places the CLI does.
pub struct Registrar {
    /// The host binary every registration points at (resolved `current_exe`
    /// in the CLI; an explicit path in tests).
    pub host_exe: PathBuf,
    /// Where wrapper scripts live (Unix).
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
        format!("{WRAPPER_SHEBANG}\n{WRAPPER_MARKER}\n{exec_line}\n")
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
    /// is judged before the first write ([`Slot`](slot::Slot)): an unreadable one or a
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

#[cfg(test)]
mod tests;
