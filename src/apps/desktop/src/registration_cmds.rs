//! Native-messaging registration from the app: the same engine
//! (`chromium_bridge_core::registration`) and browser-path resolver
//! (`chromium_bridge_core::browsers`) behind `doctor --fix` and `uninstall`,
//! pointed at the bundled host binary. App and CLI are co-equal surfaces
//! writing the same bytes (ADR-0029); every fail-closed rule (foreign
//! manifests refused, unreadable paths left alone) is the engine's, not
//! reimplemented here.

use std::path::Path;

use serde::Serialize;

use chromium_bridge_core::browsers::{self, BaseDirs, Browser, Os, PINNED_EXTENSION_ID};
use chromium_bridge_core::registration::{self, RegState, Registrar, Target};

use crate::host;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserRow {
    /// Stable key (`chrome`, `brave`, ...), also the register/unregister handle.
    pub key: &'static str,
    pub detected: bool,
    /// `RegState::describe()` output: ok / missing / stale (why) / ...
    pub state: String,
    pub healthy: bool,
    /// Where the registration lives (manifest path, or the HKCU key).
    pub location: String,
}

/// Resolve the environment and build the registrar every mutating command
/// shares. Fails when no home directory can be named or the host binary is
/// missing - registering a manifest that points nowhere would be worse.
fn engine() -> Result<(Os, BaseDirs, Registrar), String> {
    let dirs = BaseDirs::from_env()?;
    let os = Os::current();
    let registrar = Registrar {
        host_exe: host::resolve_host()?,
        install_dir: browsers::install_dir(os, &dirs),
        extension_id: PINNED_EXTENSION_ID.to_string(),
    };
    Ok((os, dirs, registrar))
}

/// Read-only: every known browser with detection + registration state.
pub fn list() -> Result<Vec<BrowserRow>, String> {
    let dirs = BaseDirs::from_env()?;
    Ok(browsers::resolve(Os::current(), &dirs)
        .iter()
        .map(|entry| {
            let state = registration::assess(&entry.registration);
            BrowserRow {
                key: entry.browser.key(),
                detected: entry.detected(),
                healthy: state == RegState::Ok,
                state: state.describe(),
                location: entry.registration.location(),
            }
        })
        .collect())
}

/// Register one known browser by key. Returns the engine's report lines.
pub fn register_browser(key: &str) -> Result<Vec<String>, String> {
    let (os, dirs, registrar) = engine()?;
    let browser = Browser::from_key(key).ok_or_else(|| format!("unknown browser key {key:?}"))?;
    let entry = browsers::entry(os, &dirs, browser);
    registrar.register(&Target::for_browser(&entry))
}

/// Remove one known browser's registration (only what we verifiably wrote;
/// the engine refuses foreign manifests).
pub fn unregister_browser(key: &str) -> Result<String, String> {
    let dirs = BaseDirs::from_env()?;
    let browser = Browser::from_key(key).ok_or_else(|| format!("unknown browser key {key:?}"))?;
    let entry = browsers::entry(Os::current(), &dirs, browser);
    Registrar::uninstall(&Target::for_browser(&entry))
}

/// Register an explicit NativeMessagingHosts directory (the manual "add a
/// browser we do not know by name" path). Absolute paths only, same rule as
/// the CLI's `--manifest-dir`.
pub fn register_manifest_dir(dir: &str) -> Result<Vec<String>, String> {
    if !Path::new(dir).is_absolute() {
        return Err(format!(
            "manifest directory must be an absolute path, got {dir:?}"
        ));
    }
    let (_, _, registrar) = engine()?;
    registrar.register(&Target::for_explicit_dir(Path::new(dir)))
}

/// Remove an explicit directory's registration.
pub fn unregister_manifest_dir(dir: &str) -> Result<String, String> {
    if !Path::new(dir).is_absolute() {
        return Err(format!(
            "manifest directory must be an absolute path, got {dir:?}"
        ));
    }
    Registrar::uninstall(&Target::for_explicit_dir(Path::new(dir)))
}

/// What the first-launch self-registration did, for the onboarding banner.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirstRunReport {
    /// Report lines per registered browser (empty when none was detected).
    pub lines: Vec<String>,
    /// Per-target failures (foreign manifests refused, transient I/O, ...).
    /// Any failure releases the first-run claim, so the next launch retries;
    /// the engine keeps refusing foreign targets on every retry.
    pub errors: Vec<String>,
    pub detected: Vec<String>,
}

/// The first-run marker: lives beside the wrapper scripts in the install
/// dir, so `uninstall` semantics stay untouched (the marker is app state,
/// not a registration artifact).
fn marker_path(os: Os, dirs: &BaseDirs) -> std::path::PathBuf {
    browsers::install_dir(os, dirs).join("desktop-first-run.json")
}

/// Self-register on first launch (ADR-0029): register every DETECTED browser
/// through the shared engine, once, then leave the marker. Returns `None`
/// when a previous (or concurrent) launch already did this.
///
/// The marker is CLAIMED first, with `create_new`: that refuses to follow a
/// planted symlink (the write can never land outside the install dir) and
/// makes the whole run single-flight - the loser of the create race does
/// nothing and reports nothing. If any registration then fails (a refused
/// foreign manifest, a transient I/O error), the claim is released so the
/// next launch retries with the report still in front of the user; retrying
/// is safe because the engine is idempotent and keeps refusing foreign
/// targets without writing.
pub fn first_launch_register() -> Result<Option<FirstRunReport>, String> {
    let (os, dirs, registrar) = engine()?;
    let marker = marker_path(os, &dirs);
    // symlink_metadata (not exists()): a dangling symlink at the marker path
    // must read as "present" so it is never followed by a write.
    if std::fs::symlink_metadata(&marker).is_ok() {
        return Ok(None);
    }
    if let Some(parent) = marker.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("could not create {}: {e}", parent.display()))?;
    }
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)
    {
        Ok(f) => f,
        // Lost the single-flight race: another launch is doing all of this.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(None),
        Err(e) => return Err(format!("could not write {}: {e}", marker.display())),
    };
    use std::io::Write as _;
    if let Err(e) = file
        .write_all(b"{\"v\":1}\n")
        .and_then(|()| file.sync_all())
    {
        drop(file);
        let _ = std::fs::remove_file(&marker);
        return Err(format!("could not write {}: {e}", marker.display()));
    }
    drop(file);

    let mut report = FirstRunReport {
        lines: Vec::new(),
        errors: Vec::new(),
        detected: Vec::new(),
    };
    for entry in browsers::resolve(os, &dirs) {
        if !entry.detected() {
            continue;
        }
        report.detected.push(entry.browser.key().to_string());
        match registrar.register(&Target::for_browser(&entry)) {
            Ok(lines) => report.lines.extend(lines),
            Err(e) => report.errors.push(format!("{}: {e}", entry.browser.key())),
        }
    }

    if !report.errors.is_empty() {
        // Release the claim so the next launch retries the failed targets.
        if let Err(e) = std::fs::remove_file(&marker) {
            report.errors.push(format!(
                "could not clear {} for a retry next launch: {e}",
                marker.display()
            ));
        }
    }
    Ok(Some(report))
}
