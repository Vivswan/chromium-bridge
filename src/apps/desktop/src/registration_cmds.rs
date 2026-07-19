//! Native-messaging registration from the app: the same engine
//! (`chromium_bridge_core::registration`) and browser-path resolver
//! (`chromium_bridge_core::browsers`) behind `doctor --fix` and `uninstall`,
//! pointed at the bundled host binary. App and CLI are co-equal surfaces
//! writing the same bytes (ADR-0029); every fail-closed rule (foreign
//! manifests refused, unreadable paths left alone) is the engine's, not
//! reimplemented here. Every manifest write is user-initiated: first launch
//! only detects browsers and reports them (ADR-0029 as amended).

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
    /// `RegState::code()`: the machine form the UI branches on. The human
    /// `state` string is display-only.
    pub code: &'static str,
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
                code: state.code(),
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

/// What first launch found, for the onboarding card. Detection only: no
/// browser configuration is touched (ADR-0029 as amended); every manifest
/// write goes through the user-initiated register commands above.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirstRunReport {
    /// Keys of the browsers detected for this user (may be empty).
    pub detected: Vec<String>,
}

/// The first-run marker: lives beside the wrapper scripts in the install
/// dir, so `uninstall` semantics stay untouched (the marker is app state,
/// not a registration artifact). It records that a launch claimed the
/// first-run card; it has never meant "registered" since the opt-in
/// amendment to ADR-0029.
fn marker_path(os: Os, dirs: &BaseDirs) -> std::path::PathBuf {
    browsers::install_dir(os, dirs).join("desktop-first-run.json")
}

/// First launch (ADR-0029 as amended): detect the user's browsers and report
/// them, writing nothing outside our own install dir. Returns `None` when a
/// previous (or concurrent) launch already claimed the card. Connecting a
/// browser is always a separate, user-initiated `register_browser` call.
pub fn first_launch_detect() -> Result<Option<FirstRunReport>, String> {
    let dirs = BaseDirs::from_env()?;
    detect_once(Os::current(), &dirs)
}

/// The marker is CLAIMED first, with `create_new`, which refuses to follow
/// a symlink planted at the marker path; the install dir is prepared by the
/// engine's `ensure_private_dir` (owner-only, refuses a symlinked leaf), so
/// a symlink planted there cannot redirect the write either. Both checks
/// are hardening against redirection, not a privilege boundary: a same-user
/// process that can plant symlinks can already write anywhere we can. The
/// claim also makes the run single-flight - the loser of the create race
/// does nothing and reports nothing.
fn detect_once(os: Os, dirs: &BaseDirs) -> Result<Option<FirstRunReport>, String> {
    let marker = marker_path(os, dirs);
    // symlink_metadata (not exists()): a dangling symlink at the marker path
    // must read as "present" so it is never followed by a write.
    if std::fs::symlink_metadata(&marker).is_ok() {
        return Ok(None);
    }
    if let Some(parent) = marker.parent() {
        registration::ensure_private_dir(parent)
            .map_err(|e| format!("could not prepare {}: {e}", parent.display()))?;
    }
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)
    {
        Ok(f) => f,
        // Lost the single-flight race: another launch is showing the card.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(None),
        Err(e) => return Err(format!("could not write {}: {e}", marker.display())),
    };
    use std::io::Write as _;
    // v2: the marker means "a launch claimed the first-run card". Claimed,
    // not provably rendered: a crash between claim and paint forfeits the
    // card, and the Browsers page carries the same information. v1 markers
    // (from builds that still auto-registered) read the same way here - only
    // existence is ever checked.
    if let Err(e) = file
        .write_all(b"{\"v\":2}\n")
        .and_then(|()| file.sync_all())
    {
        drop(file);
        let _ = std::fs::remove_file(&marker);
        return Err(format!("could not write {}: {e}", marker.display()));
    }
    drop(file);

    Ok(Some(FirstRunReport {
        detected: browsers::resolve(os, dirs)
            .iter()
            .filter(|entry| entry.detected())
            .map(|entry| entry.browser.key().to_string())
            .collect(),
    }))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;

    /// A fixture home in the temp dir; never a real user directory. The
    /// system applications folder is a fixture subdir too, so detection
    /// never scans the machine's real `/Applications`.
    fn fixture(tag: &str) -> (PathBuf, BaseDirs) {
        let root = std::env::temp_dir().join(format!("bb-first-run-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let dirs = BaseDirs {
            home: root.clone(),
            xdg_config_home: None,
            xdg_data_home: None,
            local_app_data: None,
            roaming_app_data: None,
            system_applications: root.join("SystemApplications"),
        };
        (root, dirs)
    }

    fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                files_under(&path, out);
            } else {
                out.push(path);
            }
        }
    }

    #[test]
    fn first_launch_detects_and_writes_only_the_marker() {
        let (root, dirs) = fixture("detect");
        // One detected browser: Chrome's app bundle AND its macOS config
        // root exist.
        std::fs::create_dir_all(root.join("SystemApplications/Google Chrome.app")).unwrap();
        std::fs::create_dir_all(root.join("Library/Application Support/Google/Chrome")).unwrap();
        // A leftover config root with no app bundle (the ghost-browser bug)
        // must NOT be reported as detected.
        std::fs::create_dir_all(root.join("Library/Application Support/Vivaldi")).unwrap();

        let report = detect_once(Os::MacOs, &dirs).unwrap().expect("first run");
        assert_eq!(report.detected, vec!["chrome"]);

        // The only file created anywhere under the fixture home is our own
        // marker: no browser directory gained a manifest without the user
        // asking for one.
        let mut files = Vec::new();
        files_under(&root, &mut files);
        assert_eq!(
            files,
            vec![root.join(".chromium-bridge/desktop-first-run.json")]
        );

        // Later launches: the card was shown once, nothing more to report.
        assert!(detect_once(Os::MacOs, &dirs).unwrap().is_none());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_at_the_marker_reads_as_present() {
        let (root, dirs) = fixture("symlink");
        let marker = marker_path(Os::MacOs, &dirs);
        std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(root.join("nowhere"), &marker).unwrap();

        // A planted symlink must never be followed by a write.
        assert!(detect_once(Os::MacOs, &dirs).unwrap().is_none());
        assert!(std::fs::symlink_metadata(&marker).unwrap().is_symlink());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_install_dir_is_refused() {
        let (root, dirs) = fixture("linked-dir");
        // The install dir itself is a symlink into a stand-in browser config
        // dir: the marker write must be refused, not redirected.
        let target = root.join("Library/Application Support/Google/Chrome/NativeMessagingHosts");
        std::fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, root.join(".chromium-bridge")).unwrap();

        assert!(detect_once(Os::MacOs, &dirs).is_err());
        let mut files = Vec::new();
        files_under(&target, &mut files);
        assert!(files.is_empty(), "nothing may land through the symlink");
        std::fs::remove_dir_all(&root).unwrap();
    }
}
