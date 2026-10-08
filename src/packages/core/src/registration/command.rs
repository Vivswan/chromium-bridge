//! `doctor --fix` and `uninstall` as commands: admit the caller's privilege, resolve the environment and the
//! targets, drive the engine over each, and turn what it did into the report and the exit code.

use std::fmt;
use std::path::PathBuf;

use super::files::launchable_by_every_account;
use super::wrapper::remove_wrappers;
use super::{ForeignManifest, Privilege, Registrar, RegistrarScope, Removal, Target};
use crate::browsers::{self, BaseDirs, Browser, BrowserEntry, Os, Scope};
use crate::cli::{FixTargets, UninstallArgs};
use crate::identity::{NATIVE_HOST_ID, PINNED_EXTENSION_ID};

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
    println!("genkan doctor --fix (host id {NATIVE_HOST_ID})");
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
         once it is, browsers registered by name on macOS and Windows offer to enable Genkan\n\
         (no pointer is written on Linux or for --manifest-dir). Re-check with\n\
         `genkan doctor`."
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
pub(super) fn fix_exit_code(error: &FixError) -> i32 {
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

/// `genkan uninstall`: entry point. Removes the registrations of one
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

    println!("genkan uninstall (host id {NATIVE_HOST_ID})");
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

/// `uninstall`'s exit code over everything it removed: 1 only when a verified artifact of ours could not
/// be removed.
pub(super) fn uninstall_exit_code(removals: &[Removal]) -> i32 {
    if removals.iter().any(|r| !r.failed.is_empty()) {
        1
    } else {
        0
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
             ~/.local/lib/genkan/) and run `doctor --fix` from there.",
            exe.display()
        );
    }
    Ok(exe)
}

/// The targets of one scope for these browsers, each registration once: browsers that read another's
/// directory resolve to the owner's target ([`Target::for_browser`]), so Chrome and Brave together yield
/// Chrome's manifest once rather than two writes of the same file with different labels, and that one
/// target carries both browsers' pointers, since each prompts from its own. The registration, not the
/// manifest path, is the identity: on Windows every browser's manifest sits in the one store file while
/// each has its own key.
pub(super) fn browser_targets<'a>(
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
pub(super) fn select_targets(
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
