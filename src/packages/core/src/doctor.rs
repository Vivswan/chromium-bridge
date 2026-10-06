//! `doctor` / `status`: diagnosis, and (only with `--fix`) repair.
//!
//! Plain `doctor` prints a health report without touching the browser, spawning processes, or killing
//! anything: it reads the lock file, connect-probes our OWN bridge socket passively (no bytes sent), and
//! diagnoses each browser's native-messaging registration through the shared resolver in `crate::browsers`.
//!
//! ```text
//! doctor --list   -> detection and registration state alone; no lock read, no probe
//! doctor --paths  -> where the runtime dir and lock file resolve; creates and probes nothing
//! doctor --fix    -> the diagnosis handed to `crate::registration` for an idempotent repair, which on a
//!                    fresh machine IS the registration (docs/cli.md)
//! ```

use std::io;
use std::path::PathBuf;

use serde::Serialize;

use crate::browsers::{self, BaseDirs, ExtensionPointer, Lookup, Os, Scope, Scoped};
use crate::cli::DoctorCommand;
use crate::identity::NATIVE_HOST_ID;
use crate::ipc::{LockFile, RuntimeDir};
use crate::policy::{PolicyStatusReport, PolicyStoreState};
use crate::registration::{self, PointerState, RegState};

/// Schema version of the serialized [`Report`]. Like every `--json` report of
/// this binary, a consumer checks `v` first and refuses a newer value.
pub const REPORT_VERSION: u32 = 2;

/// Plain facts gathered for the report, free of I/O so every renderer over it is pure. The serialized form is
/// what `doctor --json` prints and what other readers of the host's health consume.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub v: u32,
    pub version: &'static str,
    pub os: &'static str,
    pub arch: &'static str,
    /// The lock file, located and classified once at gather time, or the reason the runtime dir itself was
    /// refused (a socket path too long to bind), under which no lock can exist. Each state carries exactly
    /// the facts it has - contradictory reports (an endpoint without a lock file, a parse error beside a
    /// pid) cannot be constructed.
    pub lock: Result<LockReport, String>,
    /// Per known browser: detection and manifest registration, in
    /// `Browser::ALL` order - or the reason the check could not run at all
    /// (e.g. no HOME).
    pub manifests: Result<Vec<ManifestStatus>, String>,
    /// The global kill switch. `Ok(bool)` from a readable trust record;
    /// `Err(text)` when the record is unreadable (in which case every
    /// enforcement point is failing closed).
    pub kill: Result<bool, String>,
    /// The host-owned policy store. The report's own `store` state carries
    /// the fail-closed distinctions (`none` is healthy pre-cutover; `error`
    /// is a present-but-unreadable store), so no outer `Result` is needed -
    /// `gather_policy_status` never fails.
    pub policy: PolicyStatusReport,
}

/// Where the lock file resolves and what was found there.
#[derive(Debug, Clone, Serialize)]
pub struct LockReport {
    #[serde(serialize_with = "crate::audit::serialize_path_lossy")]
    pub path: PathBuf,
    #[serde(flatten)]
    pub state: LockState,
}

/// The lock file's classification: exactly absent, present-but-unreadable, or
/// parsed (with the probe result the endpoint allowed). Mirrors the three-way
/// result of `LockFile::read()`. A parsed file says nothing about the server
/// by itself: only `reachable` does, since a server that died without
/// cleaning up leaves its lock behind.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LockState {
    /// No lock file: server not running.
    Absent,
    /// The file exists but did not read/parse.
    Unreadable { detail: String },
    /// Parsed; `reachable` is the passive connect probe against `endpoint`.
    Present {
        endpoint: String,
        pid: u32,
        secret_len: usize,
        reachable: bool,
    },
}

/// One browser's registration state in both scopes, as diagnosed through the
/// shared resolver and `registration::assess`. Stores the assessed
/// [`RegState`]s themselves; the rendered wording and the health verdict are
/// derived at use, so they cannot disagree with each other.
#[derive(Debug, Clone, Serialize)]
pub struct ManifestStatus {
    pub key: &'static str,
    pub detected: bool,
    pub manifest: Scoped<SlotStatus>,
    /// The scope the browser's own lookup lands on (`registration::lookup_hit` on the per-user entry):
    /// the per-user one when its probe finds an entry there (a file of any content on macOS and Linux, a
    /// string default value in the key on Windows), else the machine-wide one.
    pub effective_scope: Scope,
    /// The browser's external-extension pointer per scope; `None` where the
    /// resolver defines none (Linux). It informs and never decides the
    /// verdict: the bridge works without it once the extension is loaded any
    /// other way.
    pub pointer: Option<Scoped<PointerStatus>>,
}

/// One scope's manifest state and where it lives. A foreign state here is the reporting leg of the rule
/// on `registration::Slot` (reported, overwritten by an explicit `--fix`, never removed by `uninstall`).
#[derive(Debug, Clone, Serialize)]
pub struct SlotStatus {
    pub state: RegState,
    pub location: String,
    /// The browser whose directory this is, when the row's browser reads another's
    /// ([`crate::browsers::Lookup::ReadsFrom`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<&'static str>,
}

impl SlotStatus {
    fn assess(lookup: &Lookup) -> SlotStatus {
        SlotStatus {
            state: registration::assess(lookup.registration()),
            location: lookup.registration().location(),
            owner: lookup.owner().map(browsers::Browser::key),
        }
    }

    /// The location, with the directory's owner when it is another browser's.
    fn describe_location(&self) -> String {
        match self.owner {
            Some(owner) => format!("{} (reads {owner}'s)", self.location),
            None => self.location.clone(),
        }
    }
}

/// One browser's external-extension pointer state, beside its manifest's.
#[derive(Debug, Clone, Serialize)]
pub struct PointerStatus {
    pub state: PointerState,
    pub location: String,
}

impl PointerStatus {
    fn assess(pointer: &ExtensionPointer) -> PointerStatus {
        PointerStatus {
            state: registration::assess_pointer(pointer),
            location: pointer.location(),
        }
    }
}

/// Why Linux rows carry no pointer, as the full report says beside them.
const NO_POINTER_ON_LINUX: &str =
    "none on linux: Chrome would install the extension silently; add it from the Web Store";

impl ManifestStatus {
    /// The registration the browser acts on.
    fn effective(&self) -> &SlotStatus {
        self.manifest.get(self.effective_scope)
    }

    fn healthy(&self) -> bool {
        self.effective().state == RegState::Ok
    }
}

impl From<&ManifestStatus> for crate::protocol::control::RegistrationRow {
    fn from(status: &ManifestStatus) -> Self {
        let effective = status.effective();
        crate::protocol::control::RegistrationRow {
            browser: status.key.to_string(),
            detected: status.detected,
            state: (&effective.state).into(),
            location: effective.location.clone(),
        }
    }
}

impl Report {
    /// Whether any browser this user actually has picks up a healthy
    /// registration.
    fn manifest_ok(&self) -> bool {
        self.manifests
            .as_ref()
            .is_ok_and(|list| list.iter().any(|m| m.detected && m.healthy()))
    }
}

/// Gather the per-browser manifest states (read-only), or the reason the
/// check could not run. The native host answers `registration_status` from
/// this same read.
pub(crate) fn gather_manifests() -> Result<Vec<ManifestStatus>, String> {
    let dirs = BaseDirs::from_env(Scope::User)?;
    Ok(browsers::resolve(Os::current(), &dirs)
        .iter()
        .map(|entry| ManifestStatus {
            key: entry.browser.key(),
            detected: entry.installed(),
            manifest: Scoped {
                user: SlotStatus::assess(&entry.manifest.user),
                system: SlotStatus::assess(&entry.manifest.system),
            },
            effective_scope: if registration::lookup_hit(entry.manifest.user.registration()) {
                Scope::User
            } else {
                Scope::System
            },
            pointer: entry.pointer.as_ref().map(|pointer| Scoped {
                user: PointerStatus::assess(&pointer.user),
                system: PointerStatus::assess(&pointer.system),
            }),
        })
        .collect())
}

/// Gather the report by reading (never mutating) local state.
pub fn gather() -> Report {
    let lock = RuntimeDir::ensure()
        .map(|dir| LockReport {
            path: LockFile::path_in(&dir),
            state: match LockFile::read() {
                Ok(Some(lf)) => LockState::Present {
                    reachable: crate::ipc::probe_endpoint(&lf.endpoint),
                    secret_len: lf.secret.len(),
                    pid: lf.pid,
                    endpoint: lf.endpoint,
                },
                Ok(None) => LockState::Absent,
                // File exists but did not read/parse. Present-but-broken.
                Err(e) => LockState::Unreadable {
                    detail: e.to_string(),
                },
            },
        })
        .map_err(|e| e.to_string());

    Report {
        v: REPORT_VERSION,
        version: env!("CARGO_PKG_VERSION"),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        lock,
        manifests: gather_manifests(),
        kill: crate::kill::is_killed().map_err(|e| e.to_string()),
        policy: crate::policy::gather_policy_status(),
    }
}

/// Pure rendering of a gathered report into the printed health text.
fn render(r: &Report) -> String {
    let mut out = String::new();
    out.push_str(&format!("chromium-bridge doctor - v{}\n", r.version));
    out.push_str(&format!("platform:        {}/{}\n", r.os, r.arch));

    match &r.lock {
        Err(detail) => {
            out.push_str(&format!("lock file:       none ({detail})\n"));
            out.push_str("mcp server:      not probed (no runtime dir)\n");
        }
        Ok(lock) => render_lock(&mut out, lock),
    }

    out.push_str("kill switch:     ");
    match &r.kill {
        Ok(false) => out.push_str("off (bridge activity permitted)\n"),
        Ok(true) => out
            .push_str("ENGAGED - all bridge activity is refused until `chromium-bridge unkill`\n"),
        Err(e) => out.push_str(&format!(
            "state UNREADABLE ({e}) - every enforcement point is failing closed;\n  \
             see docs/troubleshooting.md for recovery\n"
        )),
    }

    out.push_str("policy baseline: ");
    match &r.policy {
        // No baseline yet is HEALTHY (pre-cutover): the extension keeps
        // enforcing its deny baseline until a first policy signs. It must not
        // read as broken.
        PolicyStatusReport::None { .. } => out.push_str(
            "none yet (pre-cutover; the extension keeps enforcing its deny baseline\n  \
             until `chromium-bridge policy set` signs a baseline)\n",
        ),
        PolicyStatusReport::Present {
            revision,
            signed,
            overlay_active,
            ..
        } => {
            // The host never self-certifies the signature; the extension
            // verifies it against its pinned key. So report signed-ness, never
            // "valid"/"invalid", and say verification is not done here.
            let signed = if *signed {
                "signed (the extension verifies it against its pinned key, not here)"
            } else {
                "unsigned"
            };
            out.push_str(&format!("revision {revision}, {signed}\n"));
            if *overlay_active {
                out.push_str("  restriction overlay: active\n");
            }
        }
        PolicyStatusReport::Error { detail, .. } => out.push_str(&format!(
            "UNREADABLE ({detail}) - failing closed; see docs/troubleshooting.md\n",
        )),
    }

    out.push_str(&format!("native manifests: (host id {NATIVE_HOST_ID})\n"));
    match &r.manifests {
        Err(err) => out.push_str(&format!("  could not check: {err}\n")),
        Ok(list) => {
            for m in list {
                out.push_str(&format!(
                    "  {:<9} {:<13} {:<7} manifest {:<10} {}\n",
                    m.key,
                    if m.detected {
                        "detected"
                    } else {
                        "not detected"
                    },
                    Scope::User.key(),
                    m.manifest.user.state.describe(),
                    m.manifest.user.describe_location(),
                ));
                out.push_str(&format!(
                    "  {:<9} {:<13} {:<7} manifest {:<10} {}\n",
                    "",
                    "",
                    Scope::System.key(),
                    m.manifest.system.state.describe(),
                    m.manifest.system.describe_location(),
                ));
                match &m.pointer {
                    Some(pointer) => {
                        for (scope, p) in [
                            (Scope::User, &pointer.user),
                            (Scope::System, &pointer.system),
                        ] {
                            out.push_str(&format!(
                                "  {:<9} {:<13} {:<7} pointer  {:<10} {}\n",
                                "",
                                "",
                                scope.key(),
                                p.state.describe(),
                                p.location,
                            ));
                        }
                    }
                    None => out.push_str(&format!(
                        "  {:<9} {:<13} {:<7} pointer  {:<10} {NO_POINTER_ON_LINUX}\n",
                        "", "", "", "n/a",
                    )),
                }
            }
        }
    }

    // These probes only cover the MCP-server/bridge side. doctor cannot observe
    // whether the Chrome extension is loaded and connected without speaking the
    // native-host hello protocol on the bridge port, which would clobber the
    // live connection via the generation guard - so we tell the user how to
    // check it themselves instead of probing.
    out.push_str(
        "\nnote: the checks above cover the MCP server + native-host bridge only.\n\
         They do NOT confirm the Chrome extension is loaded and connected. Verify\n\
         that via the Chromium Bridge toolbar icon (approve the target site) and\n\
         the extension's Service Worker console at chrome://extensions.\n",
    );

    out.push_str(&format!("\n{}\n", summary(r)));
    out
}

fn render_lock(out: &mut String, lock: &LockReport) {
    out.push_str(&format!("lock file:       {}\n", lock.path.display()));
    match &lock.state {
        LockState::Unreadable { detail } => {
            out.push_str(&format!("  present but unreadable: {detail}\n"));
        }
        LockState::Present {
            endpoint,
            pid,
            secret_len,
            ..
        } => {
            out.push_str("  present: yes\n");
            out.push_str(&format!("  endpoint: {endpoint}\n"));
            out.push_str(&format!("  pid:     {pid}\n"));
            out.push_str(&format!("  secret:  <redacted, {secret_len} chars>\n"));
        }
        LockState::Absent => {
            out.push_str("  present: no (MCP server not running?)\n");
        }
    }

    out.push_str("mcp server:      ");
    match &lock.state {
        LockState::Present {
            reachable: true, ..
        } => out.push_str("reachable (socket connect OK)\n"),
        LockState::Present {
            reachable: false, ..
        } => out.push_str("not reachable\n"),
        LockState::Absent | LockState::Unreadable { .. } => {
            out.push_str("not probed (no lock file)\n")
        }
    }
}

/// One-line status summary and the derived exit code hint.
fn summary(r: &Report) -> &'static str {
    // A refused runtime dir is the one cause behind an unreadable kill state and policy store too, so it is
    // named first.
    let Ok(lock) = &r.lock else {
        return "runtime dir refused - see the lock file line for the cause";
    };
    if r.kill == Ok(true) {
        return "kill switch ENGAGED - release it with `chromium-bridge unkill`";
    }
    if r.kill.is_err() {
        return "kill state unreadable - failing closed; see docs/troubleshooting.md";
    }
    // A present-but-unreadable policy store fails closed like the kill record.
    // A missing baseline (`none`) is the healthy pre-cutover state and must
    // NOT flip the verdict.
    if r.policy.store() == PolicyStoreState::Error {
        return "policy store present but unreadable - failing closed; see docs/troubleshooting.md";
    }
    match &lock.state {
        LockState::Unreadable { .. } => {
            "lock file present but unreadable - try restarting your MCP client"
        }
        LockState::Absent => "server not running - is your MCP client started?",
        LockState::Present {
            reachable: true, ..
        } if r.manifest_ok() => "OK",
        LockState::Present {
            reachable: true, ..
        } => {
            "server reachable, but no detected browser has a healthy native-host registration - run `chromium-bridge doctor --fix`"
        }
        LockState::Present { .. } => "server not reachable - is your MCP client running?",
    }
}

/// Exit code: 0 when healthy ("OK"), 1 otherwise.
fn exit_code(r: &Report) -> i32 {
    if summary(r) == "OK" {
        0
    } else {
        1
    }
}

/// `doctor --list`: one line per known browser and scope (detection,
/// registration state, pointer state, location). Read-only, resolver-only:
/// no lock file, no probe.
fn run_list() -> i32 {
    let (os, dirs) = match registration::resolve_env(Scope::User) {
        Ok(v) => v,
        Err(code) => return code,
    };
    println!("known browsers (host id {NATIVE_HOST_ID}):");
    for entry in browsers::resolve(os, &dirs) {
        let detected = if entry.installed() {
            "detected"
        } else {
            "not detected"
        };
        let rows = [
            (Scope::User, SlotStatus::assess(&entry.manifest.user)),
            (Scope::System, SlotStatus::assess(&entry.manifest.system)),
        ];
        for (scope, slot) in rows {
            let pointer = entry.pointer.as_ref().map_or_else(
                || "n/a".into(),
                |p| PointerStatus::assess(p.get(scope)).state.describe(),
            );
            println!(
                "  {:<9} {:<13} {:<7} manifest {:<10} pointer {:<10} {}",
                entry.browser.key(),
                detected,
                scope.key(),
                slot.state.describe(),
                pointer,
                slot.describe_location()
            );
        }
    }
    0
}

/// `doctor --paths`: the two paths through the pure resolver, which [`RuntimeDir::resolve`] keeps pure; a
/// refused runtime dir is the refusal itself.
fn paths_report() -> io::Result<String> {
    let dir = RuntimeDir::resolve()?;
    Ok(format!(
        "runtime dir:     {}\nlock file:       {}\n",
        dir.as_path().display(),
        LockFile::path_in(&dir).display()
    ))
}

/// Entry point for the `doctor` / `status` subcommand. Returns the process
/// exit code.
pub fn run(command: DoctorCommand) -> i32 {
    match command {
        DoctorCommand::List => run_list(),
        DoctorCommand::Paths => match paths_report() {
            Ok(text) => {
                print!("{text}");
                0
            }
            Err(e) => {
                eprintln!("doctor: {e}");
                1
            }
        },
        DoctorCommand::Fix { targets, scope } => registration::run_fix(&targets, scope),
        DoctorCommand::Report { json } => {
            let report = gather();
            if json {
                match serde_json::to_string(&report) {
                    Ok(line) => println!("{line}"),
                    Err(e) => {
                        eprintln!("doctor: {e}");
                        return 1;
                    }
                }
            } else {
                print!("{}", render(&report));
            }
            exit_code(&report)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy_report() -> Report {
        Report {
            v: REPORT_VERSION,
            version: "1.2.3",
            os: "macos",
            arch: "aarch64",
            lock: Ok(LockReport {
                path: PathBuf::from("/tmp/run.lock"),
                state: LockState::Present {
                    endpoint: "/tmp/chromium-bridge/run.sock".into(),
                    pid: 4242,
                    secret_len: 32,
                    reachable: true,
                },
            }),
            manifests: Ok(vec![
                ManifestStatus {
                    key: "chrome",
                    detected: true,
                    manifest: Scoped {
                        user: slot(RegState::Ok, "/tmp/com.vivswan.chromium_bridge.host.json", None),
                        system: slot(
                            RegState::Missing,
                            "/Library/Google/Chrome/NativeMessagingHosts/com.vivswan.chromium_bridge.host.json",
                            None,
                        ),
                    },
                    effective_scope: Scope::User,
                    pointer: Some(Scoped {
                        user: PointerStatus {
                            state: PointerState::Ok,
                            location:
                                "/tmp/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json"
                                    .into(),
                        },
                        system: PointerStatus {
                            state: PointerState::Missing,
                            location: "/Library/Application Support/Google/Chrome/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json".into(),
                        },
                    }),
                },
                ManifestStatus {
                    key: "brave",
                    detected: false,
                    manifest: Scoped {
                        user: slot(
                            RegState::Ok,
                            "/tmp/com.vivswan.chromium_bridge.host.json",
                            Some("chrome"),
                        ),
                        system: slot(
                            RegState::Missing,
                            "/Library/Google/Chrome/NativeMessagingHosts/com.vivswan.chromium_bridge.host.json",
                            Some("chrome"),
                        ),
                    },
                    effective_scope: Scope::User,
                    pointer: None,
                },
            ]),
            kill: Ok(false),
            policy: policy_report(PolicyStoreState::None),
        }
    }

    fn row(
        state: crate::protocol::control::RegistrationState,
        location: &str,
    ) -> crate::protocol::control::RegistrationRow {
        crate::protocol::control::RegistrationRow {
            browser: "chrome".into(),
            detected: true,
            state,
            location: location.into(),
        }
    }

    fn slot(state: RegState, location: &str, owner: Option<&'static str>) -> SlotStatus {
        SlotStatus {
            state,
            location: location.into(),
            owner,
        }
    }

    /// A `PolicyStatusReport` in a given store state, for the doctor row tests.
    fn policy_report(store: PolicyStoreState) -> PolicyStatusReport {
        match store {
            PolicyStoreState::None => PolicyStatusReport::None { v: 1 },
            PolicyStoreState::Present => PolicyStatusReport::Present {
                v: 1,
                revision: 3,
                signed: true,
                overlay_active: false,
                effective: crate::policy::PolicyValues::default(),
            },
            PolicyStoreState::Error => PolicyStatusReport::Error {
                v: 1,
                detail: "policy store decode: bad".into(),
            },
        }
    }

    #[test]
    fn render_healthy_is_ok() {
        let r = healthy_report();
        let text = render(&r);
        assert!(text.contains("v1.2.3"));
        assert!(text.contains("macos/aarch64"));
        assert!(text.contains("endpoint: /tmp/chromium-bridge/run.sock"));
        assert!(text.contains("pid:     4242"));
        assert!(text.contains("<redacted, 32 chars>"));
        // The real secret value must never appear.
        assert!(!text.contains("deadbeef"));
        assert!(text.contains("reachable (socket connect OK)"));
        // Per-browser manifest lines from the shared resolver.
        assert!(text.contains("host id com.vivswan.chromium_bridge.host"));
        // Both scopes per browser, and a shared directory named after its owner in either scope (Brave on
        // macOS reads Chrome's per-user directory too).
        assert!(text.contains("chrome    detected      user    manifest ok         /tmp/"));
        assert!(text.contains("system  manifest missing    /Library/Google/Chrome/"));
        assert!(text.contains(
            "NativeMessagingHosts/com.vivswan.chromium_bridge.host.json (reads chrome's)"
        ));
        assert!(text.contains(
            "brave     not detected  user    manifest ok         /tmp/com.vivswan.chromium_bridge.host.json (reads chrome's)"
        ));
        // The pointer rows beside each manifest: state and location per scope, or why Linux has none.
        assert!(text.contains("user    pointer  ok         /tmp/External Extensions/"));
        assert!(text.contains("system  pointer  missing    /Library/Application Support/Google/Chrome/External Extensions/"));
        assert!(text.contains(
            "        pointer  n/a        none on linux: Chrome would install the extension silently"
        ));
        // Honest note: green checks still don't prove the extension connected.
        assert!(text.contains("do NOT confirm the Chrome extension"));
        assert!(text.trim_end().ends_with("OK"));
        assert_eq!(exit_code(&r), 0);
    }

    #[test]
    fn a_missing_policy_baseline_is_healthy_pre_cutover() {
        // No baseline yet is the healthy pre-cutover state: it must render as
        // "none yet" and must NOT flip the verdict away from OK.
        let r = healthy_report();
        let text = render(&r);
        assert!(text.contains("policy baseline: none yet"));
        assert!(text.trim_end().ends_with("OK"));
        assert_eq!(exit_code(&r), 0);
    }

    #[test]
    fn a_present_policy_baseline_renders_signed_without_claiming_verification() {
        let mut r = healthy_report();
        r.policy = policy_report(PolicyStoreState::Present);
        let text = render(&r);
        assert!(text.contains("revision 3"));
        // Signed, but never self-certified here, and never "invalid".
        assert!(text.contains("verifies it against its pinned key, not here"));
        assert!(!text.contains("invalid"));
        // A present, signed baseline does not by itself change the verdict.
        assert_eq!(exit_code(&r), 0);
    }

    #[test]
    fn a_corrupt_policy_store_fails_closed() {
        // A present-but-unreadable store fails closed, flipping the exit code
        // like the kill-record-unreadable case.
        let mut r = healthy_report();
        r.policy = policy_report(PolicyStoreState::Error);
        let text = render(&r);
        assert!(text.contains("UNREADABLE ("));
        assert!(text.contains("policy store present but unreadable - failing closed"));
        assert_eq!(exit_code(&r), 1);
    }

    #[test]
    fn manifest_on_undetected_browser_alone_is_not_healthy() {
        // A manifest registered only for a browser this user does not have
        // will never be read; the summary must say so instead of "OK".
        let mut r = healthy_report();
        r.manifests.as_mut().unwrap()[0].detected = false;
        let text = render(&r);
        assert!(text.contains("run `chromium-bridge doctor --fix`"));
        assert_eq!(exit_code(&r), 1);
    }

    /// Chromium's lookup order, which the verdict and the wire row follow: the per-user entry wins when
    /// one exists, whatever it holds, the system one counts only in its absence, and an entry its
    /// existence probe skips (a dangling link, unreadable to us) does not shadow.
    #[test]
    fn verdict_follows_the_per_user_entry_first_then_the_system_one() {
        use crate::protocol::control::{RegistrationRow, RegistrationState};
        let user_path = "/tmp/com.vivswan.chromium_bridge.host.json";
        let system_path =
            "/Library/Google/Chrome/NativeMessagingHosts/com.vivswan.chromium_bridge.host.json";
        let cases: Vec<(&str, RegState, RegState, Scope, i32, RegistrationRow)> = vec![
            (
                "user ok shadows system missing",
                RegState::Ok,
                RegState::Missing,
                Scope::User,
                0,
                row(RegistrationState::Ok {}, user_path),
            ),
            (
                "system ok serves when user missing (the .deb)",
                RegState::Missing,
                RegState::Ok,
                Scope::System,
                0,
                row(RegistrationState::Ok {}, system_path),
            ),
            (
                "a foreign user file shadows a healthy system one",
                RegState::Foreign("other".into()),
                RegState::Ok,
                Scope::User,
                1,
                row(
                    RegistrationState::Foreign {
                        detail: "other".into(),
                    },
                    user_path,
                ),
            ),
            (
                "a stale user file shadows too",
                RegState::Stale("launch path missing: /x".into()),
                RegState::Ok,
                Scope::User,
                1,
                row(
                    RegistrationState::Stale {
                        detail: "launch path missing: /x".into(),
                    },
                    user_path,
                ),
            ),
            (
                "an unreadable user slot the lookup probe passed over serves the system one",
                RegState::Unreadable("a dangling symlink sits at this path".into()),
                RegState::Ok,
                Scope::System,
                0,
                row(RegistrationState::Ok {}, system_path),
            ),
            (
                "both missing",
                RegState::Missing,
                RegState::Missing,
                Scope::System,
                1,
                row(RegistrationState::Missing {}, system_path),
            ),
        ];
        for (case, user, system, effective_scope, exit, wire) in cases {
            let mut r = healthy_report();
            {
                let chrome = &mut r.manifests.as_mut().unwrap()[0];
                chrome.manifest.user.state = user;
                chrome.manifest.system.state = system;
                chrome.effective_scope = effective_scope;
            }
            assert_eq!(exit_code(&r), exit, "{case}");
            assert_eq!(
                RegistrationRow::from(&r.manifests.as_ref().unwrap()[0]),
                wire,
                "{case}"
            );
        }
    }

    #[test]
    fn render_missing_lock_reports_not_running() {
        let r = Report {
            v: REPORT_VERSION,
            version: "1.2.3",
            os: "linux",
            arch: "x86_64",
            lock: Ok(LockReport {
                path: PathBuf::from("/run/user/1000/chromium-bridge.lock"),
                state: LockState::Absent,
            }),
            manifests: Ok(vec![ManifestStatus {
                key: "chrome",
                detected: true,
                manifest: Scoped {
                    user: slot(
                        RegState::Missing,
                        "/home/user/.config/google-chrome/NativeMessagingHosts/com.vivswan.chromium_bridge.host.json",
                        None,
                    ),
                    system: slot(
                        RegState::Missing,
                        "/etc/opt/chrome/native-messaging-hosts/com.vivswan.chromium_bridge.host.json",
                        None,
                    ),
                },
                effective_scope: Scope::System,
                pointer: None,
            }]),
            kill: Ok(false),
            policy: policy_report(PolicyStoreState::None),
        };
        let text = render(&r);
        assert!(text.contains("user    manifest missing"));
        assert!(text.contains("system  manifest missing"));
        assert!(text.contains("not probed (no lock file)"));
        assert!(text.contains("server not running"));
        assert_eq!(exit_code(&r), 1);
    }

    #[test]
    fn unresolvable_environment_is_reported_not_hidden() {
        let mut r = healthy_report();
        r.manifests = Err("HOME (or USERPROFILE) is not set".into());
        let text = render(&r);
        assert!(text.contains("could not check: HOME"));
        // No verified manifest means not healthy.
        assert_eq!(exit_code(&r), 1);
    }

    /// Regression: with the kill check first, a refused runtime dir read as "kill state unreadable", since the kill
    /// record resolves the same dir.
    #[test]
    fn a_refused_runtime_dir_is_the_verdict_not_an_unreadable_kill_state() {
        let refused = "runtime dir refused: the bridge socket path /tmp/x/run.sock is 104 bytes, over the 103-byte sun_path limit; point XDG_RUNTIME_DIR at a shorter directory".to_string();
        let mut r = healthy_report();
        r.lock = Err(refused.clone());
        r.kill = Err(refused.clone());
        r.policy = PolicyStatusReport::Error {
            v: 1,
            detail: refused.clone(),
        };
        let text = render(&r);
        assert!(
            text.contains(&format!("lock file:       none ({refused})\n")),
            "{text}"
        );
        assert!(
            text.contains("mcp server:      not probed (no runtime dir)\n"),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "policy baseline: UNREADABLE ({refused}) - failing closed"
            )),
            "{text}"
        );
        assert!(
            text.ends_with("\nruntime dir refused - see the lock file line for the cause\n"),
            "{text}"
        );
        assert_eq!(exit_code(&r), 1);
    }

    /// tests/protocol/harness.py refuses a misrouted binary on what `doctor --paths` prints, before any child
    /// runs; that holds only while the resolver creates nothing, so an absent runtime dir must stay absent here.
    #[test]
    fn paths_name_an_absent_runtime_dir_without_creating_it() {
        let guard = crate::test_support::scratch_runtime_dir();
        let absent = guard.point_at_absent("never-made");
        let text = paths_report().unwrap();
        let dir = absent.join("chromium-bridge");
        assert_eq!(
            text,
            format!(
                "runtime dir:     {}\nlock file:       {}\n",
                dir.display(),
                dir.join("run.lock").display()
            )
        );
        assert!(
            !absent.exists(),
            "doctor --paths created {}",
            absent.display()
        );
    }

    #[cfg(unix)]
    #[test]
    fn probe_detects_open_and_closed_sockets() {
        use std::os::unix::net::UnixListener;

        // A live Unix-domain listener: probe must succeed.
        let dir = tempfile::Builder::new()
            .prefix("bb-doctor-probe-")
            .tempdir()
            .unwrap();
        let sock = dir.path().join("run.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let path = sock.to_string_lossy().into_owned();
        assert!(crate::ipc::probe_endpoint(&path));

        // Close it and unlink, then probe the now-dead socket: must fail.
        drop(listener);
        let _ = std::fs::remove_file(&sock);
        assert!(!crate::ipc::probe_endpoint(&path));
    }

    #[cfg(windows)]
    #[test]
    fn probe_detects_a_live_and_a_closed_pipe() {
        // External fact the probe rests on: a pipe name exists only while a
        // server holds an instance, so opening it succeeds against a live
        // broker and fails once the listener is gone.
        let _dir = crate::test_support::scratch_runtime_dir();
        let crate::ipc::PublishOutcome::Published(listener, lock) =
            crate::ipc::listen_and_publish().unwrap()
        else {
            panic!("a fresh scratch runtime dir has no live broker to lose to");
        };
        assert!(crate::ipc::probe_endpoint(&lock.endpoint));

        drop(listener);
        assert!(!crate::ipc::probe_endpoint(&lock.endpoint));
    }
}
