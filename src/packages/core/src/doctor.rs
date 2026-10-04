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

use std::path::PathBuf;

use serde::Serialize;

use crate::browsers::{self, BaseDirs, Os};
use crate::cli::DoctorCommand;
use crate::identity::NATIVE_HOST_ID;
use crate::ipc::{resolve_runtime_dir, LockFile};
use crate::policy::{PolicyStatusReport, PolicyStoreState};
use crate::registration::{self, RegState};

/// Schema version of the serialized [`Report`]. Like every `--json` report of
/// this binary, a consumer checks `v` first and refuses a newer value.
pub const REPORT_VERSION: u32 = 1;

/// Plain facts gathered for the report, free of I/O so every renderer over it is pure. The serialized form is
/// what `doctor --json` prints and what other readers of the host's health consume.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub v: u32,
    pub version: &'static str,
    pub os: &'static str,
    pub arch: &'static str,
    #[serde(serialize_with = "crate::audit::serialize_path_lossy")]
    pub lock_path: PathBuf,
    /// The lock file, classified once at gather time. Each state carries
    /// exactly the facts it has - contradictory reports (an endpoint without
    /// a lock file, a parse error beside a pid) cannot be constructed.
    pub lock: LockState,
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

/// One browser's registration state, as diagnosed through the shared
/// resolver and `registration::assess`. Stores the assessed [`RegState`]
/// itself; the rendered wording and the health verdict are derived at use,
/// so they cannot disagree with each other.
#[derive(Debug, Clone, Serialize)]
pub struct ManifestStatus {
    pub key: &'static str,
    pub detected: bool,
    pub state: RegState,
    pub location: String,
}

impl ManifestStatus {
    fn healthy(&self) -> bool {
        self.state == RegState::Ok
    }
}

impl From<&ManifestStatus> for crate::protocol::control::RegistrationRow {
    fn from(status: &ManifestStatus) -> Self {
        crate::protocol::control::RegistrationRow {
            browser: status.key.to_string(),
            detected: status.detected,
            state: (&status.state).into(),
            location: status.location.clone(),
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
    let dirs = BaseDirs::from_env()?;
    Ok(browsers::resolve(Os::current(), &dirs)
        .iter()
        .map(|entry| ManifestStatus {
            key: entry.browser.key(),
            detected: entry.detected(),
            state: registration::assess(&entry.registration),
            location: entry.registration.location(),
        })
        .collect())
}

/// Gather the report by reading (never mutating) local state.
pub fn gather() -> Report {
    let lock = match LockFile::read() {
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
    };

    Report {
        v: REPORT_VERSION,
        version: env!("CARGO_PKG_VERSION"),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        lock_path: LockFile::path(),
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

    out.push_str(&format!("lock file:       {}\n", r.lock_path.display()));
    match &r.lock {
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
    match &r.lock {
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

    out.push_str("kill switch:     ");
    match &r.kill {
        Ok(false) => out.push_str("off (bridge activity permitted)\n"),
        Ok(true) => out
            .push_str("ENGAGED - all bridge activity is refused until `chromium-bridge unkill`\n"),
        Err(e) => out.push_str(&format!(
            "state UNREADABLE ({e}) - every enforcement point is failing closed;\n  \
             see docs/operations.md for recovery\n"
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
            "present but UNREADABLE ({detail}) - failing closed; see docs/operations.md\n",
        )),
    }

    out.push_str(&format!("native manifests: (host id {NATIVE_HOST_ID})\n"));
    match &r.manifests {
        Err(err) => out.push_str(&format!("  could not check: {err}\n")),
        Ok(list) => {
            for m in list {
                out.push_str(&format!(
                    "  {:<9} {:<13} manifest {:<8} {}\n",
                    m.key,
                    if m.detected {
                        "detected"
                    } else {
                        "not detected"
                    },
                    m.state.describe(),
                    m.location,
                ));
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

/// One-line status summary and the derived exit code hint.
fn summary(r: &Report) -> &'static str {
    if r.kill == Ok(true) {
        return "kill switch ENGAGED - release it with `chromium-bridge unkill`";
    }
    if r.kill.is_err() {
        return "kill state unreadable - failing closed; see docs/operations.md";
    }
    // A present-but-unreadable policy store fails closed like the kill record.
    // A missing baseline (`none`) is the healthy pre-cutover state and must
    // NOT flip the verdict.
    if r.policy.store() == PolicyStoreState::Error {
        return "policy store present but unreadable - failing closed; see docs/operations.md";
    }
    match &r.lock {
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

/// `doctor --list`: one line per known browser (detection, registration
/// state, location). Read-only, resolver-only: no lock file, no probe.
fn run_list() -> i32 {
    let (os, dirs) = match registration::resolve_env() {
        Ok(v) => v,
        Err(code) => return code,
    };
    println!("known browsers (host id {NATIVE_HOST_ID}):");
    for entry in browsers::resolve(os, &dirs) {
        println!(
            "  {:<9} {:<13} {:<30} {}",
            entry.browser.key(),
            if entry.detected() {
                "detected"
            } else {
                "not detected"
            },
            registration::assess(&entry.registration).describe(),
            entry.registration.location()
        );
    }
    0
}

/// `doctor --paths`: the two paths through the pure resolver; [`resolve_runtime_dir`] owns why it must stay pure.
fn paths_report() -> String {
    let dir = resolve_runtime_dir();
    format!(
        "runtime dir:     {}\nlock file:       {}\n",
        dir.display(),
        LockFile::path_in(&dir).display()
    )
}

/// Entry point for the `doctor` / `status` subcommand. Returns the process
/// exit code.
pub fn run(command: DoctorCommand) -> i32 {
    match command {
        DoctorCommand::List => run_list(),
        DoctorCommand::Paths => {
            print!("{}", paths_report());
            0
        }
        DoctorCommand::Fix(targets) => registration::run_fix(&targets),
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
            lock_path: PathBuf::from("/tmp/run.lock"),
            lock: LockState::Present {
                endpoint: "/tmp/chromium-bridge/run.sock".into(),
                pid: 4242,
                secret_len: 32,
                reachable: true,
            },
            manifests: Ok(vec![
                ManifestStatus {
                    key: "chrome",
                    detected: true,
                    state: RegState::Ok,
                    location: "/tmp/com.vivswan.chromium_bridge.host.json".into(),
                },
                ManifestStatus {
                    key: "brave",
                    detected: false,
                    state: RegState::Missing,
                    location: "/tmp/brave/com.vivswan.chromium_bridge.host.json".into(),
                },
            ]),
            kill: Ok(false),
            policy: policy_report(PolicyStoreState::None),
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
        assert!(text.contains("chrome"));
        assert!(text.contains("manifest ok"));
        assert!(text.contains("manifest missing"));
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
        assert!(text.contains("present but UNREADABLE"));
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

    #[test]
    fn render_missing_lock_reports_not_running() {
        let r = Report {
            v: REPORT_VERSION,
            version: "1.2.3",
            os: "linux",
            arch: "x86_64",
            lock_path: PathBuf::from("/run/user/1000/chromium-bridge.lock"),
            lock: LockState::Absent,
            manifests: Ok(vec![ManifestStatus {
                key: "chrome",
                detected: true,
                state: RegState::Missing,
                location:
                    "/home/u/.config/google-chrome/NativeMessagingHosts/com.vivswan.chromium_bridge.host.json"
                        .into(),
            }]),
            kill: Ok(false),
            policy: policy_report(PolicyStoreState::None),
        };
        let text = render(&r);
        assert!(text.contains("manifest missing"));
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

    /// tests/protocol/harness.py refuses a misrouted binary on what `doctor --paths` prints, before any child
    /// runs; that holds only while the resolver creates nothing, so an absent runtime dir must stay absent here.
    #[test]
    fn paths_name_an_absent_runtime_dir_without_creating_it() {
        let guard = crate::test_support::scratch_runtime_dir("doctor-paths");
        let absent = guard.point_at_absent("never-made");
        let text = paths_report();
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
        let _dir = crate::test_support::scratch_runtime_dir("doctor-probe");
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
