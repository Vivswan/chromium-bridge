//! `doctor` / `status`: diagnosis, and (only with `--fix`) repair.
//!
//! Plain `doctor` prints a health report without touching the browser,
//! spawning processes, or killing anything. It only reads the lock file, does
//! a passive connect probe against our OWN bridge socket (no bytes sent), and
//! diagnoses each browser's native-messaging registration
//! (missing/ok/stale/foreign) through the shared resolver in
//! `crate::browsers`. `doctor --list` is the short, resolver-only form of
//! that report. `doctor --fix` hands the diagnosis to
//! `crate::registration` for an idempotent repair; on a fresh machine that
//! repair IS the registration. The app registers through the same
//! engine; app and CLI are co-equal surfaces (see docs/cli.md).

use std::path::PathBuf;
#[cfg(windows)]
use std::time::Duration;

use crate::browsers::{self, BaseDirs, Os, HOST_ID};
use crate::ipc::LockFile;
use crate::registration::{self, RegState};

/// Plain facts gathered for the report. Kept free of I/O so `render` is pure
/// and unit-testable.
#[derive(Debug, Clone)]
struct Report {
    version: &'static str,
    os: &'static str,
    arch: &'static str,
    lock_path: PathBuf,
    /// The lock file, classified once at gather time. Each state carries
    /// exactly the facts it has - contradictory reports (an endpoint without
    /// a lock file, a parse error beside a pid) cannot be constructed.
    lock: LockState,
    /// Per known browser: detection and manifest registration, in
    /// `Browser::ALL` order - or the reason the check could not run at all
    /// (e.g. no HOME).
    manifests: Result<Vec<ManifestStatus>, String>,
    /// The global kill switch (ADR-0030). `Ok(bool)` from a readable
    /// revocation record; `Err(text)` when the record is unreadable (in which
    /// case every enforcement point is failing closed).
    kill: Result<bool, String>,
}

/// The lock file's classification: exactly absent, present-but-unreadable, or
/// parsed (with the probe result the endpoint allowed). Mirrors the three-way
/// result of `LockFile::read()`.
#[derive(Debug, Clone)]
enum LockState {
    /// No lock file: server not running.
    Absent,
    /// The file exists but did not read/parse.
    Unreadable(String),
    /// Parsed; `reachable` is the passive connect probe against `endpoint`.
    Running {
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
#[derive(Debug, Clone)]
struct ManifestStatus {
    key: &'static str,
    detected: bool,
    state: RegState,
    location: String,
}

impl ManifestStatus {
    fn healthy(&self) -> bool {
        self.state == RegState::Ok
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

/// Passive reachability probe: connect to our own bridge socket and drop the
/// connection immediately. No command bytes are ever sent. Public so the
/// desktop app's status view (ADR-0029) shares the exact probe `doctor`
/// reports with.
pub fn probe(endpoint: &str) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::net::UnixStream::connect(endpoint).is_ok()
    }
    #[cfg(windows)]
    {
        let addr = match endpoint.parse() {
            Ok(a) => a,
            Err(_) => return false,
        };
        std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok()
    }
}

/// Gather the per-browser manifest states (read-only), or the reason the
/// check could not run.
fn gather_manifests() -> Result<Vec<ManifestStatus>, String> {
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
fn gather() -> Report {
    let lock = match LockFile::read() {
        Ok(Some(lf)) => LockState::Running {
            reachable: probe(&lf.endpoint),
            secret_len: lf.secret.len(),
            pid: lf.pid,
            endpoint: lf.endpoint,
        },
        Ok(None) => LockState::Absent,
        // File exists but did not read/parse. Present-but-broken.
        Err(e) => LockState::Unreadable(e.to_string()),
    };

    Report {
        version: env!("CARGO_PKG_VERSION"),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        lock_path: LockFile::path(),
        lock,
        manifests: gather_manifests(),
        kill: crate::kill::is_killed().map_err(|e| e.to_string()),
    }
}

/// Pure rendering of a gathered report into the printed health text.
fn render(r: &Report) -> String {
    let mut out = String::new();
    out.push_str(&format!("chromium-bridge doctor - v{}\n", r.version));
    out.push_str(&format!("platform:        {}/{}\n", r.os, r.arch));

    out.push_str(&format!("lock file:       {}\n", r.lock_path.display()));
    match &r.lock {
        LockState::Unreadable(err) => {
            out.push_str(&format!("  present but unreadable: {err}\n"));
        }
        LockState::Running {
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
        LockState::Running {
            reachable: true, ..
        } => out.push_str("reachable (socket connect OK)\n"),
        LockState::Running {
            reachable: false, ..
        } => out.push_str("not reachable\n"),
        LockState::Absent | LockState::Unreadable(_) => out.push_str("not probed (no lock file)\n"),
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

    out.push_str(&format!("native manifests: (host id {HOST_ID})\n"));
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
    match &r.lock {
        LockState::Unreadable(_) => {
            "lock file present but unreadable - try restarting your MCP client"
        }
        LockState::Absent => "server not running - is your MCP client started?",
        LockState::Running {
            reachable: true, ..
        } if r.manifest_ok() => "OK",
        LockState::Running {
            reachable: true, ..
        } => {
            "server reachable, but no detected browser has a healthy native-host registration - run `chromium-bridge doctor --fix`"
        }
        LockState::Running { .. } => "server not reachable - is your MCP client running?",
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
    println!("known browsers (host id {HOST_ID}):");
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

/// Entry point for the `doctor` / `status` subcommand: report by default,
/// `--list` for the short listing, `--fix` to repair/register.
pub fn run(argv: &[String]) -> i32 {
    let cmd = match crate::cli::doctor_args(argv) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("doctor: {e}");
            return 2;
        }
    };
    match cmd {
        crate::cli::DoctorCommand::List => run_list(),
        crate::cli::DoctorCommand::Fix(targets) => registration::run_fix(&targets),
        crate::cli::DoctorCommand::Report => {
            let report = gather();
            print!("{}", render(&report));
            exit_code(&report)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy_report() -> Report {
        Report {
            version: "1.2.3",
            os: "macos",
            arch: "aarch64",
            lock_path: PathBuf::from("/tmp/run.lock"),
            lock: LockState::Running {
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

    #[cfg(unix)]
    #[test]
    fn probe_detects_open_and_closed_sockets() {
        use std::os::unix::net::UnixListener;

        // A live Unix-domain listener: probe must succeed.
        let dir = std::env::temp_dir().join(format!("bb-doctor-probe-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let sock = dir.join("run.sock");
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).unwrap();
        let path = sock.to_string_lossy().into_owned();
        assert!(probe(&path));

        // Close it and unlink, then probe the now-dead socket: must fail.
        drop(listener);
        let _ = std::fs::remove_file(&sock);
        assert!(!probe(&path));
    }

    #[cfg(windows)]
    #[test]
    fn probe_detects_open_and_closed_ports() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        assert!(probe(&endpoint));

        drop(listener);
        assert!(!probe(&endpoint));
    }
}
