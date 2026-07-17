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
//! repair IS the registration. The app self-registers through the same
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
    lock_present: bool,
    /// `Some(err)` when the lock file exists but could not be parsed.
    lock_error: Option<String>,
    endpoint: Option<String>,
    pid: Option<u32>,
    secret_len: Option<usize>,
    /// `None` when no probe was attempted (no lock file / no endpoint).
    reachable: Option<bool>,
    /// Per known browser: detection and manifest registration, in
    /// `Browser::ALL` order. Empty only when the environment could not be
    /// resolved (see `manifest_error`).
    manifests: Vec<ManifestStatus>,
    /// Why the manifest check could not run (e.g. no HOME).
    manifest_error: Option<String>,
}

/// One browser's registration state, as diagnosed through the shared
/// resolver and `registration::assess`.
#[derive(Debug, Clone)]
struct ManifestStatus {
    key: &'static str,
    detected: bool,
    /// `RegState::describe()` output: ok/missing/stale/... with the reason.
    state: String,
    healthy: bool,
    location: String,
}

impl Report {
    /// Whether any browser this user actually has picks up a healthy
    /// registration.
    fn manifest_ok(&self) -> bool {
        self.manifests.iter().any(|m| m.detected && m.healthy)
    }
}

/// Passive reachability probe: connect to our own bridge socket and drop the
/// connection immediately. No command bytes are ever sent.
fn probe(endpoint: &str) -> bool {
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

/// Gather the per-browser manifest states (read-only).
fn gather_manifests() -> (Vec<ManifestStatus>, Option<String>) {
    let dirs = match BaseDirs::from_env() {
        Ok(d) => d,
        Err(e) => return (Vec::new(), Some(e)),
    };
    let statuses = browsers::resolve(Os::current(), &dirs)
        .iter()
        .map(|entry| {
            let state = registration::assess(&entry.registration);
            ManifestStatus {
                key: entry.browser.key(),
                detected: entry.detected(),
                healthy: state == RegState::Ok,
                state: state.describe(),
                location: entry.registration.location(),
            }
        })
        .collect();
    (statuses, None)
}

/// Gather the report by reading (never mutating) local state.
fn gather() -> Report {
    let lock_path = LockFile::path();
    let (manifests, manifest_error) = gather_manifests();

    let mut report = Report {
        version: env!("CARGO_PKG_VERSION"),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        lock_path,
        lock_present: false,
        lock_error: None,
        endpoint: None,
        pid: None,
        secret_len: None,
        reachable: None,
        manifests,
        manifest_error,
    };

    match LockFile::read() {
        Ok(Some(lf)) => {
            report.lock_present = true;
            report.reachable = Some(probe(&lf.endpoint));
            report.endpoint = Some(lf.endpoint);
            report.pid = Some(lf.pid);
            report.secret_len = Some(lf.secret.len());
        }
        Ok(None) => {
            // No lock file: server not running. Leave defaults.
        }
        Err(e) => {
            // File exists but did not read/parse. Treat as present-but-broken.
            report.lock_present = true;
            report.lock_error = Some(e.to_string());
        }
    }

    report
}

/// Pure rendering of a gathered report into the printed health text.
fn render(r: &Report) -> String {
    let mut out = String::new();
    out.push_str(&format!("chromium-bridge doctor — v{}\n", r.version));
    out.push_str(&format!("platform:        {}/{}\n", r.os, r.arch));

    out.push_str(&format!("lock file:       {}\n", r.lock_path.display()));
    if let Some(err) = &r.lock_error {
        out.push_str(&format!("  present but unreadable: {err}\n"));
    } else if r.lock_present {
        out.push_str("  present: yes\n");
        if let Some(endpoint) = &r.endpoint {
            out.push_str(&format!("  endpoint: {endpoint}\n"));
        }
        if let Some(pid) = r.pid {
            out.push_str(&format!("  pid:     {pid}\n"));
        }
        if let Some(len) = r.secret_len {
            out.push_str(&format!("  secret:  <redacted, {len} chars>\n"));
        }
    } else {
        out.push_str("  present: no (MCP server not running?)\n");
    }

    out.push_str("mcp server:      ");
    match r.reachable {
        Some(true) => out.push_str("reachable (socket connect OK)\n"),
        Some(false) => out.push_str("not reachable\n"),
        None => out.push_str("not probed (no lock file)\n"),
    }

    out.push_str(&format!("native manifests: (host id {HOST_ID})\n"));
    if let Some(err) = &r.manifest_error {
        out.push_str(&format!("  could not check: {err}\n"));
    }
    for m in &r.manifests {
        out.push_str(&format!(
            "  {:<9} {:<13} manifest {:<8} {}\n",
            m.key,
            if m.detected {
                "detected"
            } else {
                "not detected"
            },
            m.state,
            m.location,
        ));
    }

    // These probes only cover the MCP-server/bridge side. doctor cannot observe
    // whether the Chrome extension is loaded and connected without speaking the
    // native-host hello protocol on the bridge port, which would clobber the
    // live connection via the generation guard — so we tell the user how to
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
    if r.lock_error.is_some() {
        return "lock file present but unreadable — try restarting your MCP client";
    }
    if !r.lock_present {
        return "server not running — is your MCP client started?";
    }
    match r.reachable {
        Some(true) if r.manifest_ok() => "OK",
        Some(true) => {
            "server reachable, but no detected browser has a healthy native-host registration — run `chromium-bridge doctor --fix`"
        }
        _ => "server not reachable — is your MCP client running?",
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
    let args = match crate::cli::doctor_args(argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("doctor: {e}");
            return 2;
        }
    };
    if args.list {
        return run_list();
    }
    if args.fix {
        return registration::run_fix(&args);
    }
    let report = gather();
    print!("{}", render(&report));
    exit_code(&report)
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
            lock_present: true,
            lock_error: None,
            endpoint: Some("/tmp/chromium-bridge/run.sock".into()),
            pid: Some(4242),
            secret_len: Some(32),
            reachable: Some(true),
            manifests: vec![
                ManifestStatus {
                    key: "chrome",
                    detected: true,
                    state: "ok".into(),
                    healthy: true,
                    location: "/tmp/com.vivswan.chromium_bridge.host.json".into(),
                },
                ManifestStatus {
                    key: "brave",
                    detected: false,
                    state: "missing".into(),
                    healthy: false,
                    location: "/tmp/brave/com.vivswan.chromium_bridge.host.json".into(),
                },
            ],
            manifest_error: None,
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
        r.manifests[0].detected = false;
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
            lock_present: false,
            lock_error: None,
            endpoint: None,
            pid: None,
            secret_len: None,
            reachable: None,
            manifests: vec![ManifestStatus {
                key: "chrome",
                detected: true,
                state: "missing".into(),
                healthy: false,
                location:
                    "/home/u/.config/google-chrome/NativeMessagingHosts/com.vivswan.chromium_bridge.host.json"
                        .into(),
            }],
            manifest_error: None,
        };
        let text = render(&r);
        assert!(text.contains("present: no"));
        assert!(text.contains("not probed (no lock file)"));
        assert!(text.contains("server not running"));
        assert_eq!(exit_code(&r), 1);
    }

    #[test]
    fn unresolvable_environment_is_reported_not_hidden() {
        let mut r = healthy_report();
        r.manifests = Vec::new();
        r.manifest_error = Some("HOME (or USERPROFILE) is not set".into());
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
