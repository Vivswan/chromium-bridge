//! Locate and drive the bundled `chromium-bridge` host binary.
//!
//! The app binary deliberately carries NO keychain entitlements (ADR-0026):
//! only the bundled host - the helper bundle with its own
//! keychain-access-groups entitlement and embedded provisioning profile - may
//! touch the Secure Enclave. Every Enclave operation the app offers (`pair`,
//! `revoke`, `enclave-status`) therefore runs the host as a subprocess and
//! consumes its output; the Touch ID prompt those operations raise attributes
//! to the signed host, the exact chain the 2026-07-17 proof exercised.
//! Everything else the app does (registration, kill switch, allowlist,
//! audit) is plain user-file I/O performed in-process through
//! `chromium_bridge_core`.
//!
//! Residual, named (threat #4, same as the CLI's registrations): the host is
//! selected by its path inside our own bundle, not by a hash - a same-user
//! process that can rewrite the .app can substitute it. The unforgeable
//! anchors live elsewhere: a substituted host cannot answer the extension's
//! pinned-key enclave challenges and does not carry the keychain access
//! group. The dev fallback (a sibling `chromium-bridge` in the target dir)
//! is compiled only into debug builds; a release app uses the helper bundle
//! path or refuses.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Candidate host locations for this app executable, in preference order:
/// the helper bundle inside the .app (the signed production layout,
/// ADR-0026), then - in debug builds only - a sibling binary in the same
/// directory (a plain `cargo` dev build, where both binaries land in
/// `target/debug/`).
pub fn host_candidates(exe: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(dir) = exe.parent() {
        if let Some(contents) = dir.parent() {
            out.push(contents.join("Helpers/chromium-bridge.app/Contents/MacOS/chromium-bridge"));
        }
        if cfg!(debug_assertions) {
            out.push(dir.join(host_binary_name()));
        }
    }
    out
}

fn host_binary_name() -> &'static str {
    if cfg!(windows) {
        "chromium-bridge.exe"
    } else {
        "chromium-bridge"
    }
}

/// Resolve the host binary this app manages, or a report of everywhere it
/// looked. No fallback beyond the two known layouts: guessing a host path
/// would register manifests pointing at a binary we cannot vouch for.
pub fn resolve_host() -> Result<PathBuf, String> {
    let exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .map_err(|e| format!("cannot resolve this app's own path: {e}"))?;
    let candidates = host_candidates(&exe);
    for c in &candidates {
        if c.is_file() {
            return Ok(c.clone());
        }
    }
    let looked: Vec<String> = candidates.iter().map(|p| p.display().to_string()).collect();
    Err(format!(
        "the chromium-bridge host binary was not found; looked at: {}. \
         In development, build it first (`cargo build`); the signed app \
         bundles it under Contents/Helpers.",
        looked.join(", ")
    ))
}

/// One captured host subprocess run. `transcript` interleaves stdout then
/// stderr; the host's subcommands print human-facing text on stdout and
/// diagnostics on stderr, and the app shows both verbatim.
pub struct HostRun {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

impl HostRun {
    pub fn transcript(&self) -> String {
        let mut t = self.stdout.trim_end().to_string();
        let err = self.stderr.trim_end();
        if !err.is_empty() {
            if !t.is_empty() {
                t.push('\n');
            }
            t.push_str(err);
        }
        t
    }
}

/// One ceremony at a time: concurrent `pair` runs would race the keychain
/// and stack Touch ID prompts. The UI disables its buttons while busy, but
/// the serialization belongs here, where the subprocess actually spawns.
static HOST_OP: Mutex<()> = Mutex::new(());

/// Run one host subcommand to completion and capture its output, serialized
/// across the app. No timeout: the Enclave subcommands legitimately wait on
/// a Touch ID prompt, and the system expires that prompt itself, so the
/// subprocess always terminates.
pub fn run_host(args: &[&str]) -> Result<HostRun, String> {
    let _serialized = HOST_OP
        .lock()
        .map_err(|_| "an earlier host operation panicked; restart the app".to_string())?;
    let host = resolve_host()?;
    let out = std::process::Command::new(&host)
        .args(args)
        .output()
        .map_err(|e| format!("could not run {}: {e}", host.display()))?;
    Ok(HostRun {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// The machine-readable enclave state, via `enclave-status --json` on the
/// bundled host, parsed into the core's typed [`EnclaveStatusReport`]. The
/// report version is checked FIRST so a newer host schema is refused loudly
/// (fail closed) before any other field is trusted; only then is the body
/// deserialized into the typed struct, whose `deny_unknown_fields` rejects an
/// unexpected shape rather than coercing it.
pub fn enclave_status_report() -> Result<chromium_bridge_core::enclave::EnclaveStatusReport, String>
{
    let run = run_host(&["enclave-status", "--json"])?;
    if !run.ok {
        return Err(format!("enclave-status failed: {}", run.transcript()));
    }
    parse_status_json(run.stdout.trim())
}

/// Parse and validate the host's `enclave-status --json` stdout. Split from
/// the subprocess call so the fail-closed rules are unit-testable without a
/// bundled host: the version gate runs before any field is trusted, and an
/// unrecognized shape is refused, not coerced.
fn parse_status_json(
    stdout: &str,
) -> Result<chromium_bridge_core::enclave::EnclaveStatusReport, String> {
    use chromium_bridge_core::enclave::EnclaveStatusReport;

    // Version gate FIRST: peek only `v` and refuse an unrecognized schema
    // before trusting any field below it. A host newer than this app is
    // rejected, never half-read.
    let raw: serde_json::Value = serde_json::from_str(stdout)
        .map_err(|e| format!("enclave-status --json did not return JSON: {e}"))?;
    if raw.get("v").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err(
            "enclave-status --json reported an unsupported schema version; \
             the bundled host is newer than this app"
                .to_string(),
        );
    }
    // Only now bind the fields to the typed report, deserializing from the
    // original bytes (not the `Value` above, which would already have collapsed
    // duplicate keys last-write-wins). The derived parse rejects duplicate
    // fields, an unknown field (`deny_unknown_fields`), or a mistyped value -
    // a strictly stronger check than trusting the free-form JSON as-is.
    serde_json::from_str::<EnclaveStatusReport>(stdout)
        .map_err(|e| format!("enclave-status --json had an unexpected shape: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_bundle_is_always_the_first_candidate() {
        let exe =
            Path::new("/Applications/Chromium Bridge.app/Contents/MacOS/chromium-bridge-desktop");
        let got = host_candidates(exe);
        assert_eq!(
            got.first(),
            Some(&PathBuf::from(
                "/Applications/Chromium Bridge.app/Contents/Helpers/chromium-bridge.app/Contents/MacOS/chromium-bridge"
            ))
        );
        // The sibling fallback exists only in debug builds; a release app
        // uses the helper bundle or refuses.
        if cfg!(debug_assertions) {
            assert_eq!(got.len(), 2);
        } else {
            assert_eq!(got.len(), 1);
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    fn dev_layout_finds_the_target_dir_sibling() {
        let exe = Path::new("/w/target/debug/chromium-bridge-desktop");
        let got = host_candidates(exe);
        assert!(got.contains(&PathBuf::from(format!(
            "/w/target/debug/{}",
            host_binary_name()
        ))));
    }

    #[test]
    fn transcript_joins_stdout_and_stderr() {
        let run = HostRun {
            ok: false,
            stdout: "line one\n".into(),
            stderr: "warning: two\n".into(),
        };
        assert_eq!(run.transcript(), "line one\nwarning: two");
        let quiet = HostRun {
            ok: true,
            stdout: "".into(),
            stderr: "".into(),
        };
        assert_eq!(quiet.transcript(), "");
    }

    #[test]
    fn parse_accepts_a_well_formed_v1_report() {
        let stdout = r#"{"key":"none","key_label":"com.vivswan.chromium-bridge.enclave.signing.v1","policy":{"enrolled":true,"granularity":"session"},"supported":true,"v":1}"#;
        let report = parse_status_json(stdout).expect("a v1 report parses");
        assert_eq!(report.v, 1);
        assert!(report.policy.is_some());
    }

    #[test]
    fn parse_refuses_an_unsupported_schema_version_first() {
        // A newer schema (v2), otherwise well-formed for v1: the version gate
        // must refuse it before trusting any field (fail closed).
        let stdout = r#"{"key":"none","key_label":"x","policy":null,"supported":true,"v":2}"#;
        let err = parse_status_json(stdout).expect_err("v2 must be refused");
        assert!(err.contains("unsupported schema version"), "got: {err}");
    }

    #[test]
    fn parse_refuses_a_missing_version() {
        let stdout = r#"{"key":"none","key_label":"x","policy":null,"supported":true}"#;
        let err = parse_status_json(stdout).expect_err("a missing v must be refused");
        assert!(err.contains("unsupported schema version"), "got: {err}");
    }

    #[test]
    fn parse_refuses_an_unrecognized_shape() {
        // v is 1, so the version gate passes, but the body carries an unknown
        // field: deny_unknown_fields makes this a loud refusal, not a silent
        // coercion of a shape this app does not understand.
        let stdout =
            r#"{"key":"none","key_label":"x","policy":null,"supported":true,"v":1,"surprise":1}"#;
        let err = parse_status_json(stdout).expect_err("an unknown field must be refused");
        assert!(err.contains("unexpected shape"), "got: {err}");
    }

    #[test]
    fn parse_refuses_non_json() {
        let err = parse_status_json("not json at all").expect_err("garbage must be refused");
        assert!(err.contains("did not return JSON"), "got: {err}");
    }

    #[test]
    fn parse_refuses_duplicate_keys() {
        // A `Value` peek collapses duplicate keys last-write-wins, so this
        // slips the version gate (v resolves to 1); the typed parse from the
        // original bytes must still refuse the duplicate `v` rather than
        // silently trust a smuggled value.
        let stdout = r#"{"v":2,"v":1,"supported":true,"key_label":"x","key":"none","policy":null}"#;
        let err = parse_status_json(stdout).expect_err("a duplicate key must be refused");
        assert!(err.contains("unexpected shape"), "got: {err}");
    }
}
