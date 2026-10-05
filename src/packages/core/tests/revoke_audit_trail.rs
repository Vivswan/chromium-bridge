//! Revocation must never rewrite trust state without a trail entry: the
//! RevokeClient audit record is written by `allowlist::revoke` itself, not by
//! its callers, so every surface - the CLI handler, the extension's
//! `client_revoke` control frame, and any future one -
//! inherits it instead of having to remember it.
//!
//! Lives in its own integration-test binary because it points the WHOLE
//! PROCESS's runtime directory at a scratch location via `XDG_RUNTIME_DIR`.
//! A separate test binary is a separate process under both `cargo test` and
//! nextest, so the env mutation cannot leak into, or race with, any other
//! test. Keep this binary single-purpose for that reason.

#![cfg(unix)]

use chromium_bridge_core::allowlist;
use chromium_bridge_core::audit::{audit_path, AuditKind, AuditRecord, Surface};
use chromium_bridge_core::runtime_record::RuntimeRecord as _;
use chromium_bridge_core::trust::Trust;

#[test]
fn revoke_always_writes_an_audit_trail_entry() {
    // Isolate the runtime dir BEFORE anything resolves it; the TempDir is removed on every exit, a failed
    // assertion included. Short on purpose: the socket path beneath it must fit sun_path (ipc/runtime_dir.rs).
    let dir = tempfile::Builder::new().prefix("bbt-").tempdir().unwrap();
    std::env::set_var("XDG_RUNTIME_DIR", dir.path());

    // Plant a paired client as the bytes on disk: pairing through the API would demand a user-presence
    // proof, which tests must never raise, and the record's fields are private to the trust module.
    let record = format!(
        r#"{{"version":{},"epoch":1,"killed":false,"kill_epoch":0,"host_key_epoch":0,"policy_epoch":0,"lang_epoch":0,"clients":[{{"name":"codex","anchor":{{"kind":"hash","value":"{}"}},"added_unix":0}}]}}"#,
        Trust::VERSION,
        "ab".repeat(20)
    );
    std::fs::write(Trust::path().unwrap(), record).unwrap();

    let revoke_records = || -> Vec<AuditRecord> {
        match std::fs::read_to_string(audit_path().unwrap()) {
            Ok(text) => text
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .filter(|r: &AuditRecord| r.event_kind == AuditKind::RevokeClient)
                .collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => panic!("cannot read the audit trail: {e}"),
        }
    };

    assert!(allowlist::revoke("codex", Surface::Cli).unwrap());
    let records = revoke_records();
    assert_eq!(records.len(), 1, "one removal, one trail entry");
    let rec = records.first().unwrap();
    assert_eq!(rec.surface, Some(Surface::Cli));
    assert_eq!(rec.name.as_deref(), Some("codex"));
    assert_eq!(rec.outcome.as_deref(), Some("ok"));

    // A no-op revoke (nothing removed) records nothing, exactly like the
    // caller-side emissions it replaced.
    assert!(!allowlist::revoke("codex", Surface::Cli).unwrap());
    assert_eq!(revoke_records().len(), 1);
}
