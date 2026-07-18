//! Revocation must never rewrite trust state without a trail entry: the
//! RevokeClient audit record is written by `Allowlist::revoke` itself, not by
//! its callers, so every surface - the CLI handler, the extension's
//! `client_revoke` control frame, the desktop app, and any future one -
//! inherits it instead of having to remember it.
//!
//! Lives in its own integration-test binary because it points the WHOLE
//! PROCESS's runtime directory at a scratch location via `XDG_RUNTIME_DIR`.
//! A separate test binary is a separate process under both `cargo test` and
//! nextest, so the env mutation cannot leak into, or race with, any other
//! test. Keep this binary single-purpose for that reason.

#![cfg(unix)]

use chromium_bridge_core::allowlist::{Allowlist, Anchor, ClientEntry};
use chromium_bridge_core::audit::{audit_path, AuditKind, AuditRecord, Surface};

#[test]
fn revoke_always_writes_an_audit_trail_entry() {
    // Isolate the runtime dir BEFORE anything resolves it.
    let dir = std::env::temp_dir().join(format!(
        "chromium-bridge-revoke-audit-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::env::set_var("XDG_RUNTIME_DIR", &dir);

    // Plant an enrolled allowlist directly: pairing through the API would
    // demand a user-presence proof, which tests must never raise.
    let list = Allowlist {
        version: 1,
        clients: vec![ClientEntry {
            name: "codex".into(),
            anchor: Anchor::Hash("ab".into()),
            added_unix: 0,
        }],
    };
    std::fs::write(Allowlist::path(), serde_json::to_vec(&list).unwrap()).unwrap();

    let revoke_records = || -> Vec<AuditRecord> {
        match std::fs::read_to_string(audit_path()) {
            Ok(text) => text
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .filter(|r: &AuditRecord| r.kind == AuditKind::RevokeClient)
                .collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => panic!("cannot read the audit trail: {e}"),
        }
    };

    assert!(Allowlist::revoke("codex", Surface::Cli).unwrap());
    let records = revoke_records();
    assert_eq!(records.len(), 1, "one removal, one trail entry");
    let rec = records.first().unwrap();
    assert_eq!(rec.surface, Some(Surface::Cli));
    assert_eq!(rec.name.as_deref(), Some("codex"));
    assert_eq!(rec.outcome.as_deref(), Some("ok"));

    // A no-op revoke (nothing removed) records nothing, exactly like the
    // caller-side emissions it replaced.
    assert!(!Allowlist::revoke("codex", Surface::Cli).unwrap());
    assert_eq!(revoke_records().len(), 1);
}
