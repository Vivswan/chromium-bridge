//! The two disposal seams side by side: the host-key-only one every `pair --reset` and extension revoke runs
//! through, and `revoke --all`'s, which also forgets every pairing. A test build's credential store always
//! answers empty, so the key under test is the file key.

use super::super::pubkey::EnclavePublicKey;
use super::*;
use crate::allowlist::{Anchor, ClientEntry, ClientName};
use crate::audit::{audit_path, AuditKind, AuditRecord};
use crate::ipc::{BrowserLabel, HashDigest};
use crate::presence::{PresenceAttestation, PresencePath};
use crate::runtime_record::RuntimeRecord as _;
use crate::test_support::scratch_runtime_dir;
use crate::webauthn::{CosePublicKey, Credential, CredentialId};

fn enrollment(browser: &str, seed: u8) -> Enrollment {
    let key = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
    Enrollment {
        label: BrowserLabel::parse(browser).unwrap(),
        credential: Credential {
            id: CredentialId::parse(vec![seed; 32]).unwrap(),
            public_key: CosePublicKey::from_sec1(&key.verifying_key().to_sec1_bytes()).unwrap(),
            sign_count: 0,
            backup_eligible: false,
        },
    }
}

fn client(name: &str) -> ClientEntry {
    ClientEntry {
        name: ClientName::try_from(name).unwrap(),
        anchor: Anchor::Hash(HashDigest::try_from("ab".repeat(20)).unwrap()),
        added_unix: 0,
    }
}

/// A machine mid-life: a file host key, two enrolled browsers, one trusted client (or never paired), and the
/// kill switch engaged.
fn plant(clients: Option<&[&str]>) {
    crate::ipc::with_runtime_lock(|lock| {
        EnrollmentKey::mint(
            lock,
            KeyStore::File,
            PresenceAttestation::assume_for_tests(PresencePath::Tty),
        )
        .unwrap();
        Trust::mutate_locked(lock, Scope::Kill, |t| {
            t.enroll(enrollment("brave", 0x31));
            t.enroll(enrollment("chrome", 0x41));
            for name in clients.into_iter().flatten() {
                t.pair(client(name));
            }
            t.set_killed(true);
        })
        .map(drop)
    })
    .unwrap();
}

fn trail() -> Vec<(AuditKind, Option<String>)> {
    std::fs::read_to_string(audit_path().unwrap())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<AuditRecord>(line).unwrap())
        .map(|r| (r.event_kind, r.name))
        .collect()
}

/// `revoke --all` is the one reset: the key and every pairing go in one critical section with the host-key
/// marker stamped, the kill latch stays, and the trail carries one entry per thing forgotten.
#[test]
fn revoke_all_forgets_every_pairing_keeps_the_kill_latch_and_writes_one_trail_entry_each() {
    let _dir = scratch_runtime_dir();
    plant(Some(&["codex"]));

    assert_eq!(run_revoke_all(), 0);

    let trust = TrustState::current().unwrap();
    assert!(
        EnrollmentKey::lookup().unwrap().is_none(),
        "the key is gone"
    );
    assert!(trust.enrollments().is_empty());
    assert_eq!(*trust.clients(), Clients::Paired(Vec::new()));
    assert!(trust.killed(), "a reset is not a release");
    assert_eq!(
        trust.host_key_epoch(),
        trust.epoch(),
        "the revocation push is keyed"
    );
    assert_eq!(
        trail(),
        vec![
            (AuditKind::HostKeyRevoke, None),
            (AuditKind::RevokeBrowser, Some("brave".into())),
            (AuditKind::RevokeBrowser, Some("chrome".into())),
            (AuditKind::RevokeClient, Some("codex".into())),
        ]
    );
}

/// A machine that never paired a client has no pairing to forget: the reset leaves the bootstrap posture
/// rather than locking every harness out.
#[test]
fn revoke_all_on_a_never_paired_machine_keeps_the_bootstrap_posture() {
    let _dir = scratch_runtime_dir();
    plant(None);

    let reset = dispose_everything(Surface::Cli).unwrap();

    let forgotten = reset.pairings.unwrap();
    assert_eq!(forgotten.enrollments.len(), 2);
    assert!(forgotten.clients.is_empty());
    assert_eq!(*forgotten.trust.clients(), Clients::NeverPaired);
    assert_eq!(
        *TrustState::current().unwrap().clients(),
        Clients::NeverPaired
    );
}

/// A reset whose baseline clear fails is reported as failed, while every part that committed is still done
/// and trailed: the user reads what happened, never a bare failure over a half-reset machine.
#[test]
fn revoke_all_reports_an_uncleared_baseline_and_still_trails_what_it_forgot() {
    let _dir = scratch_runtime_dir();
    plant(Some(&["codex"]));
    std::fs::write(
        crate::policy::PolicyStore::path().unwrap(),
        b"{ not a policy record",
    )
    .unwrap();

    assert_eq!(run_revoke_all(), 1);

    let trust = TrustState::current().unwrap();
    assert!(EnrollmentKey::lookup().unwrap().is_none());
    assert!(trust.enrollments().is_empty());
    assert_eq!(*trust.clients(), Clients::Paired(Vec::new()));
    assert_eq!(trail().len(), 4, "{:?}", trail());
}

/// The host-key-only seam (`pair --reset`, the extension's `enclave_revoke`) shares the critical section but
/// must not forget a single pairing: the two seams differ in exactly the record edit.
#[test]
fn the_host_key_disposal_leaves_every_pairing_in_place() {
    let _dir = scratch_runtime_dir();
    plant(Some(&["codex"]));
    let before = TrustState::current().unwrap();

    let revoked = dispose_enrollment_and_policy_baseline().unwrap();

    assert!(revoked.existed());
    assert!(EnrollmentKey::lookup().unwrap().is_none());
    let after = TrustState::current().unwrap();
    assert_eq!(after.enrollments(), before.enrollments());
    assert_eq!(after.clients(), before.clients());
    assert!(after.killed());
    assert_eq!(after.host_key_epoch(), after.epoch());
}

/// `enclave-status --json` is the CLI's machine-readable contract: the bytes, sorted keys and each state's
/// exact field set are pinned at the one place they leave the program.
#[test]
fn json_report_wire_bytes_for_each_key_state() {
    let mut bytes = vec![0x04u8];
    bytes.extend(std::iter::repeat_n(0xabu8, 64));
    let public = EnclavePublicKey::from_x963(bytes).unwrap();
    let (b64, fingerprint) = (public.to_base64(), public.fingerprint_display());
    let label = KEY_LABEL.to_string();
    let cases = [
        (
            EnclaveStatusReport::Present {
                v: 1,
                key_label: label.clone(),
                store: KeyStore::File,
                public_key_b64: b64.clone(),
                fingerprint: fingerprint.clone(),
            },
            format!(
                "{{\"fingerprint\":\"{fingerprint}\",\"key\":\"present\",\"key_label\":\"{KEY_LABEL}\",\
                 \"public_key_b64\":\"{b64}\",\"store\":\"file\",\"v\":1}}"
            ),
        ),
        (
            EnclaveStatusReport::None {
                v: 1,
                key_label: label.clone(),
            },
            format!("{{\"key\":\"none\",\"key_label\":\"{KEY_LABEL}\",\"v\":1}}"),
        ),
        (
            EnclaveStatusReport::Invalid {
                v: 1,
                key_label: label.clone(),
                detail: "planted scalar".into(),
            },
            format!(
                "{{\"detail\":\"planted scalar\",\"key\":\"invalid\",\"key_label\":\"{KEY_LABEL}\",\"v\":1}}"
            ),
        ),
        (
            EnclaveStatusReport::Error {
                v: 1,
                key_label: label,
                detail: "store unreachable".into(),
            },
            format!(
                "{{\"detail\":\"store unreachable\",\"key\":\"error\",\"key_label\":\"{KEY_LABEL}\",\"v\":1}}"
            ),
        ),
    ];
    for (report, want) in cases {
        let emitted = serde_json::to_value(&report).unwrap().to_string();
        assert_eq!(emitted, want);
        let back: EnclaveStatusReport = serde_json::from_str(&emitted).unwrap();
        assert_eq!(back, report, "round trip");
    }
}
