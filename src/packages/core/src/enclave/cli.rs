//! CLI runners: `pair` / `revoke` / `enclave-status`.

use serde::{Deserialize, Serialize};

use super::key::{EnrollmentKey, Revoked, StoreOutcome};
use super::record::KeyStore;
use super::{EnclaveError, KEY_LABEL};
use crate::presence::{self, TerminalStdin};

/// `chromium-bridge pair [--reset] [--file-store]`: mint the host identity key and print the fingerprint the
/// user compares against the extension's enrollment screen. Minting is a capability grant (the extension will
/// pin what it sees), so it runs behind the terminal witness and the typed phrase: a background script's
/// `pair` is refused before anything is read or written. The key goes to the OS credential store unless the
/// user names the file record; a store that refuses or does not answer fails the command and says so, never a
/// silent fallback to the weaker place.
///
/// ```text
/// a key already exists   -> `mint` refuses under its lock without --reset; `pair` never adopts a key it did not
///                           mint in this run, since a same-user process can plant one
/// --reset                -> after the phrase, disposes before minting; a store that does not answer stops a store
///                           pairing here and only warns a file pairing (that is what `--file-store` is for)
/// phrase declined        -> nothing disposed, nothing minted: the machine is exactly as it was
/// ```
pub fn run_pair(reset: bool, file_store: bool) -> i32 {
    let store = if file_store {
        KeyStore::File
    } else {
        KeyStore::CredentialStore
    };
    let terminal = match TerminalStdin::require() {
        Ok(terminal) => terminal,
        Err(e) => {
            println!("pair: refused - {e}");
            return 1;
        }
    };

    let auth = match presence::tty_confirm(
        "Pairing mints the identity key the extension will pin; every policy grant this host signs \
         will be verified against it.",
        terminal,
    ) {
        Ok(auth) => auth,
        Err(e) => {
            println!("pairing was not approved ({e}); nothing was changed.");
            return 1;
        }
    };

    if reset {
        match dispose_enrollment_and_policy_baseline() {
            Ok(revoked) => {
                audit_host_key_revoke(crate::audit::Surface::Cli, &revoked);
                if let StoreOutcome::Unanswered(e) = &revoked.store {
                    if !file_store {
                        println!("pair --reset could not consult the credential store: {e}");
                        return 1;
                    }
                    println!(
                        "note: the credential store did not answer ({e}); a store entry it may hold stays \
                         behind, unread while the file key exists"
                    );
                }
                if revoked.existed() {
                    println!("removed the previous host key.");
                }
            }
            Err(e) => {
                println!("pair --reset failed to remove the old key: {e}");
                return 1;
            }
        }
    }

    let presence = auth.path().wire_name();
    let key = match crate::ipc::with_runtime_lock(|lock| Ok(EnrollmentKey::mint(lock, store, auth)))
    {
        Ok(Ok(minted)) => minted,
        Ok(Err(e @ EnclaveError::KeyInvalid(_))) => {
            println!(
                "pair: {e}\n\
                 pairing only completes with a freshly minted key, so to (re-)enroll run:\n\
                 \n    chromium-bridge pair --reset\n\
                 \n\
                 to inspect the current key, run: chromium-bridge enclave-status\n\
                 if you never enrolled this machine yourself, treat the existing key as\n\
                 untrusted and run the reset."
            );
            return 1;
        }
        Ok(Err(e)) => {
            println!("pair failed to mint the host key: {e}");
            if store == KeyStore::CredentialStore {
                println!(
                    "if this machine has no OS credential store (a headless Linux session), rerun with \
                     `chromium-bridge pair --file-store` to keep the key in a 0600 file instead"
                );
            }
            return 1;
        }
        Err(e) => {
            println!("pair failed to take the runtime lock: {e}");
            return 1;
        }
    };

    println!("enrolled (user presence: {presence}).");
    let public_key_b64 = key.public_key().to_base64();
    let fingerprint = key.public_key().fingerprint_display();
    println!("key store:  {}", store_name(store));
    if store == KeyStore::File {
        println!(
            "            the key lives in a 0600 file in the runtime directory; any process running \
             as you can read it there"
        );
    }
    println!("public key: {public_key_b64}");
    println!("fingerprint (sha256):");
    println!("  {fingerprint}");
    println!(
        "\nnext: open the extension's enrollment screen and check it shows\n\
         EXACTLY this fingerprint before approving."
    );
    0
}

fn store_name(store: KeyStore) -> &'static str {
    match store {
        KeyStore::CredentialStore => "the OS credential store",
        KeyStore::File => "file (host_key.json)",
    }
}

/// `chromium-bridge revoke` (also `pair --reset` uses the same deletion): delete the host key and the signed
/// policy baseline and bump the host-key epoch, so a live native host pushes `enclave_revoked` and a pinned
/// extension fails closed without waiting for a reverify.
pub fn run_revoke() -> i32 {
    match dispose_enrollment_and_policy_baseline() {
        Ok(revoked) => {
            audit_host_key_revoke(crate::audit::Surface::Cli, &revoked);
            if let StoreOutcome::Unanswered(e) = &revoked.store {
                if revoked.file {
                    println!(
                        "note: the credential store did not answer ({e}); the file key is revoked, a \
                         store entry it may hold stays behind"
                    );
                } else {
                    println!("revoke could not consult the credential store: {e}");
                    return 1;
                }
            }
            if revoked.existed() {
                println!("host key revoked. re-run `chromium-bridge pair` to re-enroll.");
                println!(
                    "a connected extension is notified and fails closed; \
                     otherwise it notices on its next connect."
                );
            } else {
                println!("no host key found; nothing to revoke.");
            }
            0
        }
        Err(e) => {
            println!("revoke failed: {e}");
            1
        }
    }
}

/// The shared disposal seam: `chromium-bridge revoke`, `pair --reset`, and the extension-originated
/// `enclave_revoke` all route here, under ONE runtime-lock hold, so no concurrent WRITER (a policy write under
/// the doomed key) can land a baseline between the key deletion and the clear. Returns what each place
/// confirmed; the surfaces decide what a store that did not answer means for them.
///
/// ```text
/// file removal fails                 -> the error bubbles and the baseline stays: the key, and its valid signature, may still exist
/// baseline clear or epoch bump fails -> logged, not fatal: only cleanup or the proactive push is lost, never the deletion
/// ```
pub fn dispose_enrollment_and_policy_baseline() -> Result<Revoked, EnclaveError> {
    match crate::ipc::with_runtime_lock(dispose_locked) {
        Ok(inner) => inner,
        Err(e) => Err(EnclaveError::Keychain(format!(
            "runtime lock unavailable during host key disposal: {e}"
        ))),
    }
}

fn dispose_locked(
    lock: &crate::ipc::RuntimeLockToken,
) -> std::io::Result<Result<Revoked, EnclaveError>> {
    let revoked = match EnrollmentKey::revoke(lock) {
        Ok(revoked) => revoked,
        Err(e) => return Ok(Err(e)),
    };
    if let Err(e) = crate::policy::clear_baseline_locked(lock) {
        log_warn!(
            "enclave",
            "host key deleted but the signed policy baseline could not be cleared ({e}); it \
             survives as an artifact of the dead key until the next policy write"
        );
    }
    if let Err(e) = crate::trust::Trust::mutate_locked(lock, crate::trust::Scope::HostKey, |_| {}) {
        log_warn!(
            "enclave",
            "host key deleted but the host-key revocation epoch bump failed ({e}); other \
             surfaces notice only at their next key verification"
        );
    }
    Ok(Ok(revoked))
}

/// Record a host-key revocation in the audit trail, log-after-decide, as the verdict says: `ok` when a key
/// in use is confirmed gone, `error` naming the store's non-answer otherwise, so the trail never claims a
/// revocation the store did not confirm. The surface is the caller's own; the shared seam is surface-agnostic.
pub fn audit_host_key_revoke(surface: crate::audit::Surface, revoked: &Revoked) {
    let record =
        crate::audit::AuditRecord::new(crate::audit::AuditKind::HostKeyRevoke).surface(surface);
    crate::audit::record(match &revoked.store {
        StoreOutcome::Unanswered(e) if !revoked.file => record
            .outcome("error")
            .detail(&format!("credential store did not answer: {e}")),
        StoreOutcome::Unanswered(e) => record.outcome("ok").detail(&format!(
            "file key removed; credential store did not answer: {e}"
        )),
        StoreOutcome::Cleared { .. } => record.outcome("ok"),
    });
}

/// `chromium-bridge enclave-status`: read-only report on the host key. The `key:` line's first word is what
/// `tests/protocol/harness.py` reads to tell an enrolled machine from a fresh one.
pub fn run_status() -> i32 {
    println!("chromium-bridge enclave-status");
    match key_report() {
        EnclaveStatusReport::Present {
            store,
            public_key_b64,
            fingerprint,
            ..
        } => {
            println!("key:        present ({KEY_LABEL}, {})", store_name(store));
            println!("public key: {public_key_b64}");
            println!("fingerprint (sha256):");
            println!("  {fingerprint}");
        }
        EnclaveStatusReport::None { .. } => {
            println!("key:        none (run `chromium-bridge pair`)")
        }
        EnclaveStatusReport::Invalid { detail, .. } => println!(
            "key:        REJECTED - {detail}\n            treat it as untrusted; \
             run `chromium-bridge pair --reset` to replace it"
        ),
        EnclaveStatusReport::Error { detail, .. } => {
            println!("key:        lookup failed: {detail}")
        }
    }
    0
}

/// `chromium-bridge enclave-status --json`: the machine-readable form of [`run_status`]. One JSON object on
/// stdout; `v` is read before any other field so a consumer can refuse a report it does not understand.
pub fn run_status_json() -> i32 {
    // Through `Value` so the keys come out sorted whatever the enum's declaration order.
    match serde_json::to_value(key_report()) {
        Ok(value) => {
            println!("{value}");
            0
        }
        Err(e) => {
            eprintln!("enclave-status --json failed to serialize the report: {e}");
            1
        }
    }
}

/// The exact object `chromium-bridge enclave-status --json` prints, and what the prose report renders from. A
/// sum tagged on `key`, so a `present` report without its public half, or a `none` one naming a store, cannot
/// even deserialize; `deny_unknown_fields` makes an unexpected shape a loud refusal on the parsing side. A
/// key that exports no public half (the deny-listed fixture scalar) is the same `invalid` state as a
/// lookup-time `KeyInvalid`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "key", rename_all = "lowercase", deny_unknown_fields)]
pub enum EnclaveStatusReport {
    Present {
        /// Schema version. `1` today; a newer value must be refused before any field below is read.
        v: u32,
        /// The credential-store entry name the host key lives under.
        key_label: String,
        store: KeyStore,
        /// Base64 X9.63 public key.
        public_key_b64: String,
        /// The public key's SHA-256 fingerprint, grouped for comparison.
        fingerprint: String,
    },
    None {
        v: u32,
        key_label: String,
    },
    /// A key exists under our name but must be treated as untrusted (planted or malformed).
    Invalid {
        v: u32,
        key_label: String,
        detail: String,
    },
    /// The lookup itself failed (store unreachable, record unreadable).
    Error {
        v: u32,
        key_label: String,
        detail: String,
    },
}

/// One lookup, so the store and the public half the report shows come from the same record read.
fn key_report() -> EnclaveStatusReport {
    let (v, key_label) = (1, KEY_LABEL.to_string());
    match EnrollmentKey::lookup() {
        Ok(Some(key)) => EnclaveStatusReport::Present {
            v,
            key_label,
            store: key.store(),
            public_key_b64: key.public_key().to_base64(),
            fingerprint: key.public_key().fingerprint_display(),
        },
        Ok(None) => EnclaveStatusReport::None { v, key_label },
        Err(e @ EnclaveError::KeyInvalid(_)) => EnclaveStatusReport::Invalid {
            v,
            key_label,
            detail: e.to_string(),
        },
        Err(e) => EnclaveStatusReport::Error {
            v,
            key_label,
            detail: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::super::pubkey::EnclavePublicKey;
    use super::*;

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
}
