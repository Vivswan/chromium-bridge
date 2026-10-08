//! Every host-key removal (`pair --reset`, `revoke --all`, the extension's `enclave_revoke`) runs through one
//! critical section, `dispose_locked`.

use std::io;

use serde::{Deserialize, Serialize};

use super::key::{EnrollmentKey, Revoked, StoreOutcome};
use super::record::KeyStore;
use super::{EnclaveError, KEY_LABEL};
use crate::allowlist::ClientEntry;
use crate::audit::Surface;
use crate::presence::{self, TerminalStdin};
use crate::trust::{Clients, Scope, Trust, TrustState};
use crate::webauthn::Enrollment;

/// Minting is a capability grant (the extension pins what it sees), so `pair` runs behind the terminal
/// witness and the typed phrase: a background script's `pair` is refused before anything is read or
/// written. A store that refuses or does not answer fails the command and says so, never a silent fallback
/// to the file.
///
/// ```text
/// a key already exists -> refused without --reset; `pair` never adopts a key it did not mint in this run,
///                         since a same-user process can plant one
/// --reset              -> disposes after the phrase, before minting; a store that does not answer stops a
///                         store pairing and only warns a file pairing
/// phrase declined      -> nothing disposed, nothing minted
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
                 \n    genkan pair --reset\n\
                 \n\
                 to inspect the current key, run: genkan enclave-status\n\
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
                     `genkan pair --file-store` to keep the key in a 0600 file instead"
                );
            }
            return 1;
        }
        Err(e) => {
            println!("pair failed to take the runtime lock: {e}");
            return 1;
        }
    };

    audit_host_key_pair(store, reset, presence);
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

/// Log-after-decide: the key exists by the time this runs.
fn audit_host_key_pair(store: KeyStore, reset: bool, presence: &str) {
    let store = match store {
        KeyStore::CredentialStore => "credential_store",
        KeyStore::File => "file",
    };
    crate::audit::record(
        crate::audit::AuditRecord::new(crate::audit::AuditKind::HostKeyPair)
            .surface(crate::audit::Surface::Cli)
            .outcome("ok")
            .detail(&format!("store={store}; reset={reset}; auth={presence}")),
    );
}

/// The kill latch stays: releasing it is presence-gated everywhere else. Every part that committed is printed
/// before any failure decides the exit code, so a partial reset never reads as nothing done.
pub fn run_revoke_all() -> i32 {
    let reset = match dispose_everything(Surface::Cli) {
        Ok(reset) => reset,
        Err(e) => {
            eprintln!("revoke --all failed: {e}");
            return 1;
        }
    };
    let mut code = 0;
    match &reset.pairings {
        Ok(forgotten) => {
            println!(
                "forgot {} browser credential{} and {} trusted client{}",
                forgotten.enrollments.len(),
                if forgotten.enrollments.len() == 1 {
                    ""
                } else {
                    "s"
                },
                forgotten.clients.len(),
                if forgotten.clients.len() == 1 {
                    ""
                } else {
                    "s"
                }
            );
            println!("the next browser enrollment is first-time (trust on first use)");
            match forgotten.trust.clients() {
                Clients::Paired(_) => println!(
                    "no MCP client is admitted until `genkan pair-client` trusts one again"
                ),
                Clients::NeverPaired => {}
            }
        }
        Err(e) => {
            eprintln!(
                "the trust record could not be rewritten ({e}): the browsers' enrollments and the trusted \
                 clients stay as they were"
            );
            code = 1;
        }
    }
    match &reset.baseline {
        Ok(true) => {
            println!("cleared the policy record (the signed baseline and any restriction overlay)")
        }
        Ok(false) => {}
        Err(e) => {
            eprintln!("the policy record could not be cleared ({e}); it stays in place");
            code = 1;
        }
    }
    match &reset.revoked.store {
        StoreOutcome::Unanswered(e) if !reset.revoked.file => {
            eprintln!("revoke --all could not consult the credential store: {e}");
            return 1;
        }
        StoreOutcome::Unanswered(e) => println!(
            "note: the credential store did not answer ({e}); the file key is revoked, a store entry it \
             may hold stays behind"
        ),
        StoreOutcome::Cleared { .. } => {}
    }
    if reset.revoked.existed() {
        println!("host key revoked. re-run `genkan pair` to re-enroll.");
        // The host pushes the revocation only on a moved host-key marker (the record write that also forgets
        // the pairings) AND a store that confirms the key absent; short of either, the extension learns when
        // its next key verification fails.
        if reset.pairings.is_ok() && matches!(reset.revoked.store, StoreOutcome::Cleared { .. }) {
            println!(
                "a connected extension is notified and fails closed; otherwise it notices on its next \
                 connect."
            );
        } else {
            println!("a connected extension notices at its next key verification.");
        }
    } else {
        println!("no host key found.");
    }
    code
}

struct Reset {
    revoked: Revoked,
    /// `true` when a record existed to clear.
    baseline: io::Result<bool>,
    /// An error here means nothing was forgotten.
    pairings: io::Result<Forgotten>,
}

/// The posture the user is told about is read from `trust` as it stands after the forget, not inferred from
/// the counts.
struct Forgotten {
    trust: TrustState,
    enrollments: Vec<Enrollment>,
    clients: Vec<ClientEntry>,
}

/// One runtime-lock hold covers the key deletion and the baseline clear, so no concurrent policy write under
/// the doomed key can land a baseline between them. The surfaces decide what a store that did not answer
/// means for them.
///
/// ```text
/// file removal fails                 -> the error bubbles and the baseline stays: the key, and its valid signature, may still exist
/// baseline clear or epoch bump fails -> logged, not fatal: only cleanup or the proactive push is lost, never the deletion
/// ```
pub fn dispose_enrollment_and_policy_baseline() -> Result<Revoked, EnclaveError> {
    let disposal = with_lock(|lock| dispose_locked(lock, |_| {}))?;
    if let Err(e) = disposal.baseline {
        log_warn!(
            "enclave",
            "host key deleted but the signed policy baseline could not be cleared ({e}); it \
             survives as an artifact of the dead key until the next policy write"
        );
    }
    if let Err(e) = disposal.trust {
        log_warn!(
            "enclave",
            "host key deleted but the host-key revocation epoch bump failed ({e}); other \
             surfaces notice only at their next key verification"
        );
    }
    Ok(disposal.revoked)
}

/// Audited here under `surface`, after the lock (the key, then one record per forgotten credential and
/// client), so the trail is written whatever the caller does next.
fn dispose_everything(surface: Surface) -> Result<Reset, EnclaveError> {
    let disposal = with_lock(|lock| dispose_locked(lock, Trust::forget_pairings))?;
    audit_host_key_revoke(surface, &disposal.revoked);
    let pairings = disposal
        .trust
        .map(|(trust, (enrollments, clients))| Forgotten {
            trust,
            enrollments,
            clients,
        });
    if let Ok(forgotten) = &pairings {
        crate::webauthn::audit_browsers_revoked(surface, &forgotten.enrollments);
        for client in &forgotten.clients {
            crate::allowlist::audit_client_revoked(surface, client.name.as_str());
        }
    }
    Ok(Reset {
        revoked: disposal.revoked,
        baseline: disposal.baseline,
        pairings,
    })
}

fn with_lock<T>(
    dispose: impl FnOnce(&crate::ipc::RuntimeLockToken) -> io::Result<Result<Disposal<T>, EnclaveError>>,
) -> Result<Disposal<T>, EnclaveError> {
    match crate::ipc::with_runtime_lock(dispose) {
        Ok(inner) => inner,
        Err(e) => Err(EnclaveError::Keychain(format!(
            "runtime lock unavailable during host key disposal: {e}"
        ))),
    }
}

/// The key removal is the gate (its failure is [`dispose_locked`]'s `Err`); the other two report their own.
struct Disposal<T> {
    revoked: Revoked,
    baseline: io::Result<bool>,
    trust: io::Result<(TrustState, T)>,
}

fn dispose_locked<T>(
    lock: &crate::ipc::RuntimeLockToken,
    edit: impl FnOnce(&mut Trust) -> T,
) -> io::Result<Result<Disposal<T>, EnclaveError>> {
    let revoked = match EnrollmentKey::revoke(lock) {
        Ok(revoked) => revoked,
        Err(e) => return Ok(Err(e)),
    };
    let baseline = crate::policy::clear_baseline_locked(lock);
    let trust = Trust::mutate_locked_with(lock, Scope::HostKey, edit);
    Ok(Ok(Disposal {
        revoked,
        baseline,
        trust,
    }))
}

/// Log-after-decide: `ok` only when a key in use is confirmed gone, so the trail never claims a revocation
/// the store did not confirm.
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

/// `genkan enclave-status`: read-only report on the host key. The `key:` line's first word is what
/// `tests/protocol/harness.py` reads to tell an enrolled machine from a fresh one.
pub fn run_status() -> i32 {
    println!("genkan enclave-status");
    let report = key_report();
    println!("key:        {}", key_line(&report));
    if let EnclaveStatusReport::Present {
        public_key_b64,
        fingerprint,
        ..
    } = report
    {
        println!("public key: {public_key_b64}");
        println!("fingerprint (sha256):");
        println!("  {fingerprint}");
    }
    0
}

/// The `key:` line's text: the state, and for a present key where it lives. Printed by `enclave-status` and
/// shown by the options page, so the words are spelled here alone.
pub(crate) fn key_line(report: &EnclaveStatusReport) -> String {
    match report {
        EnclaveStatusReport::Present { store, .. } => {
            format!("present ({KEY_LABEL}, {})", store_name(*store))
        }
        EnclaveStatusReport::None { .. } => "none (run `genkan pair`)".into(),
        EnclaveStatusReport::Invalid { detail, .. } => format!(
            "REJECTED - {detail}; treat it as untrusted and run `genkan pair --reset` to replace it"
        ),
        EnclaveStatusReport::Error { detail, .. } => format!("lookup failed: {detail}"),
    }
}

/// `v` is read before any other field so a consumer can refuse a report it does not understand.
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

/// The object `enclave-status --json` prints, pinned byte for byte by
/// `json_report_wire_bytes_for_each_key_state`. Tagged on `key`, so a `present` report without its public
/// half cannot deserialize; a key with no exportable public half (the deny-listed fixture scalar) is the same
/// `invalid` as a lookup-time `KeyInvalid`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "key", rename_all = "lowercase", deny_unknown_fields)]
pub enum EnclaveStatusReport {
    Present {
        /// Schema version. `1` today; a newer value must be refused before any field below is read.
        v: u32,
        key_label: String,
        store: KeyStore,
        public_key_b64: String,
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
pub(crate) fn key_report() -> EnclaveStatusReport {
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
mod tests;
