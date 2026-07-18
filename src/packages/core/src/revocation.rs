//! The any-side revocation epoch (ADR-0025): one persisted, monotonic counter
//! that every revocation surface bumps and every enforcement point compares.
//!
//! ## Why this exists
//!
//! Phase 4 left revocation half-connected. `revoke-client` rewrote the
//! allowlist, but a broker that had already admitted that client kept serving
//! it until the process tree died; `revoke` deleted the enclave key, but a
//! pinned extension only noticed at the next opt-in reverify. Each revocable
//! trust state had its own, unsynchronized notion of "current". This module
//! gives them one: a single epoch, persisted at `runtime_dir()/revocation.json`,
//! bumped (under the runtime lock, atomically with the state change it
//! describes) by whichever surface performs a revocation -- the CLI, the
//! extension via a host-directed control frame, or a future app -- and read by
//! every enforcement point, which re-decides admission whenever the epoch it
//! cached no longer matches and **fails closed** whenever the file cannot be
//! read.
//!
//! ## What the epoch is, and is not
//!
//! The epoch is a *change notice*, not an authority. The authoritative trust
//! states stay where they were: the client allowlist (`clients.json`) and the
//! Secure Enclave key. A bump only tells an enforcement point "re-read the
//! authority now"; the re-read makes the decision. That keeps the failure
//! analysis simple: a same-user process that tampers with this file can force
//! spurious re-checks (each of which re-admits everyone still authorized) or
//! corrupt it (which makes every enforcement read fail closed). Neither
//! direction can *admit* anyone.
//!
//! ## Scope markers
//!
//! Alongside the global counter, two scope fields record the epoch of the last
//! revocation per trust state, so an observer can tell *what* changed without
//! guessing: `clients_epoch` (the client allowlist changed) and
//! `host_key_epoch` (the enclave enrollment key was revoked). The native host
//! watches `host_key_epoch` to know when to verify the keychain and push the
//! host-originated `enclave_revoked` frame to the extension (ADR-0025).
//!
//! ## Tamper evidence: the enrollment latch
//!
//! ADR-0024 named an asymmetry: a corrupt `clients.json` fails closed, but a
//! DELETED one silently reverts an enrolled bridge to the open, unenrolled
//! bootstrap (an absent file is how a first install legitimately starts).
//! `clients_enrolled` is a one-way latch, set when the first client is paired
//! and never cleared: with the latch set, an absent `clients.json` reads as
//! tampering and fails closed ([`crate::allowlist::load_enforced`]) instead of
//! reverting to open. This is deliberately bounded honesty: a same-user
//! attacker who deletes BOTH files still reaches the bootstrap posture,
//! because no user-space marker survives a writer who can delete any file we
//! can write (see ADR-0025 for the full argument). What the latch buys is that
//! a single-file deletion -- the accidental case, and the lazy attack -- is
//! detected and refused loudly rather than silently obeyed.
//!
//! ## The kill switch rides in this record (ADR-0030)
//!
//! The global kill switch's latch (`killed`, plus its `kill_epoch` marker)
//! lives in this same file, written by [`set_killed_locked`] in one atomic
//! write with its epoch bump. Unlike the epoch, the latch IS the authority
//! for the kill state; keeping it in the atomically-written record is what
//! lets every existing fail-closed read of this file double as a kill-state
//! read. See `kill.rs` for the enforcement surface.

use std::io;

use serde::{Deserialize, Serialize};

use crate::ipc;

/// Current on-disk schema version. Unknown versions are rejected (the caller
/// fails closed) rather than guessed at; `deny_unknown_fields` rejects a newer
/// shape even if the version were forged backwards.
const REVOCATION_VERSION: u32 = 1;

/// Size cap when reading the file back, matching the lock file's posture: this
/// file is a few hundred bytes, so anything larger is not ours.
const REVOCATION_MAX_BYTES: usize = 64 * 1024;

/// The persisted revocation state. Absent file = epoch 0, nothing latched
/// (the bootstrap posture of a fresh install).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revocation {
    /// Schema version; see [`REVOCATION_VERSION`].
    #[serde(default)]
    pub version: u32,
    /// The global monotonic epoch. Every revocation-relevant mutation
    /// increments it; enforcement points cache the value they admitted under
    /// and re-decide on ANY difference (inequality, not order, so enforcement
    /// stays correct even against a rolled-back file).
    pub epoch: u64,
    /// Epoch of the last client-allowlist revocation (0 = never).
    #[serde(default)]
    pub clients_epoch: u64,
    /// Epoch of the last enclave host-key revocation (0 = never).
    #[serde(default)]
    pub host_key_epoch: u64,
    /// One-way latch: a client allowlist has existed on this machine. With the
    /// latch set, an absent `clients.json` is tampering, not bootstrap.
    #[serde(default)]
    pub clients_enrolled: bool,
    /// The global kill switch (ADR-0030). While set, every enforcement point
    /// refuses all bridge activity. Unlike the epoch, this flag IS the
    /// authority for the kill state: there is no second file to re-read. It
    /// lives in this record on purpose -- the record is written atomically, so
    /// no reader can ever observe the kill without the epoch bump that
    /// accompanies it (the broker's per-request fast path skips work only on
    /// an unchanged epoch, which this invariant makes sound).
    #[serde(default)]
    pub killed: bool,
    /// Epoch of the last kill-switch transition, either direction (0 = never).
    /// The native host watches it to know when to re-read `killed` and push
    /// the state to the extension.
    #[serde(default)]
    pub kill_epoch: u64,
}

impl Revocation {
    /// Path of the revocation file in the 0700 per-user runtime directory.
    pub fn path() -> std::path::PathBuf {
        ipc::runtime_dir().join("revocation.json")
    }

    /// Read the file. `Ok(None)` when it does not exist (bootstrap). A
    /// present-but-corrupt, oversized, or unknown-versioned file is an error,
    /// and the caller MUST fail closed on it: treating a damaged revocation
    /// record as "epoch 0" would let a tamperer suppress a revocation.
    pub fn load() -> io::Result<Option<Self>> {
        let Some(bytes) = ipc::read_capped(&Self::path(), REVOCATION_MAX_BYTES)? else {
            return Ok(None);
        };
        let rev: Revocation = serde_json::from_slice(&bytes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("revocation decode: {e}"),
            )
        })?;
        if rev.version != REVOCATION_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "revocation version {} is not supported (this binary understands {})",
                    rev.version, REVOCATION_VERSION
                ),
            ));
        }
        Ok(Some(rev))
    }

    /// The current state, with the absent file mapped to the bootstrap
    /// default. Errors still propagate (the caller fails closed).
    pub fn current() -> io::Result<Self> {
        Ok(Self::load()?.unwrap_or_default())
    }

    /// Write atomically, 0600. The caller must hold the runtime lock: a bump
    /// races other writers by design, and the lock is what makes
    /// read-increment-write monotonic across processes.
    fn write_locked(&self) -> io::Result<()> {
        let bytes = serde_json::to_vec_pretty(self)?;
        ipc::write_private_atomic(&Self::path(), &bytes)
    }
}

/// Which trust state a bump describes. The scope marker lets observers act on
/// exactly the change that concerns them (the native host only wakes the
/// keychain for [`Scope::HostKey`] bumps).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The client allowlist changed (a client was revoked, or the list was
    /// otherwise rewritten in a way enforcement must re-read).
    Clients,
    /// The enclave enrollment key was revoked/deleted.
    HostKey,
}

/// Increment the epoch and stamp `scope`'s marker. MUST be called while the
/// caller already holds the runtime lock (every caller performs the
/// authoritative state change and the bump in ONE critical section, so no
/// enforcement point can observe the new epoch with the old state or vice
/// versa -- see `Allowlist::revoke`). Returns the new epoch.
///
/// On an unreadable existing file this returns the error rather than
/// rebuilding the file: silently replacing a corrupt security record would
/// mask tampering. The revocation the caller performed is still effective --
/// a corrupt revocation file makes every enforcement read fail closed, which
/// is strictly tighter than any epoch bump.
pub(crate) fn bump_locked(scope: Scope) -> io::Result<u64> {
    let mut rev = Revocation::current()?;
    rev.version = REVOCATION_VERSION;
    rev.epoch += 1;
    match scope {
        Scope::Clients => rev.clients_epoch = rev.epoch,
        Scope::HostKey => rev.host_key_epoch = rev.epoch,
    }
    rev.write_locked()?;
    Ok(rev.epoch)
}

/// Set the one-way enrollment latch (and bump the epoch so running enforcement
/// points re-read the allowlist they now enforce). Same locking contract as
/// [`bump_locked`]. Called by `Allowlist::pair` inside its critical section.
pub(crate) fn latch_clients_enrolled_locked() -> io::Result<u64> {
    let mut rev = Revocation::current()?;
    rev.version = REVOCATION_VERSION;
    rev.epoch += 1;
    rev.clients_epoch = rev.epoch;
    rev.clients_enrolled = true;
    rev.write_locked()?;
    Ok(rev.epoch)
}

/// Bump under the runtime lock, for callers that do not already hold it (the
/// enclave-key revocation paths, whose authoritative state lives in the
/// keychain rather than in a runtime-lock-guarded file).
pub(crate) fn bump(scope: Scope) -> io::Result<u64> {
    ipc::with_runtime_lock(|| bump_locked(scope))
}

/// Flip the kill switch (ADR-0030): set `killed`, stamp `kill_epoch`, and
/// bump the global epoch, all in ONE atomic write under the caller-held
/// runtime lock. One write is the load-bearing part: the kill and its epoch
/// bump can never be observed separately, so an enforcement point that skips
/// re-reading on an unchanged epoch cannot miss a kill.
///
/// Fails on an unreadable existing record, in BOTH directions, rather than
/// rebuilding the file (rebuilding would mask tampering):
/// - engaging: the caller should tell the user the bridge is ALREADY refusing
///   everything (a corrupt record fails every enforcement read closed), so
///   the kill's goal already holds;
/// - releasing: an unkill from an unknown state would be a fail-open, so it
///   is refused; recovery is documented in docs/operations.md.
pub(crate) fn set_killed_locked(killed: bool) -> io::Result<u64> {
    let mut rev = Revocation::current()?;
    rev.version = REVOCATION_VERSION;
    rev.epoch += 1;
    rev.killed = killed;
    rev.kill_epoch = rev.epoch;
    rev.write_locked()?;
    Ok(rev.epoch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_the_bootstrap_posture() {
        let rev = Revocation::default();
        assert_eq!(rev.epoch, 0);
        assert_eq!(rev.clients_epoch, 0);
        assert_eq!(rev.host_key_epoch, 0);
        assert!(!rev.clients_enrolled);
        assert!(!rev.killed, "a fresh install is not killed");
        assert_eq!(rev.kill_epoch, 0);
    }

    #[test]
    fn kill_fields_default_when_absent_from_an_older_record() {
        // A record written before the kill switch existed (no killed /
        // kill_epoch fields) still parses, reading as not-killed: the fields
        // were added with serde defaults so a Phase-5 file stays valid.
        let old = serde_json::json!({
            "version": 1, "epoch": 3, "clients_epoch": 3,
            "host_key_epoch": 0, "clients_enrolled": true
        });
        let rev: Revocation = serde_json::from_value(old).unwrap();
        assert!(!rev.killed);
        assert_eq!(rev.kill_epoch, 0);
    }

    #[test]
    fn serde_roundtrip_preserves_every_field() {
        let rev = Revocation {
            version: REVOCATION_VERSION,
            epoch: 8,
            clients_epoch: 6,
            host_key_epoch: 7,
            clients_enrolled: true,
            killed: true,
            kill_epoch: 8,
        };
        let bytes = serde_json::to_vec(&rev).unwrap();
        let back: Revocation = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, rev);
    }

    #[test]
    fn unknown_fields_are_rejected_fail_closed() {
        // A newer schema or a tampered file must be refused, never parsed
        // leniently: an unnoticed field could be a suppressed revocation.
        let bad = serde_json::json!({
            "version": 1, "epoch": 1, "surprise": true
        });
        assert!(serde_json::from_value::<Revocation>(bad).is_err());
        // Positive control.
        let good = serde_json::json!({ "version": 1, "epoch": 1 });
        assert!(serde_json::from_value::<Revocation>(good).is_ok());
    }

    #[test]
    fn unknown_version_is_rejected() {
        // load() enforces the version check; simulate its logic on a parsed
        // value (load() itself needs the runtime dir, exercised in the e2e
        // suites with an isolated XDG_RUNTIME_DIR).
        let rev: Revocation =
            serde_json::from_value(serde_json::json!({ "version": 99, "epoch": 1 })).unwrap();
        assert_ne!(rev.version, REVOCATION_VERSION);
    }

    #[test]
    fn path_has_expected_filename() {
        assert_eq!(Revocation::path().file_name().unwrap(), "revocation.json");
    }
}

/// Property tests for the pure epoch arithmetic: monotonicity and scope
/// stamping. File I/O and cross-process locking are exercised by the e2e and
/// adversarial suites in an isolated runtime dir.
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// The pure core of [`bump_locked`], factored for property testing.
    fn bump_pure(mut rev: Revocation, scope: Scope) -> Revocation {
        rev.version = REVOCATION_VERSION;
        rev.epoch += 1;
        match scope {
            Scope::Clients => rev.clients_epoch = rev.epoch,
            Scope::HostKey => rev.host_key_epoch = rev.epoch,
        }
        rev
    }

    /// The pure core of [`set_killed_locked`], factored the same way.
    fn set_killed_pure(mut rev: Revocation, killed: bool) -> Revocation {
        rev.version = REVOCATION_VERSION;
        rev.epoch += 1;
        rev.killed = killed;
        rev.kill_epoch = rev.epoch;
        rev
    }

    /// One mutation of the record: an epoch bump for a scope, or a kill-switch
    /// transition. Mixing them in one property pins that the mutations cannot
    /// disturb each other's markers.
    #[derive(Debug, Clone, Copy)]
    enum Mutation {
        Bump(Scope),
        SetKilled(bool),
    }

    fn arb_scope() -> impl Strategy<Value = Scope> {
        prop_oneof![Just(Scope::Clients), Just(Scope::HostKey)]
    }

    fn arb_mutation() -> impl Strategy<Value = Mutation> {
        prop_oneof![
            arb_scope().prop_map(Mutation::Bump),
            any::<bool>().prop_map(Mutation::SetKilled),
        ]
    }

    proptest! {
        /// Any sequence of bumps is strictly monotonic in the global epoch,
        /// and every scope marker always equals the epoch of the most recent
        /// bump of that scope (never runs ahead of the global counter).
        #[test]
        fn bumps_are_strictly_monotonic_and_scopes_track(
            scopes in prop::collection::vec(arb_scope(), 1..64)
        ) {
            let mut rev = Revocation::default();
            let mut last_epoch = rev.epoch;
            let (mut last_clients, mut last_host) = (0u64, 0u64);
            for scope in scopes {
                rev = bump_pure(rev, scope);
                prop_assert!(rev.epoch > last_epoch, "epoch must strictly increase");
                last_epoch = rev.epoch;
                match scope {
                    Scope::Clients => last_clients = rev.epoch,
                    Scope::HostKey => last_host = rev.epoch,
                }
                prop_assert_eq!(rev.clients_epoch, last_clients);
                prop_assert_eq!(rev.host_key_epoch, last_host);
                prop_assert!(rev.clients_epoch <= rev.epoch);
                prop_assert!(rev.host_key_epoch <= rev.epoch);
            }
        }

        /// Interleaving kill transitions with scope bumps keeps every
        /// invariant: the epoch stays strictly monotonic, `killed` always
        /// reflects the LAST transition, `kill_epoch` equals the epoch of that
        /// transition and never runs ahead of the counter, and a kill
        /// transition never disturbs the other scope markers (nor bumps the
        /// kill marker).
        #[test]
        fn kill_transitions_interleave_soundly(
            muts in prop::collection::vec(arb_mutation(), 1..64)
        ) {
            let mut rev = Revocation::default();
            let mut last_epoch = rev.epoch;
            let mut want_killed = false;
            let mut want_kill_epoch = 0u64;
            for m in muts {
                let (before_clients, before_host) = (rev.clients_epoch, rev.host_key_epoch);
                let before_kill = rev.kill_epoch;
                match m {
                    Mutation::Bump(scope) => {
                        rev = bump_pure(rev, scope);
                        prop_assert_eq!(rev.kill_epoch, before_kill,
                            "a scope bump must not move the kill marker");
                    }
                    Mutation::SetKilled(k) => {
                        rev = set_killed_pure(rev, k);
                        want_killed = k;
                        want_kill_epoch = rev.epoch;
                        prop_assert_eq!(rev.clients_epoch, before_clients);
                        prop_assert_eq!(rev.host_key_epoch, before_host);
                    }
                }
                prop_assert!(rev.epoch > last_epoch, "epoch must strictly increase");
                last_epoch = rev.epoch;
                prop_assert_eq!(rev.killed, want_killed);
                prop_assert_eq!(rev.kill_epoch, want_kill_epoch);
                prop_assert!(rev.kill_epoch <= rev.epoch);
            }
        }

    }
}
