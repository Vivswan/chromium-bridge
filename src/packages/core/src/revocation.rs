//! The any-side revocation epoch (ADR-0025): one persisted, monotonic counter at `runtime_dir()/revocation.json` that
//! every revocation surface bumps under the runtime lock, AFTER writing the state change it describes, and every
//! enforcement point compares, re-deciding admission whenever its cached epoch no longer matches and failing closed
//! whenever the file cannot be read. The epoch is a change notice, not an authority: the client allowlist
//! (`clients.json`) and the Secure Enclave key stay authoritative, so a same-user tamperer can force spurious
//! re-checks or make every read fail closed, but can never admit anyone.
//!
//! ```text
//! lock-free reader   -> may see the new state under the old epoch, never the new epoch over the old state (the lock
//!                       serializes writers only, see bump_locked)
//! per-scope epochs   -> record WHICH trust state changed; the native host wakes the keychain and pushes
//!                       enclave_revoked only for host_key_epoch
//! clients_enrolled   -> a one-way latch: with it set, an absent clients.json reads as tampering and fails closed
//!                       (crate::allowlist::load_enforced) instead of reverting to the open bootstrap an absent file
//!                       means on a first install; an attacker who deletes BOTH files still reaches bootstrap, since no
//!                       user-space marker survives a writer who can delete anything we can write (ADR-0025), so the
//!                       latch catches the single-file deletion, the accidental case and the lazy attack
//! killed (ADR-0030)  -> unlike the epoch, IS the authority; written in the same atomic write as its epoch bump, so
//!                       every fail-closed read of this file doubles as a kill-state read; enforcement lives in kill.rs
//! ```

use std::io;

use serde::{Deserialize, Serialize};

use crate::ipc;

/// How often long-lived watchers (the native host's revocation watch and the
/// broker's idle-connection watcher) re-read this module's record to notice
/// an out-of-band change. One shared value so revocation propagation latency
/// cannot silently drift apart across enforcement points.
pub const REVOCATION_POLL: std::time::Duration = std::time::Duration::from_secs(1);

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
    /// Epoch of the last host-owned policy change (0 = never). The native host
    /// watches it to know when to push `policy_current` to the extension
    /// (ADR-0032 decision 4); it is a change notice, never authority (the
    /// signed baseline in `policy.json` is the authority).
    #[serde(default)]
    pub policy_epoch: u64,
    /// Epoch of the last shared-language change (0 = never). The native host
    /// watches it to push `lang_current` (ADR-0032 decision 7).
    #[serde(default)]
    pub lang_epoch: u64,
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

    /// The epoch after one bump. Refuses the u64 wrap rather than saturating
    /// or wrapping: a repeated or rolled-back epoch reads as "unchanged" to an
    /// enforcement point, which would suppress the re-check the bump exists to
    /// force.
    fn bumped_epoch(&self) -> io::Result<u64> {
        self.epoch
            .checked_add(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "revocation epoch overflow"))
    }

    /// Write atomically, 0600. Demands the [`ipc::RuntimeLockToken`] witness:
    /// a bump races other writers by design, and the runtime lock the token
    /// proves is what makes read-increment-write monotonic across processes.
    fn write_locked(&self, _lock: &ipc::RuntimeLockToken) -> io::Result<()> {
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
    /// The host-owned policy changed (a signed baseline write or an unsigned
    /// restriction, ADR-0032). A change notice for the native host's
    /// `policy_current` push; the signed baseline stays the authority.
    Policy,
    /// The shared `uiLanguage` preference changed (ADR-0032 decision 7). A
    /// change notice for the native host's `lang_current` push.
    Lang,
}

/// Increment the epoch and stamp `scope`'s marker; returns the new epoch. The [`ipc::RuntimeLockToken`] makes the
/// lock precondition structural: a token exists only inside [`ipc::with_runtime_lock`], so a lock-free call (a stale
/// read-modify-write that could overwrite a concurrent `killed: true`) does not compile.
///
/// ```text
/// lock serializes WRITERS only -> every caller writes its authoritative state first and bumps in the same hold, while
///                                 lock-free enforcement reads may see the new state under the old epoch, never the new
///                                 epoch over the old state (the broker's EpochGuard::recheck reads the epoch first)
/// unreadable existing file     -> returned as the error, never rebuilt: silently replacing a corrupt security record
///                                 would mask tampering, and a corrupt file already fails every enforcement read closed,
///                                 strictly tighter than any epoch bump
/// ```
pub(crate) fn bump_locked(lock: &ipc::RuntimeLockToken, scope: Scope) -> io::Result<u64> {
    let mut rev = Revocation::current()?;
    rev.version = REVOCATION_VERSION;
    rev.epoch = rev.bumped_epoch()?;
    match scope {
        Scope::Clients => rev.clients_epoch = rev.epoch,
        Scope::HostKey => rev.host_key_epoch = rev.epoch,
        Scope::Policy => rev.policy_epoch = rev.epoch,
        Scope::Lang => rev.lang_epoch = rev.epoch,
    }
    rev.write_locked(lock)?;
    Ok(rev.epoch)
}

/// Set the one-way enrollment latch (and bump the epoch so running enforcement
/// points re-read the allowlist they now enforce). Same lock-token contract as
/// [`bump_locked`]. Called by `Allowlist::pair` inside its critical section.
pub(crate) fn latch_clients_enrolled_locked(lock: &ipc::RuntimeLockToken) -> io::Result<u64> {
    let mut rev = Revocation::current()?;
    rev.version = REVOCATION_VERSION;
    rev.epoch = rev.bumped_epoch()?;
    rev.clients_epoch = rev.epoch;
    rev.clients_enrolled = true;
    rev.write_locked(lock)?;
    Ok(rev.epoch)
}

/// Flip the kill switch (ADR-0030): `killed`, `kill_epoch`, and the global epoch in ONE atomic write, so
/// the kill and its bump can never be observed separately and an enforcement point that skips re-reading
/// on an unchanged epoch cannot miss a kill. Same lock-token contract as [`bump_locked`].
///
/// An unreadable existing record fails in BOTH directions rather than being rebuilt (rebuilding would mask
/// tampering):
/// ```text
/// engaging  -> the corrupt record already fails every enforcement read closed, so the kill's goal holds
/// releasing -> an unkill from an unknown state would fail open; recovery is in docs/operations.md
/// ```
pub(crate) fn set_killed_locked(lock: &ipc::RuntimeLockToken, killed: bool) -> io::Result<u64> {
    let mut rev = Revocation::current()?;
    rev.version = REVOCATION_VERSION;
    rev.epoch = rev.bumped_epoch()?;
    rev.killed = killed;
    rev.kill_epoch = rev.epoch;
    rev.write_locked(lock)?;
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
        assert_eq!(rev.policy_epoch, 0);
        assert_eq!(rev.lang_epoch, 0);
        assert!(!rev.clients_enrolled);
        assert!(!rev.killed, "a fresh install is not killed");
        assert_eq!(rev.kill_epoch, 0);
    }

    #[test]
    fn kill_fields_default_when_absent_from_an_older_record() {
        // A record written before the kill switch existed (no killed /
        // kill_epoch fields) still parses, reading as not-killed: the fields
        // carry serde defaults so an older file stays valid.
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
            policy_epoch: 5,
            lang_epoch: 4,
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
            Scope::Policy => rev.policy_epoch = rev.epoch,
            Scope::Lang => rev.lang_epoch = rev.epoch,
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
        prop_oneof![
            Just(Scope::Clients),
            Just(Scope::HostKey),
            Just(Scope::Policy),
            Just(Scope::Lang),
        ]
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
            let (mut last_policy, mut last_lang) = (0u64, 0u64);
            for scope in scopes {
                rev = bump_pure(rev, scope);
                prop_assert!(rev.epoch > last_epoch, "epoch must strictly increase");
                last_epoch = rev.epoch;
                match scope {
                    Scope::Clients => last_clients = rev.epoch,
                    Scope::HostKey => last_host = rev.epoch,
                    Scope::Policy => last_policy = rev.epoch,
                    Scope::Lang => last_lang = rev.epoch,
                }
                prop_assert_eq!(rev.clients_epoch, last_clients);
                prop_assert_eq!(rev.host_key_epoch, last_host);
                prop_assert_eq!(rev.policy_epoch, last_policy);
                prop_assert_eq!(rev.lang_epoch, last_lang);
                prop_assert!(rev.clients_epoch <= rev.epoch);
                prop_assert!(rev.host_key_epoch <= rev.epoch);
                prop_assert!(rev.policy_epoch <= rev.epoch);
                prop_assert!(rev.lang_epoch <= rev.epoch);
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
