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
use crate::runtime_record::{Record, Rung, RuntimeRecord};

/// How often long-lived watchers (the native host's revocation watch and the
/// broker's idle-connection watcher) re-read this module's record to notice
/// an out-of-band change. One shared value so revocation propagation latency
/// cannot silently drift apart across enforcement points.
pub const REVOCATION_POLL: std::time::Duration = std::time::Duration::from_secs(1);

/// The persisted revocation state (`revocation.json`). Absent file = epoch 0, nothing latched (the
/// bootstrap posture of a fresh install). A present-but-damaged file is an error the caller MUST fail
/// closed on: reading it as "epoch 0" would let a tamperer suppress a revocation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revocation {
    /// The global monotonic epoch. Every revocation-relevant mutation
    /// increments it; enforcement points cache the value they admitted under
    /// and re-decide on ANY difference (inequality, not order, so enforcement
    /// stays correct even against a rolled-back file).
    pub epoch: u64,
    /// Epoch of the last client-allowlist revocation (0 = never).
    pub clients_epoch: u64,
    /// Epoch of the last enclave host-key revocation (0 = never).
    pub host_key_epoch: u64,
    /// Epoch of the last host-owned policy change (0 = never). The native host
    /// watches it to know when to push `policy_current` to the extension;
    /// it is a change notice, never authority (the signed baseline in
    /// `policy.json` is the authority).
    pub policy_epoch: u64,
    /// Epoch of the last shared-language change (0 = never). The native host
    /// watches it to push `lang_current`.
    pub lang_epoch: u64,
    /// One-way latch: a client allowlist has existed on this machine. With the
    /// latch set, an absent `clients.json` is tampering, not bootstrap.
    pub clients_enrolled: bool,
    /// The global kill switch. While set, every enforcement point
    /// refuses all bridge activity. Unlike the epoch, this flag IS the
    /// authority for the kill state: there is no second file to re-read. It
    /// lives in this record on purpose -- the record is written atomically, so
    /// no reader can ever observe the kill without the epoch bump that
    /// accompanies it (the broker's per-request fast path skips work only on
    /// an unchanged epoch, which this invariant makes sound).
    pub killed: bool,
    /// Epoch of the last kill-switch transition, either direction (0 = never).
    /// The native host watches it to know when to re-read `killed` and push
    /// the state to the extension.
    pub kill_epoch: u64,
}

impl Record for Revocation {
    const FILE: &'static str = "revocation.json";
    const MAX_BYTES: usize = 64 * 1024;
    const MIGRATIONS: &'static [Rung] = crate::migrations::revocation::LADDER;
}

impl Revocation {
    /// The current state, with the absent file mapped to the bootstrap
    /// default. Errors still propagate (the caller fails closed).
    pub fn current() -> io::Result<Self> {
        Ok(Self::load()?.unwrap_or_default())
    }

    /// Refuses the u64 wrap rather than saturating or wrapping: a repeated or rolled-back epoch reads as
    /// "unchanged" to an enforcement point, which would suppress the re-check the bump exists to force.
    fn advanced(mut self) -> io::Result<Self> {
        self.epoch = self.epoch.checked_add(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "revocation epoch overflow")
        })?;
        Ok(self)
    }

    fn bumped(self, scope: Scope) -> io::Result<Self> {
        let mut next = self.advanced()?;
        match scope {
            Scope::Clients => next.clients_epoch = next.epoch,
            Scope::HostKey => next.host_key_epoch = next.epoch,
            Scope::Policy => next.policy_epoch = next.epoch,
            Scope::Lang => next.lang_epoch = next.epoch,
        }
        Ok(next)
    }

    /// The clients bump makes running enforcement points re-read the allowlist they now enforce.
    fn latched(self) -> io::Result<Self> {
        let mut next = self.bumped(Scope::Clients)?;
        next.clients_enrolled = true;
        Ok(next)
    }

    /// No scope marker moves on a kill transition: the native host's watch keys each push on its own marker.
    fn with_killed(self, killed: bool) -> io::Result<Self> {
        let mut next = self.advanced()?;
        next.killed = killed;
        next.kill_epoch = next.epoch;
        Ok(next)
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
    commit_locked(lock, |rev| rev.bumped(scope))
}

/// Set the one-way enrollment latch. Same lock-token contract as [`bump_locked`]. Called by
/// `Allowlist::pair` inside its critical section.
pub(crate) fn latch_clients_enrolled_locked(lock: &ipc::RuntimeLockToken) -> io::Result<u64> {
    commit_locked(lock, Revocation::latched)
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
    commit_locked(lock, |rev| rev.with_killed(killed))
}

fn commit_locked(
    lock: &ipc::RuntimeLockToken,
    transform: impl FnOnce(Revocation) -> io::Result<Revocation>,
) -> io::Result<u64> {
    let next = transform(Revocation::current()?)?;
    next.write(lock)?;
    Ok(next.epoch)
}

/// Property tests over the production mutators ([`Revocation::bumped`], [`Revocation::with_killed`]):
/// the native host's watch and the broker's epoch guard rely on these cross-field facts, which no
/// single call site states. File I/O and cross-process locking are exercised by the e2e and
/// adversarial suites in an isolated runtime dir.
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

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
                rev = rev.bumped(scope).unwrap();
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
                        rev = rev.bumped(scope).unwrap();
                        prop_assert_eq!(rev.kill_epoch, before_kill,
                            "a scope bump must not move the kill marker");
                    }
                    Mutation::SetKilled(k) => {
                        rev = rev.with_killed(k).unwrap();
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
