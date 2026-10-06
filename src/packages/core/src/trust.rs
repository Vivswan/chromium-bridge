//! The one trust record, `trust.json`: the kill latch, the trusted-client allowlist, the WebAuthn enrollments,
//! and the change counter every enforcement point re-reads before it decides. A decision is a pure function of one snapshot
//! ([`TrustState`]), so no reader orders two files or caches a counter against a stale list.
//!
//! ```text
//! file absent                  -> the bootstrap: no client paired, kill off; `rm trust.json` is the conceded
//!                                 same-user residual (trust-boundaries.md names it)
//! clients: null                -> never paired: every harness admitted, logged at ERROR by the admitting surface
//! clients: []                  -> every client revoked: nobody admitted
//! enrollments: []              -> no browser enrolled an authenticator: the first enrollment is trust on first use,
//!                                 and the extension's software confirmation is the only presence path
//! killed                       -> the authority for the kill state; enforcement lives in kill.rs
//! epoch                        -> moves on every mutation; watchers compare it for inequality, never order, so a
//!                                 rolled-back file still reads as a change
//! host_key / kill / policy /   -> the markers the native host's watch keys its pushes on; two flips inside one
//! lang epoch                      poll interval still read as a change
//! unreadable file              -> an error every caller fails closed on, and no writer rebuilds
//! ```
//!
//! The record's fields are private to this module and admission is [`TrustState::decide`] alone: the one
//! anchor comparison is the private [`anchor_matches`], so a second admission path would have to hand-roll it,
//! which a grep for anchor comparisons outside this file catches. The listing surfaces read [`Trust::clients`]
//! because the `client_list` wire frame carries the entries, anchors included.

use std::io;
use std::ops::Deref;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::allowlist::{Anchor, ClientEntry};
use crate::audit::{self, AuditKind, AuditRecord};
use crate::ipc::{BrowserLabel, ClientIdentity, RuntimeLockToken};
use crate::runtime_record::{Ladder, Record, RuntimeRecord};
use crate::webauthn::{CredentialId, Enrollment};

/// How often the long-lived watchers (the broker's idle-connection sweep, the native host's push watch)
/// re-read the record. One value, so propagation latency cannot drift apart across enforcement points.
pub const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// The persisted record. Mutation goes through [`Trust::mutate_locked`] only; readers take a [`TrustState`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trust {
    epoch: u64,
    /// The global kill switch; `true` refuses all bridge activity until `chromium-bridge unkill`.
    killed: bool,
    /// Epoch of the last kill transition, either direction (0 = never). The native host pushes the kill state
    /// when it moves, so an engage and a release inside one poll interval still reach the extension's mirror.
    kill_epoch: u64,
    /// Epoch of the last enclave host-key revocation (0 = never).
    host_key_epoch: u64,
    /// Epoch of the last host-owned policy change (0 = never). A change notice for the native host's
    /// `policy_current` push; the signed baseline in `policy.json` is the authority.
    policy_epoch: u64,
    /// Epoch of the last shared-language change (0 = never), driving the `lang_current` push.
    lang_epoch: u64,
    #[serde(deserialize_with = "Clients::deserialize")]
    clients: Clients,
    /// The credentials each browser enrolled; `webauthn::store` writes them, `presence::request` reads them.
    enrollments: Vec<Enrollment>,
}

/// The trusted-client allowlist's two postures, named so every match site says which one it handles. On
/// disk `NeverPaired` is `null` and `Paired` is the array: serde parses the `Option<Vec<ClientEntry>>` (so a
/// malformed entry is refused with the rule it broke) and `From` names the two cases. The field above carries
/// `deserialize_with` so a missing key is refused like every other field instead of reading as the bootstrap.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(from = "Option<Vec<ClientEntry>>")]
pub enum Clients {
    /// No client has ever been paired: admission is not enforced.
    #[default]
    NeverPaired,
    /// The paired entries; an empty list is every client revoked and admits nobody.
    Paired(Vec<ClientEntry>),
}

impl From<Option<Vec<ClientEntry>>> for Clients {
    fn from(clients: Option<Vec<ClientEntry>>) -> Self {
        clients.map_or(Clients::NeverPaired, Clients::Paired)
    }
}

impl Serialize for Clients {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Clients::NeverPaired => s.serialize_none(),
            Clients::Paired(clients) => clients.serialize(s),
        }
    }
}

impl Record for Trust {
    const FILE: &'static str = "trust.json";
    const MAX_BYTES: usize = 256 * 1024;
    const LADDER: Ladder = crate::migrations::trust::LADDER;
}

impl Trust {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn killed(&self) -> bool {
        self.killed
    }

    pub fn kill_epoch(&self) -> u64 {
        self.kill_epoch
    }

    pub fn host_key_epoch(&self) -> u64 {
        self.host_key_epoch
    }

    pub fn policy_epoch(&self) -> u64 {
        self.policy_epoch
    }

    pub fn lang_epoch(&self) -> u64 {
        self.lang_epoch
    }

    /// The paired entries for the listing surfaces (`list-clients`, the `client_list` frame, which carries them
    /// anchors included). Not an admission input: admission is [`TrustState::decide`] only.
    pub fn clients(&self) -> &Clients {
        &self.clients
    }

    pub(crate) fn set_killed(&mut self, killed: bool) {
        self.killed = killed;
    }

    pub fn enrollments(&self) -> &[Enrollment] {
        &self.enrollments
    }

    /// Add `enrollment`, replacing an earlier one of the same credential id so a re-registration of one
    /// authenticator does not accumulate stale counters.
    pub(crate) fn enroll(&mut self, enrollment: Enrollment) {
        self.enrollments
            .retain(|e| e.credential.id != enrollment.credential.id);
        self.enrollments.push(enrollment);
    }

    /// Forget every enrollment under `label`; returns the ones that went, for the trail.
    pub(crate) fn revoke_browser(&mut self, label: &BrowserLabel) -> Vec<Enrollment> {
        let (gone, kept) = std::mem::take(&mut self.enrollments)
            .into_iter()
            .partition(|e| &e.label == label);
        self.enrollments = kept;
        gone
    }

    /// Forget every enrollment and every client pairing; returns what went, for the trail. A paired list
    /// stays paired (empty: nobody admitted until the next `pair-client`); a never-paired machine has no
    /// pairing to forget and keeps its bootstrap posture. The kill latch is not a pairing and stays.
    pub(crate) fn forget_pairings(&mut self) -> (Vec<Enrollment>, Vec<ClientEntry>) {
        let clients = match &mut self.clients {
            Clients::Paired(clients) => std::mem::take(clients),
            Clients::NeverPaired => Vec::new(),
        };
        (std::mem::take(&mut self.enrollments), clients)
    }

    /// Whether the sign counter an accepted assertion carried may land: the credential must be enrolled and
    /// `sign_count` must move its stored counter forward. A counter another host already moved past is stale.
    /// The writer decides under the lock, against the record as it stands then.
    pub(crate) fn counter_advance(&self, id: &CredentialId, sign_count: u32) -> CounterAdvance {
        let Some(e) = self.enrollments.iter().find(|e| &e.credential.id == id) else {
            return CounterAdvance::NotEnrolled;
        };
        let stored = e.credential.sign_count;
        if crate::webauthn::counter_advances(stored, sign_count) {
            CounterAdvance::Advanced
        } else {
            CounterAdvance::Stale { stored }
        }
    }

    /// Land the counter [`counter_advance`](Self::counter_advance) accepted.
    pub(crate) fn set_sign_count(&mut self, id: &CredentialId, sign_count: u32) {
        if let Some(e) = self.enrollments.iter_mut().find(|e| &e.credential.id == id) {
            e.credential.sign_count = sign_count;
        }
    }

    /// Add `entry`, replacing a same-named one so a re-pair does not accumulate stale anchors.
    pub(crate) fn pair(&mut self, entry: ClientEntry) {
        let mut clients = match std::mem::take(&mut self.clients) {
            Clients::Paired(clients) => clients,
            Clients::NeverPaired => Vec::new(),
        };
        clients.retain(|c| c.name != entry.name);
        clients.push(entry);
        self.clients = Clients::Paired(clients);
    }

    /// Remove the entry named `name`; the list stays `Paired` even when it empties (nobody admitted).
    pub(crate) fn revoke(&mut self, name: &str) {
        if let Clients::Paired(clients) = &mut self.clients {
            clients.retain(|c| c.name.as_str() != name);
        }
    }
}

#[cfg(test)]
impl Trust {
    pub(crate) fn fixture(epoch: u64, killed: bool, clients: Clients) -> Trust {
        Trust {
            epoch,
            killed,
            clients,
            ..Trust::default()
        }
    }

    pub(crate) fn with_markers(self, kill: u64, host_key: u64, policy: u64, lang: u64) -> Trust {
        Trust {
            kill_epoch: kill,
            host_key_epoch: host_key,
            policy_epoch: policy,
            lang_epoch: lang,
            ..self
        }
    }
}

/// The verdict of [`Trust::counter_advance`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterAdvance {
    Advanced,
    Stale { stored: u32 },
    NotEnrolled,
}

/// What a mutation changed. Every scope the native host's watch pushes on stamps a marker; the clients list
/// needs none, since the broker re-decides from the list itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// A client was paired or revoked.
    Clients,
    /// The kill switch flipped.
    Kill,
    /// The enclave enrollment key was revoked or deleted.
    HostKey,
    /// The host-owned policy changed.
    Policy,
    /// The shared `uiLanguage` preference changed.
    Lang,
    /// A credential was enrolled or forgotten, or its sign counter advanced; the enrollments are re-read per
    /// act, so no marker.
    Enrollments,
}

impl Trust {
    /// Refuses the u64 wrap rather than saturating or wrapping: a repeated epoch reads as "unchanged" to a
    /// watcher, which would suppress the push the bump exists to trigger.
    fn bumped(mut self, scope: Scope) -> io::Result<Self> {
        self.epoch = self
            .epoch
            .checked_add(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "trust epoch overflow"))?;
        match scope {
            Scope::Clients | Scope::Enrollments => {}
            Scope::Kill => self.kill_epoch = self.epoch,
            Scope::HostKey => self.host_key_epoch = self.epoch,
            Scope::Policy => self.policy_epoch = self.epoch,
            Scope::Lang => self.lang_epoch = self.epoch,
        }
        Ok(self)
    }

    /// The one write path. The [`RuntimeLockToken`] makes the lock precondition structural: a lock-free
    /// read-modify-write (one that could overwrite a concurrent `killed: true`) does not compile.
    ///
    /// An unreadable existing file is returned as the error, never rebuilt: replacing a corrupt record would
    /// mask tampering, and the corrupt file already fails every read closed, which is tighter than any write.
    pub(crate) fn mutate_locked(
        lock: &RuntimeLockToken,
        scope: Scope,
        f: impl FnOnce(&mut Trust),
    ) -> io::Result<TrustState> {
        Self::mutate_locked_with(lock, scope, f).map(|(state, ())| state)
    }

    /// [`mutate_locked`](Self::mutate_locked), handing back what `f` returned beside the snapshot: a writer
    /// that forgets entries gets them for its trail exactly when the write landed, never from a side channel.
    pub(crate) fn mutate_locked_with<T>(
        lock: &RuntimeLockToken,
        scope: Scope,
        f: impl FnOnce(&mut Trust) -> T,
    ) -> io::Result<(TrustState, T)> {
        let mut next = TrustState::current()?.0.bumped(scope)?;
        let out = f(&mut next);
        next.write(lock)?;
        Ok((TrustState(next), out))
    }
}

/// The admission verdict for a harness, decided by [`TrustState::decide`] and acted on by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// Served, under the posture the record was in.
    Admit(Posture),
    /// Clients are paired and the identity matched none, or could not be measured. Do not serve.
    Refused,
}

/// The posture an admitted harness is served under. The broker keeps it for the connection's lifetime and
/// never serves a connection under a weaker posture than it was admitted with (`crate::broker`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Posture {
    /// No client has ever been paired; the admitting surface logs that at ERROR.
    Unenrolled,
    /// The attested identity matched an entry; its name is the audit label.
    Trusted { name: String },
}

/// A snapshot of the record as read, the only input an enforcement decision takes. Derefs to the record for
/// its fields and is never written back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustState(Trust);

impl Deref for TrustState {
    type Target = Trust;

    fn deref(&self) -> &Trust {
        &self.0
    }
}

impl TrustState {
    /// Read the record once. An absent file is the bootstrap; an unreadable one is the error the caller fails
    /// closed on.
    pub fn current() -> io::Result<Self> {
        Ok(TrustState(Trust::load()?.unwrap_or_default()))
    }

    /// Harness admission from this snapshot alone. Keys on the anchor, never the name: a harness cannot admit
    /// itself by claiming to be `claude-code`. The kill switch is not an admission question: a killed bridge
    /// keeps the harness connected so the typed `BRIDGE_KILLED` refusal is deliverable (kill.rs).
    pub fn decide(&self, identity: Option<&ClientIdentity>) -> Admission {
        let Clients::Paired(clients) = &self.clients else {
            return Admission::Admit(Posture::Unenrolled);
        };
        let Some(identity) = identity else {
            return Admission::Refused;
        };
        clients
            .iter()
            .find(|c| anchor_matches(&c.anchor, identity))
            .map_or(Admission::Refused, |c| {
                Admission::Admit(Posture::Trusted {
                    name: c.name.to_string(),
                })
            })
    }
}

/// Plain equality on the anchored half of the identity: these are not secrets. Private here so the one
/// admission function is the only place an anchor is compared.
fn anchor_matches(anchor: &Anchor, identity: &ClientIdentity) -> bool {
    match anchor {
        Anchor::Hash(h) => *h == identity.hash,
        Anchor::Signer(t) => identity.signer.as_ref() == Some(t),
    }
}

/// The two surfaces that admit a harness. Each carries its audit surface and its log tag, so an admission
/// cannot be audited under one surface and logged under another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmittingSurface {
    /// The broker's relay endpoint, admitting a harness another server process attested.
    Relay,
    /// An MCP-server-mode process, admitting the harness that spawned it over stdio.
    Stdio,
}

impl AdmittingSurface {
    fn audit(self) -> audit::Surface {
        match self {
            AdmittingSurface::Relay => audit::Surface::Broker,
            AdmittingSurface::Stdio => audit::Surface::Host,
        }
    }

    fn log_tag(self) -> &'static str {
        match self {
            AdmittingSurface::Relay => "broker",
            AdmittingSurface::Stdio => "mcp",
        }
    }
}

impl Admission {
    /// Audit this verdict and log the admitted postures, the same way on every surface, so neither surface can
    /// drift to a quieter unenrolled admission. `reported_name` is the harness's self-asserted label, already
    /// validated by the caller; `identity` is the measured anchor set, printed on an unenrolled admission so
    /// the operator can pair this harness with `--hash` or `--signer` where `--this-parent` cannot measure it
    /// (Windows, or a harness that spawns the server over a pipe).
    pub fn announce(
        &self,
        surface: AdmittingSurface,
        reported_name: Option<&str>,
        identity: Option<&ClientIdentity>,
    ) {
        let tag = surface.log_tag();
        let label = reported_name.unwrap_or("-");
        match self {
            Admission::Refused => audit::record(
                AuditRecord::new(AuditKind::HarnessRefuse)
                    .surface(surface.audit())
                    .name(label)
                    .outcome("refused")
                    .detail("not in the trusted-client allowlist"),
            ),
            Admission::Admit(Posture::Unenrolled) => {
                log_error!(
                    tag,
                    "SECURITY: harness admitted WITHOUT attestation enforcement -- no trusted client has \
                     been paired yet (unenrolled). Any same-user process that runs our binary can drive \
                     the browser. Run `chromium-bridge pair-client` to enroll trusted clients and turn on \
                     enforcement. See SECURITY.md."
                );
                // The subject is printed bare, not as a shell argument: an X.500 subject can carry quotes
                // and commas, and quoting differs per shell.
                if let Some(id) = identity {
                    let signer = id
                        .signer
                        .as_ref()
                        .map(|s| format!(", signer [{s}]"))
                        .unwrap_or_default();
                    log_error!(
                        tag,
                        "this harness measured as hash {}{signer}; pair it with `pair-client --hash {}`{}",
                        id.hash,
                        id.hash,
                        if id.signer.is_some() {
                            " or `--signer` with that value, quoted for your shell"
                        } else {
                            ""
                        }
                    );
                }
                audit::record(
                    AuditRecord::new(AuditKind::HarnessAdmit)
                        .surface(surface.audit())
                        .name(label)
                        .outcome("unenrolled"),
                );
            }
            Admission::Admit(Posture::Trusted { name }) => {
                log_info!(tag, "harness admitted as trusted client '{name}'");
                audit::record(
                    AuditRecord::new(AuditKind::HarnessAdmit)
                        .surface(surface.audit())
                        .name(name)
                        .outcome("ok"),
                );
            }
        }
    }
}

#[cfg(test)]
impl From<Trust> for TrustState {
    fn from(trust: Trust) -> Self {
        TrustState(trust)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{HashDigest, SignerId};
    use crate::test_support::scratch_runtime_dir;
    use proptest::prelude::*;

    fn hd(seed: &str) -> HashDigest {
        HashDigest::try_from(seed.chars().cycle().take(40).collect::<String>()).unwrap()
    }

    fn id(hash: &str, signer: Option<&str>) -> ClientIdentity {
        ClientIdentity {
            hash: hd(hash),
            signer: signer.map(|s| SignerId::try_from(s).unwrap()),
        }
    }

    /// The pairing contract docs/security/rationale.md documents, pinned where the bytes enter and leave: a hash anchor
    /// needs a re-pair after a re-sign while a signer anchor survives it, the name never admits, `null`
    /// clients is the open bootstrap, `[]` is every client revoked, and a missing `clients` key is refused
    /// like any other missing field instead of reading as the bootstrap.
    #[test]
    fn on_disk_record_decides_as_the_pairing_contract_documents() {
        let decode = |clients: &str| {
            Trust::decode(
                format!(
                    r#"{{"version":{},"epoch":1,"killed":false,"kill_epoch":0,"host_key_epoch":0,"policy_epoch":0,"lang_epoch":0,"enrollments":[]{clients}}}"#,
                    Trust::VERSION
                )
                .as_bytes(),
            )
        };
        let hash_entry = format!(
            r#"{{"name":"codex","anchor":{{"kind":"hash","value":"{}"}},"added_unix":0}}"#,
            hd("deadbeef")
        );
        let signer_entry = r#"{"name":"claude-code","anchor":{"kind":"signer","value":"SIGNER0001"},"added_unix":0}"#;
        let paired = format!(r#","clients":[{hash_entry},{signer_entry}]"#);
        let trusted = |name: &str| Admission::Admit(Posture::Trusted { name: name.into() });
        let cases = [
            (
                "never paired, unmeasured",
                r#","clients":null"#.to_string(),
                None,
                Admission::Admit(Posture::Unenrolled),
            ),
            (
                "never paired, measured",
                r#","clients":null"#.to_string(),
                Some(id("abc", None)),
                Admission::Admit(Posture::Unenrolled),
            ),
            (
                "every client revoked",
                r#","clients":[]"#.to_string(),
                Some(id("abc", Some("SIGNER0001"))),
                Admission::Refused,
            ),
            (
                "paired, unmeasured",
                paired.clone(),
                None,
                Admission::Refused,
            ),
            (
                "hash anchor, exact hash",
                paired.clone(),
                Some(id("deadbeef", None)),
                trusted("codex"),
            ),
            (
                "hash anchor, re-signed hash",
                paired.clone(),
                Some(id("cafef00d", None)),
                Admission::Refused,
            ),
            (
                "signer anchor, re-signed hash",
                paired.clone(),
                Some(id("0e51a", Some("SIGNER0001"))),
                trusted("claude-code"),
            ),
            (
                "signer anchor, other signer",
                paired.clone(),
                Some(id("0e51a", Some("OTHERSIGNER"))),
                Admission::Refused,
            ),
        ];
        for (case, clients, identity, want) in cases {
            let trust = TrustState(decode(&clients).unwrap_or_else(|e| panic!("{case}: {e}")));
            assert_eq!(trust.decide(identity.as_ref()), want, "{case}");
        }
        let err = decode("").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
        assert!(err.to_string().contains("missing field `clients`"), "{err}");
        // The write side of the same contract: NeverPaired lands as null, Paired as the array.
        let encoded = |clients: Clients| {
            serde_json::to_value(Trust::fixture(0, false, clients)).unwrap()["clients"].clone()
        };
        assert_eq!(encoded(Clients::NeverPaired), serde_json::Value::Null);
        assert_eq!(encoded(Clients::Paired(vec![])), serde_json::json!([]));
    }

    /// A writer never rebuilds a record it cannot read: the corrupt bytes stay exactly as found, so the
    /// tampering evidence survives and the record keeps failing every read closed.
    #[test]
    fn mutate_refuses_an_unreadable_record_and_leaves_its_bytes_alone() {
        let _dir = scratch_runtime_dir();
        let garbage = b"{ this is not json".to_vec();
        std::fs::write(Trust::path().unwrap(), &garbage).unwrap();
        let err = crate::ipc::with_runtime_lock(|lock| {
            Trust::mutate_locked(lock, Scope::Kill, |t| t.killed = true)
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
        assert_eq!(std::fs::read(Trust::path().unwrap()).unwrap(), garbage);
        assert!(
            TrustState::current().is_err(),
            "the record keeps failing closed"
        );
    }

    fn arb_scope() -> impl Strategy<Value = Scope> {
        prop_oneof![
            Just(Scope::Clients),
            Just(Scope::Kill),
            Just(Scope::HostKey),
            Just(Scope::Policy),
            Just(Scope::Lang),
            Just(Scope::Enrollments),
        ]
    }

    proptest! {
        /// Any sequence of bumps is strictly monotonic in the epoch, every marker equals the epoch of the latest
        /// bump of its own scope (never ahead of the counter), a Clients or Enrollments bump moves no marker, and
        /// a bump touches nothing else. The native host's watch keys its pushes on these facts, which no call site states.
        #[test]
        fn bumps_are_strictly_monotonic_and_markers_track_their_scope(
            scopes in prop::collection::vec(arb_scope(), 1..64)
        ) {
            let mut trust = Trust { killed: true, clients: Clients::Paired(vec![]), ..Trust::default() };
            let mut last = trust.epoch;
            let (mut want_kill, mut want_host, mut want_policy, mut want_lang) = (0u64, 0u64, 0u64, 0u64);
            for scope in scopes {
                trust = trust.bumped(scope).unwrap();
                prop_assert!(trust.epoch > last, "epoch must strictly increase");
                last = trust.epoch;
                match scope {
                    Scope::Kill => want_kill = trust.epoch,
                    Scope::HostKey => want_host = trust.epoch,
                    Scope::Policy => want_policy = trust.epoch,
                    Scope::Lang => want_lang = trust.epoch,
                    Scope::Clients | Scope::Enrollments => {}
                }
                prop_assert_eq!(
                    (trust.kill_epoch, trust.host_key_epoch, trust.policy_epoch, trust.lang_epoch),
                    (want_kill, want_host, want_policy, want_lang)
                );
                prop_assert!(trust.killed && trust.clients == Clients::Paired(vec![]), "a bump edits no other field");
            }
        }
    }
}
