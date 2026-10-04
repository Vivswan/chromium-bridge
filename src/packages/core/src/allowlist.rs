//! Host-side trusted-client allowlist: which MCP-client harnesses (Claude Code, Copilot, Codex, ...) may drive
//! the browser through this bridge (ADR-0024).
//!
//! Peer attestation (ADR-0019/0020) proves a bridge peer is our own binary but says nothing about who drives
//! the MCP server over its stdio, so the broker checks the harness's kernel-attested identity
//! ([`ClientIdentity`], measured by [`crate::ipc::attest_parent`]) against this persisted set before serving
//! its tool calls. Admission keys on the [`Anchor`], never the human-facing `name`: a harness cannot admit
//! itself by claiming to be `claude-code`.
//!
//! ```text
//! Team-ID-signed client        -> Anchor::TeamId, stable across the weekly re-sign of a free Apple
//!                                 Development certificate (which changes the cdhash)
//! unsigned / ad-hoc dev build  -> Anchor::Hash, re-pair after every renewal
//!
//! file absent, latch clear  -> unenrolled: admission not enforced, logged loudly (the same-user residual stays open)
//! file absent, latch set    -> tampering: the revocation record's clients_enrolled latch says clients were paired,
//!                              so admission fails closed (load_enforced)
//! file present              -> enforced: only a matching identity is admitted; an unmeasurable identity fails closed
//! ```

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::ipc::{self, ClientIdentity, HashDigest, TeamId};
use crate::presence::{self, PresenceAttestation};
use crate::revocation::Revocation;
use crate::runtime_record::{Record, Rung, RuntimeRecord};

/// The authorization key of an allowlist entry: the unforgeable thing a
/// harness's attested identity must match. Never the name. Both payloads are
/// parsed at the decode boundary ([`crate::ipc::HashDigest`],
/// [`crate::ipc::TeamId`]), so a value no measurement can equal never loads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "envelope-schema", derive(schemars::JsonSchema))]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Anchor {
    /// Pin the exact attested image hash (macOS `cdhash`, Linux
    /// `/proc/<pid>/exe` SHA256). Precise, but a code re-sign changes the
    /// `cdhash`, so this anchor requires a re-pair after a renewal. It is the
    /// only anchor available for unsigned / ad-hoc dev builds.
    Hash(HashDigest),
    /// Pin the macOS signing Team ID. Stable across the weekly re-sign of a
    /// free Apple Development certificate, so it survives renewals without a
    /// re-pair. Only available when the client image is Team-ID signed.
    TeamId(TeamId),
}

/// One trusted client. The `name` is a validated, human-facing label for the
/// user and the audit log; `anchor` is the authorization key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "envelope-schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ClientEntry {
    /// Human-facing label (validated like a browser label). NOT the
    /// authorization key -- a harness cannot admit itself by claiming a name.
    pub name: String,
    /// The unforgeable authorization key.
    pub anchor: Anchor,
    /// When this client was paired, Unix seconds. For the audit/status
    /// surface; not used in the admission decision.
    #[serde(default)]
    pub added_unix: u64,
}

/// The persisted allowlist (`clients.json`). Its mere *presence* on disk means admission is
/// enforced (see [`decide`]); an empty `clients` list is therefore a fully
/// locked bridge, not an open one. Loading a present-but-damaged file is an error, NOT a
/// silent `None`: treating it as unenrolled would fail *open*, so callers fail closed on the error.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allowlist {
    pub clients: Vec<ClientEntry>,
}

impl Record for Allowlist {
    const FILE: &'static str = "clients.json";
    const MAX_BYTES: usize = 256 * 1024;
    const MIGRATIONS: &'static [Rung] = crate::migrations::clients::LADDER;
}

/// The admission verdict for a harness. Kept separate from acting on it so the
/// policy is a pure, exhaustively-tested function ([`decide`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// No allowlist exists yet (unenrolled). Admit, but harness admission is not yet load-bearing and the
    /// caller must log that loudly.
    AdmitUnenrolled,
    /// An allowlist exists and the harness's attested identity matched an
    /// entry. Carries the matched entry's name for logging/audit.
    Admit { name: String },
    /// An allowlist exists and the harness did not match (or could not be
    /// measured at all). Fail closed: do not serve this harness.
    Refuse,
}

impl Allowlist {
    /// Whether `identity` matches any entry. Returns the matched entry's name.
    /// A `Hash` anchor matches the measured hash; a `TeamId` anchor matches a
    /// measured Team ID. Comparisons are plain equality: these are not secrets.
    fn matched_name(&self, identity: &ClientIdentity) -> Option<String> {
        self.clients.iter().find_map(|c| match &c.anchor {
            Anchor::Hash(h) if *h == identity.hash => Some(c.name.clone()),
            Anchor::TeamId(t) if identity.team_id.as_ref() == Some(t) => Some(c.name.clone()),
            Anchor::Hash(_) | Anchor::TeamId(_) => None,
        })
    }

    /// Add or replace a client (the same `name` replaces, so a re-pair does not accumulate stale anchors),
    /// persisted atomically under the runtime lock. Module-private on purpose: the ONLY entry point is
    /// [`pair_client_with_presence`], which runs the presence ladder and audits every outcome, so no allowlist
    /// mutation can skip the trail (ADR-0030) and no path can enroll without a [`PresenceAttestation`], which
    /// only [`presence::require_presence`] mints (pairing GRANTS capability, ADR-0031).
    ///
    /// The one-way enrollment latch (ADR-0025) is set BEFORE the list is written, so a partial failure fails closed:
    /// ```text
    /// latch ok, clients.json write fails  -> the next admission sees latch + no list and refuses as tampering
    ///                                        (re-running `pair-client` completes the write)
    /// the reverse order                    -> a usable list with no deletion evidence: `rm clients.json` reverts to open
    /// ```
    fn pair(name: &str, anchor: Anchor, auth: PresenceAttestation) -> io::Result<()> {
        // The attestation is structural evidence, consumed here; the audit
        // record that names its path is written by the caller
        // (pair_client_with_presence), log-after-decide.
        let _ = auth;
        if !crate::ipc::validate_label(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid client name (want 1-32 chars of [A-Za-z0-9._-], starting alphanumeric)",
            ));
        }
        ipc::with_runtime_lock(|lock| {
            let mut list = Self::load()?.unwrap_or_default();
            list.clients.retain(|c| c.name != name);
            list.clients.push(ClientEntry {
                name: name.to_string(),
                anchor,
                added_unix: now_unix(),
            });
            // Latch first (fail closed on a partial write), then the list.
            crate::revocation::latch_clients_enrolled_locked(lock)?;
            list.write(lock)
        })
    }

    /// Remove the client with `name`; returns whether an entry was removed. The file stays in place even when
    /// empty: an empty file still means enrolled (nobody admitted), the fail-closed reading of "revoked every
    /// client". Audited HERE, not by the caller, so revocation cannot rewrite trust state without a trail entry (ADR-0030).
    ///
    /// The list rewrite is the authoritative act; the epoch bump only accelerates the broker's per-request fast
    /// path. The runtime lock serializes the two writes against other WRITERS only, so list-first ordering and
    /// the broker's unconditional watcher, not the lock, are what keep its lock-free readers safe.
    /// ```text
    /// list rewritten  -> re-attach refused at once; the watcher re-decides every poll regardless of the epoch
    /// bump fails      -> logged; the live connection drops within a poll instead of on its next call
    /// ```
    pub fn revoke(name: &str, surface: crate::audit::Surface) -> io::Result<bool> {
        let removed = ipc::with_runtime_lock(|lock| {
            let Some(mut list) = Self::load()? else {
                return Ok(false);
            };
            let before = list.clients.len();
            list.clients.retain(|c| c.name != name);
            let removed = list.clients.len() != before;
            if removed {
                list.write(lock)?;
                if let Err(e) =
                    crate::revocation::bump_locked(lock, crate::revocation::Scope::Clients)
                {
                    log_error!(
                        "allowlist",
                        "client '{name}' revoked (removed from clients.json), but the \
                         revocation epoch bump failed ({e}); the broker's per-request fast \
                         path will not accelerate, but its watcher still drops the \
                         connection within a poll and re-attach is already refused"
                    );
                }
            }
            Ok(removed)
        })?;
        if removed {
            // Log-after-decide (ADR-0030): the list rewrite + epoch bump are
            // done, and the lock above is released.
            crate::audit::record(
                crate::audit::AuditRecord::new(crate::audit::AuditKind::RevokeClient)
                    .surface(surface)
                    .name(name)
                    .outcome("ok"),
            );
        }
        Ok(removed)
    }
}

/// The admission decision. Pure: given the loaded allowlist (or `None` for
/// unenrolled) and the measured harness identity (or `None` when measurement
/// failed), decide whether to serve the harness. Enforcement is fail-closed
/// once enrolled -- an unmeasured identity is refused, never admitted.
pub fn decide(list: Option<&Allowlist>, identity: Option<&ClientIdentity>) -> Decision {
    match list {
        None => Decision::AdmitUnenrolled,
        Some(l) => match identity.and_then(|id| l.matched_name(id)) {
            Some(name) => Decision::Admit { name },
            None => Decision::Refuse,
        },
    }
}

/// Load the allowlist for an ADMISSION decision, honoring the tamper-evidence latch (ADR-0025): with the latch set,
/// an ABSENT `clients.json` is a deletion, not the bootstrap posture, and fails closed instead of reverting to open.
/// Takes the whole [`Revocation`] and reads `clients_enrolled` itself, so a caller cannot hand-pick an adjacent flag
/// (`killed`) and silently reopen what the latch closed.
pub fn load_enforced(rev: &Revocation) -> io::Result<Option<Allowlist>> {
    apply_latch(Allowlist::load()?, rev)
}

/// The pure core of [`load_enforced`]: the latch turns "absent list" from
/// bootstrap into tampering. Factored out so the fail-closed matrix is
/// unit-testable without touching the runtime directory. Reads the latch
/// from the record for the same no-wrong-flag reason as [`load_enforced`].
fn apply_latch(list: Option<Allowlist>, rev: &Revocation) -> io::Result<Option<Allowlist>> {
    match list {
        Some(list) => Ok(Some(list)),
        None if rev.clients_enrolled => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "clients.json is missing but this machine has enrolled trusted clients \
             (the revocation record's enrollment latch is set); treating the deletion \
             as tampering and failing closed. Re-pair with `chromium-bridge pair-client` \
             to rebuild the allowlist.",
        )),
        None => Ok(None),
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---- The presence-gated pairing API (ADR-0031) ------------------------------

/// Why a presence-gated pairing did not happen. Both variants leave the
/// allowlist untouched.
#[derive(Debug)]
pub enum PairClientError {
    /// The request was malformed (invalid client name); refused BEFORE the
    /// presence prompt, so a bad request can never raise a hardware sheet.
    InvalidName,
    /// The user-presence gate refused: a hardware refusal, a non-interactive
    /// stdin, or a declined prompt. Never downgraded, already audited.
    Presence(presence::PresenceError),
    /// Presence passed but the allowlist write failed.
    Io(io::Error),
}

impl std::fmt::Display for PairClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PairClientError::InvalidName => write!(
                f,
                "invalid client name (want 1-32 chars of [A-Za-z0-9._-], starting alphanumeric)"
            ),
            PairClientError::Presence(e) => write!(f, "user presence not attested: {e}"),
            PairClientError::Io(e) => write!(f, "could not write the allowlist: {e}"),
        }
    }
}

/// Pair a trusted client behind the user-presence gate (ADR-0031): the one entry point every surface uses to
/// GRANT harness capability. Runs the presence ladder, then writes the allowlist, and audits each outcome after
/// the fact (refusal, write, write failure) with the rung that decided it; returns the attesting path so the
/// surface can tell the user which proof authorized the pairing. Revocation stays friction-free on purpose:
/// removing capability never needs a human proof (the presence symmetry rule).
///
/// `terminal` is the CLI floor's witness, or the precondition failure that kept the surface from constructing one
/// (`TerminalStdin::require()`: a piped stdin arrives as the `Err`); either way the name check runs first, so a
/// malformed request never reaches the gate.
pub fn pair_client_with_presence(
    name: &str,
    anchor: Anchor,
    surface: crate::audit::Surface,
    terminal: Result<presence::TerminalStdin, presence::PresenceError>,
) -> Result<presence::PresencePath, PairClientError> {
    use crate::audit::{self, AuditKind, AuditRecord};
    // Validate before prompting: a malformed request must not be able to put
    // a Touch ID sheet in front of the user.
    if !crate::ipc::validate_label(name) {
        return Err(PairClientError::InvalidName);
    }
    let reason = format!(
        "Pair '{name}' as a trusted client of chromium-bridge? A trusted \
         client can drive your browser through this bridge."
    );
    let auth = match terminal.and_then(|terminal| presence::require_presence(&reason, terminal)) {
        Ok(auth) => auth,
        Err(e) => {
            // Log-after-decide: the refusal has already happened; make the
            // attempted silent enrollment visible in the trail.
            audit::record(
                AuditRecord::new(AuditKind::PairClient)
                    .surface(surface)
                    .name(name)
                    .outcome("refused")
                    .detail(&format!("presence: {e}")),
            );
            return Err(PairClientError::Presence(e));
        }
    };
    let auth_path = auth.path();
    let shown = match &anchor {
        Anchor::Hash(h) => format!("hash {h}"),
        Anchor::TeamId(t) => format!("Team ID {t}"),
    };
    match Allowlist::pair(name, anchor, auth) {
        Ok(()) => {
            // Log-after-decide (ADR-0030): the pairing is persisted; the
            // record names the presence rung that authorized it.
            audit::record(
                AuditRecord::new(AuditKind::PairClient)
                    .surface(surface)
                    .name(name)
                    .outcome("ok")
                    .detail(&format!("{shown}; auth={}", auth_path.wire_name())),
            );
            Ok(auth_path)
        }
        Err(e) => {
            audit::record(
                AuditRecord::new(AuditKind::PairClient)
                    .surface(surface)
                    .name(name)
                    .outcome("error")
                    .detail(&format!(
                        "{shown}; auth={}; write refused: {e}",
                        auth_path.wire_name()
                    )),
            );
            Err(PairClientError::Io(e))
        }
    }
}

// ---- CLI handlers ----------------------------------------------------------

/// `pair-client`: add or replace a trusted client in the allowlist, behind
/// the user-presence gate (Touch ID where the machine has it; the typed
/// terminal confirmation otherwise). Prints a confirmation and the resolved
/// anchor. Returns a process exit code.
pub fn run_pair_client(argv: &[String]) -> i32 {
    let parsed = match crate::cli::pair_client_args(argv) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("pair-client: {e}");
            return 2;
        }
    };
    let anchor = match resolve_anchor(&parsed.anchor) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("pair-client: {e}");
            return 1;
        }
    };
    let shown = match &anchor {
        Anchor::Hash(h) => format!("hash {h}"),
        Anchor::TeamId(t) => format!("Team ID {t}"),
    };
    match pair_client_with_presence(
        &parsed.name,
        anchor,
        crate::audit::Surface::Cli,
        // The terminal witness comes first, by construction: a piped stdin
        // arrives at the gate as the precondition failure, refused (and
        // audited) after the name check, promptless.
        presence::TerminalStdin::require(),
    ) {
        Ok(path) => {
            println!(
                "paired trusted client '{}' on {shown} (user presence: {})",
                parsed.name,
                path.wire_name()
            );
            println!("harness admission is now ENFORCED (fail closed for anything else)");
            0
        }
        Err(e @ PairClientError::Presence(_)) => {
            eprintln!("pair-client: refused - {e}");
            eprintln!("nothing was paired");
            1
        }
        Err(e) => {
            eprintln!("pair-client: {e}");
            1
        }
    }
}

/// Turn a CLI anchor spec into a concrete [`Anchor`], measuring this
/// invocation's parent when asked (`--this-parent`). The one validation path
/// for user-supplied anchors, so a malformed value is refused identically
/// wherever one arrives.
pub fn resolve_anchor(spec: &crate::cli::AnchorSpec) -> Result<Anchor, String> {
    use crate::cli::AnchorSpec;
    match spec {
        AnchorSpec::Hash(h) => {
            // Normalizing user INPUT to lowercase is the legitimate-entry
            // convenience this path has always offered; only the persisted
            // form is held strictly canonical (see [`HashDigest`]).
            HashDigest::try_from(h.to_ascii_lowercase())
                .map(Anchor::Hash)
                .map_err(|e| format!("--hash: {e}"))
        }
        AnchorSpec::TeamId(t) => TeamId::try_from(t.clone())
            .map(Anchor::TeamId)
            .map_err(|e| format!("--team-id: {e}")),
        AnchorSpec::ThisParent => {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                let id = ipc::attest_parent()
                    .map_err(|e| format!("could not attest the parent process: {e}"))?;
                Ok(Anchor::Hash(id.hash))
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                Err("--this-parent is not supported on this platform (no attestation)".into())
            }
        }
    }
}

/// `revoke-client`: remove a trusted client. Returns a process exit code.
pub fn run_revoke_client(argv: &[String]) -> i32 {
    let name = match crate::cli::revoke_client_name(argv) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("revoke-client: {e}");
            return 2;
        }
    };
    match Allowlist::revoke(&name, crate::audit::Surface::Cli) {
        Ok(true) => {
            println!("revoked trusted client '{name}'");
            println!(
                "a live broker drops this client's connections and refuses its re-attach \
                 (immediately if the revocation epoch advanced, otherwise within the \
                 broker's next check)"
            );
            0
        }
        Ok(false) => {
            eprintln!("revoke-client: no trusted client named '{name}'");
            1
        }
        Err(e) => {
            eprintln!("revoke-client: could not write the allowlist: {e}");
            1
        }
    }
}

/// `list-clients`: print the trusted-client allowlist. Returns a process exit
/// code. Consults the tamper-evidence latch (ADR-0025): an absent allowlist on
/// a machine whose latch is set is reported as tampering, not as unenrolled.
pub fn run_list_clients() -> i32 {
    let rev = match crate::revocation::Revocation::current() {
        Ok(rev) => rev,
        Err(e) => {
            eprintln!("list-clients: could not read the revocation record: {e}");
            eprintln!("(treating the trust state as suspect; fail closed)");
            return 1;
        }
    };
    match load_enforced(&rev) {
        Ok(None) => {
            println!(
                "no trusted-client allowlist yet (UNENROLLED: harness admission not enforced)"
            );
            0
        }
        Ok(Some(list)) => {
            if list.clients.is_empty() {
                println!(
                    "trusted-client allowlist is EMPTY (enrolled: every harness fails closed)"
                );
            } else {
                println!("trusted clients ({}):", list.clients.len());
                for c in &list.clients {
                    let anchor = match &c.anchor {
                        Anchor::Hash(h) => format!("hash {h}"),
                        Anchor::TeamId(t) => format!("Team ID {t}"),
                    };
                    println!("  {}  ({anchor})", c.name);
                }
            }
            0
        }
        Err(e) => {
            eprintln!("list-clients: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A measured identity from literals: a valid lowercase-hex hash and an
    /// optional non-empty team id.
    fn id(hash: &str, team: Option<&str>) -> ClientIdentity {
        ClientIdentity {
            hash: hd(hash),
            team_id: team.map(tid),
        }
    }

    /// A 40-character test digest from a lowercase-hex seed.
    fn hd(seed: &str) -> HashDigest {
        HashDigest::try_from(seed.chars().cycle().take(40).collect::<String>()).unwrap()
    }

    /// A test team id from a non-empty literal.
    fn tid(team: &str) -> TeamId {
        TeamId::try_from(team).unwrap()
    }

    /// A revocation record whose enrollment latch is `latched`, everything
    /// else at the bootstrap default.
    fn rev_with_latch(latched: bool) -> Revocation {
        Revocation {
            clients_enrolled: latched,
            ..Revocation::default()
        }
    }

    fn list_of(entries: Vec<ClientEntry>) -> Allowlist {
        Allowlist { clients: entries }
    }

    #[test]
    fn unenrolled_admits_but_flags_pre_enrollment() {
        // No file -> None -> AdmitUnenrolled regardless of identity (even an
        // unmeasured one). This is the documented pre-enrollment residual.
        assert_eq!(decide(None, None), Decision::AdmitUnenrolled);
        assert_eq!(
            decide(None, Some(&id("abc", None))),
            Decision::AdmitUnenrolled
        );
    }

    #[test]
    fn enrolled_refuses_an_unmeasured_identity() {
        // Enrolled + cannot measure -> fail closed, never admit.
        let l = list_of(vec![ClientEntry {
            name: "claude-code".into(),
            anchor: Anchor::Hash(hd("abc")),
            added_unix: 0,
        }]);
        assert_eq!(decide(Some(&l), None), Decision::Refuse);
    }

    #[test]
    fn hash_anchor_matches_exact_hash_only() {
        let l = list_of(vec![ClientEntry {
            name: "codex".into(),
            anchor: Anchor::Hash(hd("deadbeef")),
            added_unix: 0,
        }]);
        assert_eq!(
            decide(Some(&l), Some(&id("deadbeef", None))),
            Decision::Admit {
                name: "codex".into()
            }
        );
        // A different hash (e.g. after a re-sign) no longer matches the Hash
        // anchor -- the re-pair path exists for exactly this.
        assert_eq!(
            decide(Some(&l), Some(&id("cafef00d", None))),
            Decision::Refuse
        );
    }

    #[test]
    fn team_id_anchor_survives_a_hash_change() {
        // A Team-ID anchor matches on team id regardless of the (changed)
        // cdhash: the point of anchoring on Team ID across a weekly re-sign.
        let l = list_of(vec![ClientEntry {
            name: "claude-code".into(),
            anchor: Anchor::TeamId(tid("TEAMID0001")),
            added_unix: 0,
        }]);
        assert_eq!(
            decide(Some(&l), Some(&id("0e51a", Some("TEAMID0001")))),
            Decision::Admit {
                name: "claude-code".into()
            }
        );
        // Wrong team id -> refuse. A matching cdhash is irrelevant to a
        // Team-ID anchor.
        assert_eq!(
            decide(Some(&l), Some(&id("0e51a", Some("OTHERTEAM")))),
            Decision::Refuse
        );
        // No team id measured at all (ad-hoc build) -> refuse against a
        // Team-ID anchor.
        assert_eq!(decide(Some(&l), Some(&id("0e51a", None))), Decision::Refuse);
    }

    #[test]
    fn empty_enrolled_list_admits_nobody() {
        // A present-but-empty allowlist is enrolled: it fails every harness
        // closed rather than reverting to the open pre-enrollment posture.
        let l = list_of(vec![]);
        assert_eq!(
            decide(Some(&l), Some(&id("a11", Some("any")))),
            Decision::Refuse
        );
    }

    #[test]
    fn a_name_is_never_an_authorization_key() {
        // Two clients; a harness whose measured identity matches NEITHER anchor
        // is refused even though its (untrusted, unused here) name might equal
        // an entry. The decision only ever consults anchors.
        let l = list_of(vec![
            ClientEntry {
                name: "claude-code".into(),
                anchor: Anchor::Hash(hd("c1a0de")),
                added_unix: 0,
            },
            ClientEntry {
                name: "codex".into(),
                anchor: Anchor::TeamId(tid("TEAMX")),
                added_unix: 0,
            },
        ]);
        assert_eq!(
            decide(Some(&l), Some(&id("1a905e7", None))),
            Decision::Refuse
        );
        // The genuine hash for claude-code admits under its name.
        assert_eq!(
            decide(Some(&l), Some(&id("c1a0de", None))),
            Decision::Admit {
                name: "claude-code".into()
            }
        );
    }

    #[test]
    fn entry_serde_roundtrips_both_anchor_kinds() {
        let hash_entry = ClientEntry {
            name: "codex".into(),
            anchor: Anchor::Hash(HashDigest::try_from("ab".repeat(32)).unwrap()),
            added_unix: 42,
        };
        let team_entry = ClientEntry {
            name: "claude-code".into(),
            anchor: Anchor::TeamId(tid("TEAMID0001")),
            added_unix: 7,
        };
        let list = list_of(vec![hash_entry.clone(), team_entry.clone()]);
        let bytes = serde_json::to_vec(&list).unwrap();
        let back: Allowlist = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.clients, vec![hash_entry, team_entry]);
    }

    #[test]
    fn anchor_serde_shape_is_tagged() {
        // The on-disk shape is a tagged {kind, value} so a hash and a team id
        // can never be confused for one another.
        assert_eq!(
            serde_json::to_value(Anchor::Hash(hd("0a"))).unwrap(),
            serde_json::json!({ "kind": "hash", "value": "0a".repeat(20) })
        );
        assert_eq!(
            serde_json::to_value(Anchor::TeamId(tid("t"))).unwrap(),
            serde_json::json!({ "kind": "team_id", "value": "t" })
        );
    }

    #[test]
    fn a_valid_hash_anchor_round_trips_with_an_unchanged_serialized_form() {
        // The newtype must be invisible on disk: a valid lowercase-hex anchor
        // serializes to exactly the same JSON as when the field was a plain
        // String, and parses back equal.
        let anchor = Anchor::Hash(hd("deadbeef"));
        let value = serde_json::to_value(&anchor).unwrap();
        assert_eq!(
            value,
            serde_json::json!({ "kind": "hash", "value": "deadbeef".repeat(5) })
        );
        let back: Anchor = serde_json::from_value(value).unwrap();
        assert_eq!(back, anchor);
    }

    #[test]
    fn a_malformed_on_disk_anchor_is_rejected_at_load_fail_closed() {
        // Incident: the hand-edited `{"kind":"team_id","value":""}` entry that loaded and then never matched.
        const HASH_RULE: &str = "hash anchor must be 40 or 64 lowercase hex characters";
        for (kind, bad, rule) in [
            ("team_id", String::new(), "team id must be non-empty"),
            ("hash", "AB".repeat(20), HASH_RULE),
            ("hash", String::new(), HASH_RULE),
            ("hash", "zz".repeat(20), HASH_RULE),
            ("hash", "ab".repeat(19), HASH_RULE),
            ("hash", format!("{}a", "ab".repeat(20)), HASH_RULE),
            ("hash", "ab".repeat(21), HASH_RULE),
        ] {
            let anchor = serde_json::json!({ "kind": kind, "value": bad });
            // Through the full file shape at the load boundary: one bad entry
            // poisons the whole list with the same tampering-class error as
            // any other decode failure, and the error names the rule.
            let file = serde_json::json!({
                "version": Allowlist::VERSION,
                "clients": [
                    { "name": "good", "anchor": { "kind": "team_id", "value": "TEAMID0001" }, "added_unix": 0 },
                    { "name": "bad", "anchor": anchor, "added_unix": 0 },
                ],
            });
            let err = Allowlist::decode(&serde_json::to_vec(&file).unwrap())
                .expect_err(&format!("{kind} anchor value {bad:?} must be refused"));
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{kind} {bad:?}");
            assert!(
                err.to_string().starts_with("clients.json: ") && err.to_string().contains(rule),
                "{kind} {bad:?}: {err}"
            );
        }
    }

    #[test]
    fn resolve_anchor_normalizes_cli_input_but_refuses_non_hex() {
        use crate::cli::AnchorSpec;
        // User INPUT keeps its historical convenience: uppercase hex is
        // normalized to the canonical lowercase form.
        assert_eq!(
            resolve_anchor(&AnchorSpec::Hash("DEADBEEF".repeat(5))).unwrap(),
            Anchor::Hash(hd("deadbeef"))
        );
        // Non-hex, empty, and wrong-width input are refused with the digest's
        // own rule, so the user is never told a value fails a rule it meets
        // (`--hash deadbeef` used to be reported as not lowercase hex).
        for bad in ["", "not-hex", "dead beef", "deadbeef"] {
            let err = resolve_anchor(&AnchorSpec::Hash(bad.into())).unwrap_err();
            assert_eq!(
                err, "--hash: hash anchor must be 40 or 64 lowercase hex characters",
                "{bad:?}"
            );
        }
    }

    #[test]
    fn latch_turns_an_absent_list_into_tampering() {
        // Unlatched + absent: the legitimate bootstrap (fresh install).
        assert!(apply_latch(None, &rev_with_latch(false)).unwrap().is_none());
        // Latched + absent: a client allowlist existed here, so its absence is
        // a deletion -> fail closed (the ADR-0024 silent-revert residual).
        let err = apply_latch(None, &rev_with_latch(true)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        // A present list passes through untouched regardless of the latch.
        let list = list_of(vec![]);
        assert!(apply_latch(Some(list.clone()), &rev_with_latch(false))
            .unwrap()
            .is_some());
        assert!(apply_latch(Some(list), &rev_with_latch(true))
            .unwrap()
            .is_some());
    }

    #[test]
    fn the_latch_is_the_enrollment_flag_not_an_adjacent_one() {
        // The record's other booleans must not be able to play the latch:
        // `killed: true` on an unenrolled machine keeps the bootstrap posture
        // for an absent list (the kill switch has its own enforcement point)...
        let mut killed_only = rev_with_latch(false);
        killed_only.killed = true;
        killed_only.epoch = 9;
        killed_only.kill_epoch = 9;
        assert!(apply_latch(None, &killed_only).unwrap().is_none());
        // ...and `clients_enrolled: true` fails closed even with every other
        // flag at its default. Taking the whole record makes picking the
        // wrong field impossible at the call sites, and this pins WHICH field
        // the function itself reads.
        assert!(apply_latch(None, &rev_with_latch(true)).is_err());
    }

    #[test]
    fn a_malformed_pair_request_is_refused_before_the_presence_prompt() {
        // Order matters: the name check runs BEFORE the presence gate, so a
        // bad request can never raise a hardware sheet (and, under this test
        // harness, never reaches the audit sink either - the early return is
        // the whole point). The floor arrives as the CLI's precondition
        // failure here; if the ordering ever broke, the result would be the
        // Presence error instead of InvalidName. See presence's module docs
        // for why tests must not reach the hardware rung.
        let err = pair_client_with_presence(
            "bad name!",
            Anchor::Hash(hd("abc")),
            crate::audit::Surface::Cli,
            Err(presence::PresenceError::NotInteractive),
        )
        .unwrap_err();
        assert!(matches!(err, PairClientError::InvalidName));
    }

    #[test]
    fn unknown_fields_are_rejected_at_every_nesting_level() {
        // The record's own strictness is pinned for every record in runtime_record.rs; an entry and
        // the anchor's adjacently-tagged {kind, value} shape must be as strict, or a tampered field
        // inside an entry would be skimmed over.
        assert!(serde_json::from_value::<ClientEntry>(serde_json::json!({
            "name": "codex",
            "anchor": { "kind": "hash", "value": "ab".repeat(20) },
            "added_unix": 0,
            "surprise": true
        }))
        .is_err());
        assert!(serde_json::from_value::<Anchor>(serde_json::json!({
            "kind": "hash",
            "value": "ab".repeat(20),
            "surprise": true
        }))
        .is_err());
        // Positive controls: the same shapes without the extra field parse.
        assert!(serde_json::from_value::<Anchor>(serde_json::json!({
            "kind": "hash",
            "value": "ab".repeat(20)
        }))
        .is_ok());
        assert!(serde_json::from_value::<Anchor>(serde_json::json!({
            "kind": "team_id",
            "value": "TEAMID0001"
        }))
        .is_ok());
    }
}
