//! Host-side trusted-client allowlist: which MCP-client harnesses (Claude
//! Code, Copilot, Codex, ...) are permitted to drive the browser through this
//! bridge.
//!
//! ## Why this exists
//!
//! ADR-0019/0020 attest that a bridge peer is *our own binary*. That is the
//! right identity for the browser leg (the native host and the MCP server are
//! the same `chromium-bridge` binary in two modes). It says nothing about
//! *who is driving the MCP server* over its stdio: today anything that spawns
//! the binary in MCP mode owns its stdin and is trusted unconditionally. This
//! module is the enforcement policy for the harness->stdio admission boundary
//! (threat-model boundary 1): a persisted set of client identities, keyed on
//! the harness's **attested code identity**, that the broker checks before it
//! will serve a harness's tool calls. See ADR-0024.
//!
//! ## Authorization keys on the attested hash, never the self-asserted name
//!
//! Each entry pairs a human-facing `name` (a validated label like
//! `claude-code`) with an [`Anchor`] that is the actual authorization key. The
//! name is for the user and the audit surface only; a harness cannot admit
//! itself by *claiming* to be `claude-code`. Admission requires that the
//! harness's kernel-attested identity ([`ClientIdentity`], measured by
//! [`crate::ipc::attest_parent`]) match an anchor. This is the zero-trust rule
//! from AGENTS.md applied to the client boundary: a self-reported identity is
//! not enforcement.
//!
//! ## Anchors and re-signing
//!
//! A free Apple Development certificate re-signs roughly weekly, which changes
//! a binary's `cdhash`. Pinning the raw hash would then break admission on
//! every re-sign and force a re-pair. So where a client is signed with a Team
//! ID, the anchor pins the **Team ID** ([`Anchor::TeamId`]), which is stable
//! across re-signs. Unsigned / ad-hoc dev builds have no Team ID, so they fall
//! back to [`Anchor::Hash`] with an explicit re-pair-on-renewal path. See
//! ADR-0024 and [`ClientIdentity`].
//!
//! ## Enrolled vs. unenrolled (fail-closed once enrolled)
//!
//! The allowlist file is absent until the user pairs a first client. Absent
//! means *unenrolled*: admission is not yet enforced and the bridge keeps the
//! pre-enrollment posture (the same-user residual of threat #4), logged
//! loudly. Once the file exists, admission is **enforced**: only a matching
//! identity is admitted and everything else fails closed -- including an
//! identity we could not measure. This mirrors the enrollment ceremony
//! (ADR-0021): opt-in, host-side first, with the residual named honestly until
//! it is turned on.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::ipc::{self, ClientIdentity};

/// The current on-disk allowlist schema version. Bumped only on a
/// breaking-shape change; unknown-field parsing is fail-closed
/// (`deny_unknown_fields`) so a newer file is rejected rather than
/// misinterpreted by an older binary.
const ALLOWLIST_VERSION: u32 = 1;

/// Upper bound on the allowlist file when reading it back, matching the lock
/// file's cap. A few dozen entries are a few KB; anything larger is not ours
/// and is rejected rather than slurped into memory.
const ALLOWLIST_MAX_BYTES: usize = 256 * 1024;

/// The authorization key of an allowlist entry: the unforgeable thing a
/// harness's attested identity must match. Never the name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Anchor {
    /// Pin the exact attested image hash (macOS `cdhash`, Linux
    /// `/proc/<pid>/exe` SHA256). Precise, but a code re-sign changes the
    /// `cdhash`, so this anchor requires a re-pair after a renewal. It is the
    /// only anchor available for unsigned / ad-hoc dev builds.
    Hash(String),
    /// Pin the macOS signing Team ID. Stable across the weekly re-sign of a
    /// free Apple Development certificate, so it survives renewals without a
    /// re-pair. Only available when the client image is Team-ID signed.
    TeamId(String),
}

/// One trusted client. The `name` is a validated, human-facing label for the
/// user and the audit log; `anchor` is the authorization key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// The persisted allowlist. Its mere *presence* on disk means admission is
/// enforced (see [`decide`]); an empty `clients` list is therefore a fully
/// locked bridge, not an open one.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allowlist {
    /// Schema version; see [`ALLOWLIST_VERSION`].
    #[serde(default)]
    pub version: u32,
    pub clients: Vec<ClientEntry>,
}

/// The admission verdict for a harness. Kept separate from acting on it so the
/// policy is a pure, exhaustively-tested function ([`decide`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// No allowlist exists yet (unenrolled). Admit, but the bridge is in the
    /// pre-enrollment posture: harness admission is not yet load-bearing and
    /// the caller must log that loudly. Carries the measured name only if an
    /// entry happens to match (it cannot, since there is no list) -- always
    /// `None` here; kept as a unit for symmetry.
    AdmitUnenrolled,
    /// An allowlist exists and the harness's attested identity matched an
    /// entry. Carries the matched entry's name for logging/audit.
    Admit { name: String },
    /// An allowlist exists and the harness did not match (or could not be
    /// measured at all). Fail closed: do not serve this harness.
    Refuse,
}

impl Allowlist {
    /// Path of the allowlist file in the 0700 per-user runtime directory.
    pub fn path() -> std::path::PathBuf {
        ipc::runtime_dir().join("clients.json")
    }

    /// Read the allowlist. `Ok(None)` when the file does not exist
    /// (unenrolled). A present-but-corrupt or oversized file is an error, NOT
    /// a silent `None`: treating a damaged allowlist as "unenrolled" would
    /// fail *open*, so the caller must fail closed on the error instead.
    pub fn load() -> io::Result<Option<Self>> {
        let Some(bytes) = ipc::read_capped(&Self::path(), ALLOWLIST_MAX_BYTES)? else {
            return Ok(None);
        };
        let list: Allowlist = serde_json::from_slice(&bytes).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("allowlist decode: {e}"))
        })?;
        if list.version != ALLOWLIST_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "allowlist version {} is not supported (this binary understands {})",
                    list.version, ALLOWLIST_VERSION
                ),
            ));
        }
        Ok(Some(list))
    }

    /// Whether `identity` matches any entry. Returns the matched entry's name.
    /// A `Hash` anchor matches the measured hash; a `TeamId` anchor matches a
    /// measured Team ID. Comparisons are plain equality: these are not secrets.
    fn matched_name(&self, identity: &ClientIdentity) -> Option<String> {
        self.clients.iter().find_map(|c| match &c.anchor {
            Anchor::Hash(h) if *h == identity.hash => Some(c.name.clone()),
            Anchor::TeamId(t) if identity.team_id.as_deref() == Some(t.as_str()) => {
                Some(c.name.clone())
            }
            _ => None,
        })
    }

    /// Add or replace a client. If an entry with the same `name` exists it is
    /// replaced (re-pair / renewal), so pairing the same client twice does not
    /// accumulate stale anchors. Persists atomically under the runtime lock.
    pub fn pair(name: &str, anchor: Anchor) -> io::Result<()> {
        if !crate::ipc::validate_label(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid client name (want 1-32 chars of [A-Za-z0-9._-], starting alphanumeric)",
            ));
        }
        ipc::with_runtime_lock(|| {
            let mut list = Self::load()?.unwrap_or_default();
            list.version = ALLOWLIST_VERSION;
            list.clients.retain(|c| c.name != name);
            list.clients.push(ClientEntry {
                name: name.to_string(),
                anchor,
                added_unix: now_unix(),
            });
            list.write()
        })
    }

    /// Remove the client with `name`. Returns whether an entry was removed.
    /// The file is left in place even when it becomes empty: an empty file
    /// still means "enrolled" (admission enforced, nobody admitted), which is
    /// the fail-closed reading of "the user revoked every client".
    pub fn revoke(name: &str) -> io::Result<bool> {
        ipc::with_runtime_lock(|| {
            let Some(mut list) = Self::load()? else {
                return Ok(false);
            };
            let before = list.clients.len();
            list.clients.retain(|c| c.name != name);
            let removed = list.clients.len() != before;
            if removed {
                list.version = ALLOWLIST_VERSION;
                list.write()?;
            }
            Ok(removed)
        })
    }

    /// Write atomically, 0600, under the caller-held runtime lock.
    fn write(&self) -> io::Result<()> {
        let bytes = serde_json::to_vec_pretty(self)?;
        ipc::write_private_atomic(&Self::path(), &bytes)
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

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---- CLI handlers ----------------------------------------------------------

/// `pair-client`: add or replace a trusted client in the allowlist. Prints a
/// confirmation and the resolved anchor. Returns a process exit code.
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
    match Allowlist::pair(&parsed.name, anchor.clone()) {
        Ok(()) => {
            let shown = match &anchor {
                Anchor::Hash(h) => format!("hash {h}"),
                Anchor::TeamId(t) => format!("Team ID {t}"),
            };
            println!("paired trusted client '{}' on {shown}", parsed.name);
            println!("harness admission is now ENFORCED (fail closed for anything else)");
            0
        }
        Err(e) => {
            eprintln!("pair-client: could not write the allowlist: {e}");
            1
        }
    }
}

/// Turn a CLI anchor spec into a concrete [`Anchor`], measuring this
/// invocation's parent when asked (`--this-parent`).
fn resolve_anchor(spec: &crate::cli::AnchorSpec) -> Result<Anchor, String> {
    use crate::cli::AnchorSpec;
    match spec {
        AnchorSpec::Hash(h) => {
            let h = h.to_ascii_lowercase();
            if h.is_empty() || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("--hash must be non-empty lowercase hex".into());
            }
            Ok(Anchor::Hash(h))
        }
        AnchorSpec::TeamId(t) => {
            if t.is_empty() {
                return Err("--team-id must be non-empty".into());
            }
            Ok(Anchor::TeamId(t.clone()))
        }
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
    match Allowlist::revoke(&name) {
        Ok(true) => {
            println!("revoked trusted client '{name}'");
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
/// code.
pub fn run_list_clients() -> i32 {
    match Allowlist::load() {
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
            eprintln!("list-clients: could not read the allowlist: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(hash: &str, team: Option<&str>) -> ClientIdentity {
        ClientIdentity {
            hash: hash.to_string(),
            team_id: team.map(str::to_string),
        }
    }

    fn list_of(entries: Vec<ClientEntry>) -> Allowlist {
        Allowlist {
            version: ALLOWLIST_VERSION,
            clients: entries,
        }
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
            anchor: Anchor::Hash("abc".into()),
            added_unix: 0,
        }]);
        assert_eq!(decide(Some(&l), None), Decision::Refuse);
    }

    #[test]
    fn hash_anchor_matches_exact_hash_only() {
        let l = list_of(vec![ClientEntry {
            name: "codex".into(),
            anchor: Anchor::Hash("deadbeef".into()),
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
            anchor: Anchor::TeamId("3ZMH96L4V9".into()),
            added_unix: 0,
        }]);
        assert_eq!(
            decide(Some(&l), Some(&id("hash-after-resign", Some("3ZMH96L4V9")))),
            Decision::Admit {
                name: "claude-code".into()
            }
        );
        // Wrong team id -> refuse. A matching cdhash is irrelevant to a
        // Team-ID anchor.
        assert_eq!(
            decide(Some(&l), Some(&id("hash-after-resign", Some("OTHERTEAM")))),
            Decision::Refuse
        );
        // No team id measured at all (ad-hoc build) -> refuse against a
        // Team-ID anchor.
        assert_eq!(
            decide(Some(&l), Some(&id("hash-after-resign", None))),
            Decision::Refuse
        );
    }

    #[test]
    fn empty_enrolled_list_admits_nobody() {
        // A present-but-empty allowlist is enrolled: it fails every harness
        // closed rather than reverting to the open pre-enrollment posture.
        let l = list_of(vec![]);
        assert_eq!(
            decide(Some(&l), Some(&id("anything", Some("any")))),
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
                anchor: Anchor::Hash("h-claude".into()),
                added_unix: 0,
            },
            ClientEntry {
                name: "codex".into(),
                anchor: Anchor::TeamId("TEAMX".into()),
                added_unix: 0,
            },
        ]);
        assert_eq!(
            decide(Some(&l), Some(&id("h-imposter", None))),
            Decision::Refuse
        );
        // The genuine hash for claude-code admits under its name.
        assert_eq!(
            decide(Some(&l), Some(&id("h-claude", None))),
            Decision::Admit {
                name: "claude-code".into()
            }
        );
    }

    #[test]
    fn entry_serde_roundtrips_both_anchor_kinds() {
        let hash_entry = ClientEntry {
            name: "codex".into(),
            anchor: Anchor::Hash("ab".repeat(32)),
            added_unix: 42,
        };
        let team_entry = ClientEntry {
            name: "claude-code".into(),
            anchor: Anchor::TeamId("3ZMH96L4V9".into()),
            added_unix: 7,
        };
        let list = list_of(vec![hash_entry.clone(), team_entry.clone()]);
        let bytes = serde_json::to_vec(&list).unwrap();
        let back: Allowlist = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.clients, vec![hash_entry, team_entry]);
        assert_eq!(back.version, ALLOWLIST_VERSION);
    }

    #[test]
    fn anchor_serde_shape_is_tagged() {
        // The on-disk shape is a tagged {kind, value} so a hash and a team id
        // can never be confused for one another.
        assert_eq!(
            serde_json::to_value(Anchor::Hash("h".into())).unwrap(),
            serde_json::json!({ "kind": "hash", "value": "h" })
        );
        assert_eq!(
            serde_json::to_value(Anchor::TeamId("t".into())).unwrap(),
            serde_json::json!({ "kind": "team_id", "value": "t" })
        );
    }

    #[test]
    fn unknown_fields_are_rejected_fail_closed() {
        // deny_unknown_fields: a file with an extra field (a newer schema, or
        // tampering) is refused rather than parsed leniently.
        let json = serde_json::json!({
            "version": 1,
            "clients": [],
            "surprise": true
        });
        assert!(serde_json::from_value::<Allowlist>(json).is_err());
    }
}
