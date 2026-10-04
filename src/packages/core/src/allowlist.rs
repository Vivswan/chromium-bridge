//! Host-side trusted-client allowlist: which MCP-client harnesses (Claude Code, Copilot, Codex, ...) may drive
//! the browser through this bridge. The list lives in the trust record ([`crate::trust`]); this module owns
//! the entry types, the pairing and revocation writes, and their CLI handlers.
//!
//! Peer attestation proves a bridge peer is our own binary but says nothing about who drives the MCP server
//! over its stdio, so the broker checks the harness's kernel-attested identity ([`crate::ipc::ClientIdentity`], measured by
//! [`crate::ipc::attest_parent`]) against the paired entries before serving its tool calls
//! ([`crate::trust::TrustState::decide`]). Admission keys on the [`Anchor`], never the human-facing `name`.
//!
//! ```text
//! Team-ID-signed client        -> Anchor::TeamId, stable across the weekly re-sign of a free Apple
//!                                 Development certificate (which changes the cdhash)
//! unsigned / ad-hoc dev build  -> Anchor::Hash, re-pair after every renewal
//! ```

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::cli::{AnchorSpec, PairClientArgs};
use crate::ipc::{self, HashDigest, TeamId};
use crate::presence::{self, PresenceAttestation};
use crate::trust::{Clients, Scope, Trust, TrustState};

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
    pub added_unix: u64,
}

/// Add or replace a client in one atomic write of the trust record. Module-private on purpose: the ONLY entry point is
/// [`pair_client_with_presence`], which runs the presence ladder and audits every outcome, so no allowlist
/// mutation can skip the trail and no path can enroll without a [`PresenceAttestation`], which only
/// [`presence::require_presence`] mints (pairing GRANTS capability).
fn pair(name: &str, anchor: Anchor, auth: PresenceAttestation) -> io::Result<()> {
    // The attestation is structural evidence, consumed here; the audit record that names its path is written
    // by the caller, log-after-decide.
    let _ = auth;
    if !crate::ipc::validate_label(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid client name (want 1-32 chars of [A-Za-z0-9._-], starting alphanumeric)",
        ));
    }
    ipc::with_runtime_lock(|lock| {
        Trust::mutate_locked(lock, Scope::Clients, |trust| {
            trust.pair(ClientEntry {
                name: name.to_string(),
                anchor,
                added_unix: now_unix(),
            })
        })
    })?;
    Ok(())
}

/// Remove the client with `name`; returns whether an entry was removed. The list stays in place even when
/// empty: an empty list still means paired (nobody admitted), the fail-closed reading of "revoked every
/// client". Audited HERE, not by the caller, so revocation cannot rewrite trust state without a trail entry.
/// A live broker re-decides every request from the record, so the revoked client's next call is refused.
pub fn revoke(name: &str, surface: crate::audit::Surface) -> io::Result<bool> {
    let removed = ipc::with_runtime_lock(|lock| {
        let named = |c: &ClientEntry| c.name == name;
        let Clients::Paired(current) = TrustState::current()?.clients().clone() else {
            return Ok(false);
        };
        if !current.iter().any(named) {
            return Ok(false);
        }
        Trust::mutate_locked(lock, Scope::Clients, |trust| trust.revoke(name))?;
        Ok(true)
    })?;
    if removed {
        crate::audit::record(
            crate::audit::AuditRecord::new(crate::audit::AuditKind::RevokeClient)
                .surface(surface)
                .name(name)
                .outcome("ok"),
        );
    }
    Ok(removed)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---- The presence-gated pairing API -----------------------------------------

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

/// Pair a trusted client behind the user-presence gate: the one entry point every surface uses to
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
    match pair(name, anchor, auth) {
        Ok(()) => {
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
pub fn run_pair_client(client: PairClientArgs) -> i32 {
    let anchor = match resolve_anchor(client.anchor) {
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
        &client.name,
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
                client.name,
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

/// Turn the CLI's anchor choice into a concrete [`Anchor`], measuring this
/// invocation's parent when asked (`--this-parent`). Explicit anchors were
/// validated at the argv boundary and pass straight through.
///
/// `--this-parent` is Unix-only. The server keys a Windows harness on the
/// creator of its stdin pipe, and this command either runs from a console (no
/// pipe, nothing to measure) or from a pipe (which the presence gate refuses),
/// so no measurement here could ever match what admission measures.
fn resolve_anchor(spec: AnchorSpec) -> Result<Anchor, String> {
    match spec {
        AnchorSpec::Hash(hash) => Ok(Anchor::Hash(hash)),
        AnchorSpec::TeamId(team_id) => Ok(Anchor::TeamId(team_id)),
        #[cfg(unix)]
        AnchorSpec::ThisParent => {
            let id = ipc::attest_parent()
                .map_err(|e| format!("could not attest the parent process: {e}"))?;
            Ok(Anchor::Hash(id.hash))
        }
        #[cfg(windows)]
        AnchorSpec::ThisParent => Err(THIS_PARENT_UNAVAILABLE_ON_WINDOWS.to_string()),
    }
}

/// The refusal names the two anchors that do work and where their values come
/// from (the server logs a measured, unenrolled harness at startup).
#[cfg(windows)]
const THIS_PARENT_UNAVAILABLE_ON_WINDOWS: &str = concat!(
    "--this-parent is unavailable on Windows: the server identifies a harness by the ",
    "creator of its stdin pipe, which a console command has none of. Pair with ",
    "--hash <sha256> or --team-id <publisher subject>; the server logs the hash, and ",
    "the subject when the image is signed, at startup while unenrolled"
);

/// `revoke-client`: remove a trusted client. Returns a process exit code.
pub fn run_revoke_client(name: &str) -> i32 {
    match revoke(name, crate::audit::Surface::Cli) {
        Ok(true) => {
            println!("revoked trusted client '{name}'");
            println!(
                "a live broker refuses this client's next request and its re-attach; an idle \
                 connection is dropped within a second"
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

/// `list-clients`: print the trusted-client allowlist. Returns a process exit code.
pub fn run_list_clients() -> i32 {
    let trust = match TrustState::current() {
        Ok(trust) => trust,
        Err(e) => {
            eprintln!("list-clients: could not read the trust record: {e}");
            eprintln!("(treating the trust state as suspect; fail closed)");
            return 1;
        }
    };
    match trust.clients() {
        Clients::NeverPaired => {
            println!(
                "no trusted-client allowlist yet (UNENROLLED: harness admission not enforced)"
            );
        }
        Clients::Paired(clients) if clients.is_empty() => {
            println!("trusted-client allowlist is EMPTY (enrolled: every harness fails closed)");
        }
        Clients::Paired(clients) => {
            println!("trusted clients ({}):", clients.len());
            for c in clients {
                let anchor = match &c.anchor {
                    Anchor::Hash(h) => format!("hash {h}"),
                    Anchor::TeamId(t) => format!("Team ID {t}"),
                };
                println!("  {}  ({anchor})", c.name);
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_record::RuntimeRecord as _;

    /// On Windows `--this-parent` can never pair: a console stdin has no pipe
    /// creator for the server to key on, and a piped stdin is refused by the
    /// presence gate. The refusal must name the anchors that do work, so the
    /// operator is not left with a bare measurement error.
    #[cfg(windows)]
    #[test]
    fn this_parent_is_refused_on_windows_naming_the_anchors_that_work() {
        let err = resolve_anchor(AnchorSpec::ThisParent).unwrap_err();
        assert!(err.contains("--hash") && err.contains("--team-id"), "{err}");
    }

    /// A 40-character test digest from a lowercase-hex seed.
    fn hd(seed: &str) -> HashDigest {
        HashDigest::try_from(seed.chars().cycle().take(40).collect::<String>()).unwrap()
    }

    /// A test team id from a non-empty literal.
    fn tid(team: &str) -> TeamId {
        TeamId::try_from(team).unwrap()
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
            // poisons the whole record with the same tampering-class error as
            // any other decode failure, and the error names the rule.
            let file = serde_json::json!({
                "version": Trust::VERSION,
                "epoch": 1,
                "killed": false,
                "kill_epoch": 0,
                "host_key_epoch": 0,
                "policy_epoch": 0,
                "lang_epoch": 0,
                "clients": [
                    { "name": "good", "anchor": { "kind": "team_id", "value": "TEAMID0001" }, "added_unix": 0 },
                    { "name": "bad", "anchor": anchor, "added_unix": 0 },
                ],
            });
            let err = Trust::decode(&serde_json::to_vec(&file).unwrap())
                .expect_err(&format!("{kind} anchor value {bad:?} must be refused"));
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{kind} {bad:?}");
            assert!(
                err.to_string().starts_with("trust.json: ") && err.to_string().contains(rule),
                "{kind} {bad:?}: {err}"
            );
        }
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
