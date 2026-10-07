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
//! signed client                -> Anchor::Signer, stable across the weekly re-sign of a free Apple
//!                                 Development certificate (which changes the cdhash)
//! unsigned / ad-hoc dev build  -> Anchor::Hash, re-pair after every renewal
//! ```

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::cli::{AnchorSpec, PairClientArgs};
use crate::ipc::{self, HashDigest, SignerId};
use crate::presence::{self, PresenceAttestation};
use crate::trust::{Clients, Scope, Trust, TrustState};

/// The authorization key of an allowlist entry: the unforgeable thing a
/// harness's attested identity must match. Never the name. Both payloads are
/// parsed at the decode boundary ([`crate::ipc::HashDigest`],
/// [`crate::ipc::SignerId`]), so a value no measurement can equal never loads.
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
    /// Pin the code signer. Stable across the weekly re-sign of a free Apple
    /// Development certificate, so it survives renewals without a re-pair.
    /// Only available when the client image carries a trusted signature.
    Signer(SignerId),
}

impl std::fmt::Display for Anchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Anchor::Hash(h) => write!(f, "hash {h}"),
            Anchor::Signer(s) => write!(f, "signer {s}"),
        }
    }
}

/// A trusted client's label under the rule [`crate::ipc::validate_label`] states. A hand-edited record
/// with a blank name once loaded and made the extension refuse the whole `client_list_result` frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "envelope-schema",
    derive(schemars::JsonSchema),
    schemars(with = "String")
)]
#[serde(try_from = "String")]
pub struct ClientName(String);

const INVALID_CLIENT_NAME: &str =
    "invalid client name (want 1-32 chars of [A-Za-z0-9._-], starting alphanumeric)";

impl ClientName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ClientName {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if ipc::validate_label(&value) {
            Ok(ClientName(value))
        } else {
            Err(INVALID_CLIENT_NAME.to_string())
        }
    }
}

impl TryFrom<&str> for ClientName {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        ClientName::try_from(value.to_string())
    }
}

impl std::fmt::Display for ClientName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One trusted client. The `name` is a validated, human-facing label for the
/// user and the audit log; `anchor` is the authorization key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "envelope-schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ClientEntry {
    /// Human-facing label. NOT the authorization key -- a harness cannot admit
    /// itself by claiming a name.
    pub name: ClientName,
    /// The unforgeable authorization key.
    pub anchor: Anchor,
    /// When this client was paired, Unix seconds. For the audit/status
    /// surface; not used in the admission decision.
    pub added_unix: u64,
}

/// Add or replace a client in one atomic write of the trust record. Module-private on purpose: the ONLY entry point is
/// [`pair_client_with_presence`], which runs the presence prompt and audits every outcome, so no allowlist
/// mutation can skip the trail and no path can enroll without a [`PresenceAttestation`], which only
/// [`crate::presence`] mints (pairing GRANTS capability).
fn pair(name: &ClientName, anchor: Anchor, auth: PresenceAttestation) -> io::Result<()> {
    // Consumed as evidence; the caller writes the audit record that names its path.
    let _ = auth;
    ipc::with_runtime_lock(|lock| {
        Trust::mutate_locked(lock, Scope::Clients, |trust| {
            trust.pair(ClientEntry {
                name: name.clone(),
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
        let named = |c: &ClientEntry| c.name.as_str() == name;
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
        audit_client_revoked(surface, name);
    }
    Ok(removed)
}

/// The [`AuditKind::RevokeClient`](crate::audit::AuditKind::RevokeClient) record one removed entry leaves.
/// Call it after the write, outside the lock.
pub(crate) fn audit_client_revoked(surface: crate::audit::Surface, name: &str) {
    crate::audit::record(
        crate::audit::AuditRecord::new(crate::audit::AuditKind::RevokeClient)
            .surface(surface)
            .name(name)
            .outcome("ok"),
    );
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
    /// The request cannot be put to a prompt as asked (a summary past the bound a presence prompt can show);
    /// refused BEFORE any prompt, unaudited like every promptless validity refusal.
    Invalid(String),
    /// The user-presence gate refused: a hardware refusal, a non-interactive
    /// stdin, or a declined prompt. Never downgraded, already audited.
    Presence(presence::PresenceError),
    /// Presence passed but the allowlist write failed.
    Io(io::Error),
}

impl std::fmt::Display for PairClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PairClientError::Invalid(e) => write!(f, "invalid pairing request: {e}"),
            PairClientError::Presence(e) => write!(f, "user presence not attested: {e}"),
            PairClientError::Io(e) => write!(f, "could not write the allowlist: {e}"),
        }
    }
}

/// Pair a trusted client behind the user-presence gate: the one entry point every surface uses to
/// GRANT harness capability. Runs `attest`, the surface's presence proof (the CLI's typed phrase, the host's
/// already-verified tap), then writes the allowlist, and audits each outcome after the fact (refusal, write,
/// write failure) with the rung that decided it; returns the attesting path so the surface can tell the user
/// which proof authorized the pairing. Revocation stays friction-free on purpose: removing capability never
/// needs a human proof (the presence symmetry rule).
///
/// `attest` receives the reason a prompt shows; it runs after the name and anchor validated at the frame or
/// argv boundary, so a malformed request never reaches a prompt.
pub fn pair_client_with_presence(
    name: &ClientName,
    anchor: Anchor,
    surface: crate::audit::Surface,
    attest: impl FnOnce(&str) -> Result<presence::PresenceAttestation, presence::PresenceError>,
) -> Result<presence::PresencePath, PairClientError> {
    use crate::audit::{self, AuditKind, AuditRecord};
    let reason = format!(
        "Pair '{name}' as a trusted client of chromium-bridge? A trusted \
         client can drive your browser through this bridge."
    );
    let auth = match attest(&reason) {
        Ok(auth) => auth,
        Err(e) => {
            audit_pair_refused(name, surface, &e);
            return Err(PairClientError::Presence(e));
        }
    };
    let auth_path = auth.path().clone();
    let shown = anchor.to_string();
    match pair(name, anchor, auth) {
        Ok(()) => {
            audit::record(
                AuditRecord::new(AuditKind::PairClient)
                    .surface(surface)
                    .name(name.as_str())
                    .outcome("ok")
                    .detail(&format!("{shown}; auth={}", auth_path.wire_name())),
            );
            Ok(auth_path)
        }
        Err(e) => {
            audit::record(
                AuditRecord::new(AuditKind::PairClient)
                    .surface(surface)
                    .name(name.as_str())
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

/// The pairing trail for a presence gate that refused: log-after-decide, so the attempted silent enrollment is
/// visible whichever surface's gate refused it (the CLI's phrase inside [`pair_client_with_presence`], the
/// host's tap before the pairing ran).
pub fn audit_pair_refused(
    name: &ClientName,
    surface: crate::audit::Surface,
    e: &presence::PresenceError,
) {
    crate::audit::record(
        crate::audit::AuditRecord::new(crate::audit::AuditKind::PairClient)
            .surface(surface)
            .name(name.as_str())
            .outcome("refused")
            .detail(&format!("presence: {e}")),
    );
}

// ---- CLI handlers ----------------------------------------------------------

/// `pair-client`: add or replace a trusted client in the allowlist, behind
/// the CLI's presence path (the typed terminal confirmation). Prints a
/// confirmation and the resolved anchor. Returns a process exit code.
pub fn run_pair_client(client: PairClientArgs) -> i32 {
    let anchor = match resolve_anchor(client.anchor) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("pair-client: {e}");
            return 1;
        }
    };
    let shown = anchor.to_string();
    // The terminal witness comes first, by construction: a piped stdin arrives at the gate as the
    // precondition failure, refused (and audited) after the name check, promptless.
    match pair_client_with_presence(&client.name, anchor, crate::audit::Surface::Cli, |reason| {
        presence::TerminalStdin::require()
            .and_then(|terminal| presence::tty_confirm(reason, terminal))
    }) {
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
        AnchorSpec::Signer(signer) => Ok(Anchor::Signer(signer)),
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
    "--hash <sha256> or --signer <publisher subject>; the server logs the hash, and ",
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
            eprintln!("list-clients: {}", crate::trust::unreadable_sentence(&e));
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
                println!("  {}  ({})", c.name, c.anchor);
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
        assert!(err.contains("--hash") && err.contains("--signer"), "{err}");
    }

    fn anchor_entry(kind: &str, value: String) -> serde_json::Value {
        serde_json::json!({ "name": "bad", "anchor": { "kind": kind, "value": value }, "added_unix": 0 })
    }

    fn named_entry(name: &str) -> serde_json::Value {
        serde_json::json!({ "name": name, "anchor": { "kind": "signer", "value": "SIGNER0001" }, "added_unix": 0 })
    }

    #[test]
    fn a_malformed_on_disk_entry_is_rejected_at_load_fail_closed() {
        // Incidents: the hand-edited `{"kind":"signer","value":""}` anchor that loaded and then never
        // matched, and the hand-edited `"name":""` that loaded and made the extension refuse the whole
        // `client_list_result` frame.
        const HASH_RULE: &str = "hash anchor must be 40 or 64 lowercase hex characters";
        const NAME_RULE: &str =
            "invalid client name (want 1-32 chars of [A-Za-z0-9._-], starting alphanumeric)";
        for (case, entry, rule) in [
            (
                "blank signer",
                anchor_entry("signer", String::new()),
                "signer anchor must be non-empty",
            ),
            (
                "uppercase hash",
                anchor_entry("hash", "AB".repeat(20)),
                HASH_RULE,
            ),
            ("blank hash", anchor_entry("hash", String::new()), HASH_RULE),
            (
                "non-hex hash",
                anchor_entry("hash", "zz".repeat(20)),
                HASH_RULE,
            ),
            (
                "short hash",
                anchor_entry("hash", "ab".repeat(19)),
                HASH_RULE,
            ),
            (
                "odd-length hash",
                anchor_entry("hash", format!("{}a", "ab".repeat(20))),
                HASH_RULE,
            ),
            (
                "long hash",
                anchor_entry("hash", "ab".repeat(21)),
                HASH_RULE,
            ),
            ("blank name", named_entry(""), NAME_RULE),
            (
                "name with a space and punctuation",
                named_entry("bad name!"),
                NAME_RULE,
            ),
            (
                "name over 32 chars",
                named_entry(&"x".repeat(33)),
                NAME_RULE,
            ),
            ("name starting like a flag", named_entry("-flag"), NAME_RULE),
        ] {
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
                    { "name": "good", "anchor": { "kind": "signer", "value": "SIGNER0001" }, "added_unix": 0 },
                    entry,
                ],
            });
            let err = Trust::decode(&serde_json::to_vec(&file).unwrap())
                .expect_err(&format!("{case} must be refused"));
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{case}");
            assert!(
                err.to_string().starts_with("trust.json: ") && err.to_string().contains(rule),
                "{case}: {err}"
            );
        }
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
            "kind": "signer",
            "value": "SIGNER0001"
        }))
        .is_ok());
    }
}
