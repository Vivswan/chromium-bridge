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
use crate::presence::{self, PresenceAttestation};
use crate::revocation::Revocation;

/// The current on-disk allowlist schema version. Bumped only on a
/// breaking-shape change; unknown-field parsing is fail-closed
/// (`deny_unknown_fields`) so a newer file is rejected rather than
/// misinterpreted by an older binary.
const ALLOWLIST_VERSION: u32 = 1;

/// Upper bound on the allowlist file when reading it back. A few dozen
/// entries are a few KB; anything larger is not ours and is rejected rather
/// than slurped into memory.
const ALLOWLIST_MAX_BYTES: usize = 256 * 1024;

/// A validated image digest for [`Anchor::Hash`]: non-empty, lowercase ASCII
/// hex - the canonical form every attested identity is measured in (both
/// platforms hex-encode with lowercase digits, `ipc::rand::hex_encode`) and
/// the form [`resolve_anchor`] has always normalized user input into.
///
/// Holding the invariant in the type keeps the plain-equality admission match
/// sound: a digest that could never equal a measured identity (uppercase,
/// empty, non-hex) cannot be constructed, so it is refused at the parse
/// boundary instead of becoming a permanent, silent `Refuse`. An on-disk
/// value that violates the form makes the whole `clients.json` fail to
/// decode, which callers already treat as a corrupt allowlist and fail
/// closed on - deliberately NOT silently normalized into a valid digest,
/// which would mask tampering. Serializes as the plain inner string, so the
/// on-disk and wire shapes of a valid anchor are unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct HashDigest(String);

impl HashDigest {
    /// The digest as its lowercase hex string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for HashDigest {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let canonical = !value.is_empty()
            && value
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if canonical {
            Ok(HashDigest(value))
        } else {
            Err("hash anchor must be non-empty lowercase hex".to_string())
        }
    }
}

impl TryFrom<&str> for HashDigest {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        HashDigest::try_from(value.to_string())
    }
}

impl From<HashDigest> for String {
    fn from(digest: HashDigest) -> String {
        digest.0
    }
}

impl std::fmt::Display for HashDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Schema-identical to a plain string on purpose: the canonical-form rule is
/// enforced by the Rust parser at the trust boundary (ADR-0028's single
/// source), and the generated TS wire schema must stay exactly what it was
/// when this field was a `String` - the extension only ever consumes these
/// values read-only in `client_list_result`.
#[cfg(feature = "envelope-schema")]
impl schemars::JsonSchema for HashDigest {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        <String as schemars::JsonSchema>::schema_name()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        <String as schemars::JsonSchema>::schema_id()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        <String as schemars::JsonSchema>::json_schema(generator)
    }

    fn inline_schema() -> bool {
        <String as schemars::JsonSchema>::inline_schema()
    }
}

/// The authorization key of an allowlist entry: the unforgeable thing a
/// harness's attested identity must match. Never the name.
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
    TeamId(String),
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
            Anchor::Hash(h) if h.as_str() == identity.hash => Some(c.name.clone()),
            Anchor::TeamId(t) if identity.team_id.as_deref() == Some(t.as_str()) => {
                Some(c.name.clone())
            }
            _ => None,
        })
    }

    /// Add or replace a client. If an entry with the same `name` exists it is
    /// replaced (re-pair / renewal), so pairing the same client twice does not
    /// accumulate stale anchors. Persists atomically under the runtime lock.
    ///
    /// Pairing GRANTS capability (the presence symmetry rule, ADR-0031), so
    /// the write demands a [`PresenceAttestation`]: the only way to obtain
    /// one is [`presence::require_presence`], which means no code path can
    /// enroll a client without the user-presence ladder having run - Touch ID
    /// where the machine has it, an explicit interactive confirmation where
    /// it does not.
    ///
    /// The one-way enrollment latch (ADR-0025) is set BEFORE the allowlist is
    /// written, so a partial failure fails closed rather than open: if the
    /// latch write succeeds but the `clients.json` write then fails, the next
    /// admission sees the latch set and no allowlist and refuses as tampering
    /// (the user re-runs `pair-client`, which completes the write). The reverse
    /// order would leave a usable allowlist with no deletion evidence, so a
    /// later `rm clients.json` would silently revert to open. The bump the
    /// latch carries also nudges running enforcement points to re-read.
    ///
    /// Module-private on purpose: the ONLY entry point is
    /// [`pair_client_with_presence`], which runs the presence ladder and
    /// audits every outcome (granted, refused, and write-failed) with the
    /// rung that decided it. Keeping the audit in that single wrapper - and
    /// making this function unreachable from outside the module - is what
    /// makes the ADR-0030 "every allowlist mutation leaves a trail entry"
    /// property un-bypassable without duplicating records.
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
            list.version = ALLOWLIST_VERSION;
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

    /// Remove the client with `name`. Returns whether an entry was removed.
    /// The file is left in place even when it becomes empty: an empty file
    /// still means "enrolled" (admission enforced, nobody admitted), which is
    /// the fail-closed reading of "the user revoked every client".
    ///
    /// A removal is audited HERE, not by the caller, so revocation cannot
    /// rewrite trust state without a trail entry (audit completeness as a
    /// property of the function, ADR-0030 - the same shape as
    /// [`crate::kill::engage`]). `surface` names the trusted surface that
    /// acted, for the record. Log-after-decide: the record is written after
    /// the rewrite and epoch bump, outside the runtime lock (audit I/O never
    /// runs inside a critical section, see [`crate::audit`]).
    ///
    /// The allowlist rewrite is the authoritative act: it is what a re-attach
    /// reads (refused at once) and what the broker's watcher re-decides every
    /// tick against. The revocation-epoch bump that follows is a PROMPTNESS
    /// signal only, accelerating the broker's per-request fast path so a live
    /// connection is dropped on its next call rather than at the next poll.
    /// Enforcement therefore does NOT depend on the bump succeeding: if the
    /// bump write fails, the client is still gone from `clients.json`, so
    /// re-attach is refused and the watcher (which re-decides unconditionally,
    /// not on an epoch change) drops the live connection within a poll
    /// interval. The failure is logged, not swallowed silently. Both writes
    /// happen under one runtime-lock hold, which serializes them against other
    /// WRITERS; it does not make them atomic to the broker's lock-free readers,
    /// which is why the list-first ordering and the unconditional watcher (not
    /// the lock) are what keep a concurrent reader safe.
    pub fn revoke(name: &str, surface: crate::audit::Surface) -> io::Result<bool> {
        let removed = ipc::with_runtime_lock(|lock| {
            let Some(mut list) = Self::load()? else {
                return Ok(false);
            };
            let before = list.clients.len();
            list.clients.retain(|c| c.name != name);
            let removed = list.clients.len() != before;
            if removed {
                list.version = ALLOWLIST_VERSION;
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

    /// Write atomically, 0600. The [`ipc::RuntimeLockToken`] proves the
    /// caller holds the runtime lock (it is only minted inside
    /// [`ipc::with_runtime_lock`]), so a lock-free rewrite of the allowlist
    /// does not compile.
    fn write(&self, _lock: &ipc::RuntimeLockToken) -> io::Result<()> {
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

/// Load the allowlist for an ADMISSION decision, honoring the tamper-evidence
/// latch (ADR-0025). Takes the whole [`Revocation`] record and reads its
/// `clients_enrolled` latch itself, so a caller cannot hand-pick the wrong
/// one of the record's adjacent flags to play the latch -- passing `killed`
/// here on a latched machine would silently reopen the pre-enrollment
/// fail-open ADR-0025 closed. With the latch set, an ABSENT
/// `clients.json` is no longer the bootstrap posture -- a client allowlist
/// existed on this machine, so its disappearance is a deletion, and deletion
/// must fail closed instead of silently reverting to the open pre-enrollment
/// posture (the ADR-0024 residual this closes for the single-file case).
/// Every other outcome is [`Allowlist::load`] unchanged.
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

/// Pair a trusted client behind the user-presence gate (ADR-0031): the one
/// entry point every surface uses to GRANT harness capability. Runs the
/// presence ladder (Touch ID first; `floor` only when hardware is genuinely
/// unavailable), audits the outcome either way with the rung that decided it,
/// and only then writes the allowlist. Returns the attesting path so the
/// surface can tell the user which proof authorized the pairing.
///
/// Surfaces: the CLI passes [`presence::Floor::CliConfirm`]; the desktop app
/// passes [`presence::Floor::AppConfirm`] after showing its own modal
/// confirmation (see the `Floor` docs for the obligation that carries).
/// Revocation stays friction-free on purpose - removing capability never
/// needs a human proof (the presence symmetry rule).
pub fn pair_client_with_presence(
    name: &str,
    anchor: Anchor,
    surface: crate::audit::Surface,
    floor: presence::Floor,
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
    let auth = match presence::require_presence(&reason, floor) {
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
                    .detail(&format!("{shown}; auth={}", auth.path().wire_name())),
            );
            Ok(auth.path())
        }
        Err(e) => {
            audit::record(
                AuditRecord::new(AuditKind::PairClient)
                    .surface(surface)
                    .name(name)
                    .outcome("error")
                    .detail(&format!(
                        "{shown}; auth={}; write refused: {e}",
                        auth.path().wire_name()
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
        presence::Floor::CliConfirm,
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
/// invocation's parent when asked (`--this-parent`). Public because it is the
/// one validation path for user-supplied anchors, shared by the CLI and the
/// desktop app's pairing form (ADR-0029): a malformed hash must be refused
/// identically on every surface.
pub fn resolve_anchor(spec: &crate::cli::AnchorSpec) -> Result<Anchor, String> {
    use crate::cli::AnchorSpec;
    match spec {
        AnchorSpec::Hash(h) => {
            // Normalizing user INPUT to lowercase is the legitimate-entry
            // convenience this path has always offered; only the persisted
            // form is held strictly canonical (see [`HashDigest`]).
            let digest = HashDigest::try_from(h.to_ascii_lowercase())
                .map_err(|_| "--hash must be non-empty lowercase hex".to_string())?;
            Ok(Anchor::Hash(digest))
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
                // Both platforms hex-encode measurements in lowercase, so a
                // failure here means the attested value is not a digest at
                // all: refuse it rather than normalize it.
                let digest = HashDigest::try_from(id.hash)
                    .map_err(|e| format!("attested parent hash is not a canonical digest: {e}"))?;
                Ok(Anchor::Hash(digest))
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

    fn id(hash: &str, team: Option<&str>) -> ClientIdentity {
        ClientIdentity {
            hash: hash.to_string(),
            team_id: team.map(str::to_string),
        }
    }

    /// A test digest from a literal that is valid lowercase hex.
    fn hd(hex: &str) -> HashDigest {
        HashDigest::try_from(hex).unwrap()
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
                anchor: Anchor::Hash(hd("c1a0de")),
                added_unix: 0,
            },
            ClientEntry {
                name: "codex".into(),
                anchor: Anchor::TeamId("TEAMX".into()),
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
            anchor: Anchor::Hash(hd(&"ab".repeat(32))),
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
            serde_json::to_value(Anchor::Hash(hd("0a"))).unwrap(),
            serde_json::json!({ "kind": "hash", "value": "0a" })
        );
        assert_eq!(
            serde_json::to_value(Anchor::TeamId("t".into())).unwrap(),
            serde_json::json!({ "kind": "team_id", "value": "t" })
        );
    }

    #[test]
    fn hash_digest_accepts_only_non_empty_lowercase_hex() {
        // The legitimate forms: lowercase hex of any (even) length -- a
        // 20-byte macOS cdhash or a 32-byte Linux SHA256 both pass.
        assert!(HashDigest::try_from("deadbeef").is_ok());
        assert!(HashDigest::try_from("ab".repeat(32)).is_ok());
        assert!(HashDigest::try_from("0123456789abcdef").is_ok());
        // Everything that could never match a measured lowercase-hex identity
        // is refused at the parse boundary instead of becoming a permanent,
        // silent Refuse.
        assert!(HashDigest::try_from("").is_err(), "empty");
        assert!(HashDigest::try_from("DEADBEEF").is_err(), "uppercase");
        assert!(HashDigest::try_from("aBc1").is_err(), "mixed case");
        assert!(HashDigest::try_from("zz").is_err(), "non-hex");
        assert!(HashDigest::try_from("dead beef").is_err(), "whitespace");
        assert!(HashDigest::try_from("dead-beef").is_err(), "punctuation");
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
            serde_json::json!({ "kind": "hash", "value": "deadbeef" })
        );
        let back: Anchor = serde_json::from_value(value).unwrap();
        assert_eq!(back, anchor);
    }

    #[test]
    fn a_malformed_on_disk_hash_anchor_is_rejected_fail_closed() {
        // Pre-HashDigest, {"value": "DEADBEEF"} parsed fine and simply never
        // matched the lowercase runtime measurement -- a permanent, silent
        // Refuse. Now the decode itself fails, so the whole file reads as a
        // corrupt allowlist and every caller fails closed LOUDLY, the same
        // policy as any other damaged clients.json. Never silently
        // normalized: an on-disk value in the wrong form is evidence of a
        // foreign writer, not input to fix up.
        for bad in ["DEADBEEF", "", "zz", "aBc1"] {
            let anchor = serde_json::json!({ "kind": "hash", "value": bad });
            assert!(
                serde_json::from_value::<Anchor>(anchor.clone()).is_err(),
                "anchor value {bad:?} must be refused"
            );
            // And through the full file shape: one bad entry poisons the
            // whole list, exactly like any other decode failure.
            let file = serde_json::json!({
                "version": 1,
                "clients": [
                    { "name": "good", "anchor": { "kind": "team_id", "value": "T" }, "added_unix": 0 },
                    { "name": "bad", "anchor": anchor, "added_unix": 0 },
                ],
            });
            assert!(serde_json::from_value::<Allowlist>(file).is_err());
        }
    }

    #[test]
    fn resolve_anchor_normalizes_cli_input_but_refuses_non_hex() {
        use crate::cli::AnchorSpec;
        // User INPUT keeps its historical convenience: uppercase hex is
        // normalized to the canonical lowercase form.
        assert_eq!(
            resolve_anchor(&AnchorSpec::Hash("DEADBEEF".into())).unwrap(),
            Anchor::Hash(hd("deadbeef"))
        );
        // Non-hex and empty input are refused with the same message as ever.
        for bad in ["", "not-hex", "dead beef"] {
            let err = resolve_anchor(&AnchorSpec::Hash(bad.into())).unwrap_err();
            assert_eq!(err, "--hash must be non-empty lowercase hex");
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
        // Order matters: the name check runs BEFORE require_presence, so a
        // bad request can never raise a hardware sheet (and, under this test
        // harness, never reaches the audit sink either - the early return is
        // the whole point). See presence's module docs for why tests must
        // not reach the hardware rung.
        let err = pair_client_with_presence(
            "bad name!",
            Anchor::Hash(hd("abc")),
            crate::audit::Surface::Cli,
            presence::Floor::CliConfirm,
        )
        .unwrap_err();
        assert!(matches!(err, PairClientError::InvalidName));
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

        // The same holds at every nesting level: inside an entry and inside
        // the anchor's adjacently-tagged {kind, value} shape.
        assert!(serde_json::from_value::<ClientEntry>(serde_json::json!({
            "name": "codex",
            "anchor": { "kind": "hash", "value": "ab" },
            "added_unix": 0,
            "surprise": true
        }))
        .is_err());
        assert!(serde_json::from_value::<Anchor>(serde_json::json!({
            "kind": "hash",
            "value": "ab",
            "surprise": true
        }))
        .is_err());
        // Positive control: the exact shape still parses.
        assert!(serde_json::from_value::<Anchor>(serde_json::json!({
            "kind": "team_id",
            "value": "3ZMH96L4V9"
        }))
        .is_ok());
    }
}
