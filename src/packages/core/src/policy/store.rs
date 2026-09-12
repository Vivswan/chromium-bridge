//! The on-disk policy store, the history ring, and the write seams
//! (ADR-0032 decisions 3 and 5), on the `Allowlist` template: fail-closed
//! loads, atomic 0600 writes under the runtime lock, a module-private write
//! path behind the public seams, and log-after-decide audit outside the
//! lock.

use std::io;

use serde::{Deserialize, Serialize};

use super::{
    field_relaxes, fold, restricts_or_equal, validate_disabled_tools, PolicyDoc, PolicyField,
    PolicyOverlay, PolicyValues, JS_SAFE_INT_MAX, POLICY_DOC_VERSION,
};
use crate::enclave::{base64_decode, base64_encode};
use crate::ipc;
use crate::presence::{PolicySignOutcome, PresencePath};

// ---- The on-disk store (ADR-0032 decision 5) --------------------------------

/// The current on-disk policy store schema version. Bumped only on a
/// breaking-shape change; unknown-field parsing is fail-closed
/// (`deny_unknown_fields`) so a newer file is rejected rather than
/// misinterpreted by an older binary.
pub const POLICY_STORE_VERSION: u32 = 1;

/// Upper bound on `policy.json` when reading it back. One baseline plus an
/// overlay is a few KB; anything larger is not ours and is rejected rather
/// than slurped into memory.
const POLICY_MAX_BYTES: usize = 256 * 1024;

/// The persisted policy state (ADR-0032 decision 5): the signed baseline as the EXACT bytes the signature covers
/// (base64, so the artifact survives the JSON hop byte-for-byte), its signature, and the restriction overlay.
/// Storage, not authority: the extension verifies the signature against its own pin and the host re-derives
/// everything from the bytes.
///
/// ```text
/// load          -> the FILE authority: size cap, strict shape, store version; no base64 work
/// baseline_doc  -> the BYTE authority: strict base64 and the strict PolicyDoc parse, the one place a damaged
///                  baseline surfaces and fails closed; the doctor row and the policy_current push both reach it
///                  through effective()
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyStore {
    /// Schema version; see [`POLICY_STORE_VERSION`].
    pub version: u32,
    /// The exact signed document bytes, base64 (strict alphabet, one
    /// accepted spelling per byte string - see [`base64_decode`]).
    pub baseline_b64: String,
    /// The enclave signature over the policy-domain message, base64. `None`
    /// is the app-floor unsigned baseline (ADR-0032 decision 3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_b64: Option<String>,
    /// The signing key id, host bookkeeping only: the extension verifies
    /// against its own pinned key and never trusts this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// The current unsigned restriction overlay, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlay: Option<PolicyOverlay>,
}

impl PolicyStore {
    /// Path of the policy store in the 0700 per-user runtime directory.
    pub fn path() -> std::path::PathBuf {
        ipc::runtime_dir().join("policy.json")
    }

    /// Read the store. `Ok(None)` when the file does not exist (no policy
    /// yet). A present-but-corrupt, oversized, or wrong-version file is an
    /// error, NOT a silent `None`: the callers' contract (ADR-0032 decision
    /// 5) is "unreadable store means refuse", never a default that could
    /// mask a tamper. The baseline bytes are deliberately not decoded here -
    /// see the type docs for the load/baseline_doc split.
    pub fn load() -> io::Result<Option<Self>> {
        let Some(bytes) = ipc::read_capped(&Self::path(), POLICY_MAX_BYTES)? else {
            return Ok(None);
        };
        let store: PolicyStore = serde_json::from_slice(&bytes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("policy store decode: {e}"),
            )
        })?;
        if store.version != POLICY_STORE_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "policy store version {} is not supported (this binary understands {})",
                    store.version, POLICY_STORE_VERSION
                ),
            ));
        }
        Ok(Some(store))
    }

    /// The signed baseline document, strict-parsed from the EXACT stored
    /// bytes: strict base64, strict `deny_unknown_fields` JSON, and
    /// [`PolicyDoc::validate`]. Any failure is an error, never a default -
    /// a baseline that does not parse is a damaged store, and enforcement
    /// fails closed on it.
    pub fn baseline_doc(&self) -> io::Result<PolicyDoc> {
        let bytes = base64_decode(&self.baseline_b64)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("baseline: {e}")))?;
        let doc: PolicyDoc = serde_json::from_slice(&bytes).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("baseline parse: {e}"))
        })?;
        doc.validate()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("baseline: {e}")))?;
        Ok(doc)
    }

    /// The baseline with the stored overlay folded over it, direction-checked: every legitimate write leaves the
    /// overlay restricting-or-holding the baseline, so a fold that relaxes it anywhere is a tampered or corrupted
    /// store and reads as an error, never as the relaxed values. Enforcement fails closed on it like an
    /// unparsable baseline; the extension applies the same direction check independently.
    pub fn effective(&self) -> io::Result<PolicyValues> {
        let baseline = self.baseline_doc()?.values();
        let effective = fold(&baseline, &self.overlay.clone().unwrap_or_default());
        if !restricts_or_equal(&effective, &baseline) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the stored overlay relaxes the signed baseline; refusing the store",
            ));
        }
        Ok(effective)
    }

    /// Write atomically, 0600. The [`ipc::RuntimeLockToken`] proves the
    /// caller holds the runtime lock, so a lock-free rewrite of the policy
    /// store does not compile (the `Allowlist::write` pattern).
    fn write(&self, _lock: &ipc::RuntimeLockToken) -> io::Result<()> {
        let bytes = serde_json::to_vec_pretty(self)?;
        // Never write what load cannot read back: a store over the read cap
        // would persist fine and then fail every subsequent load.
        if bytes.len() > POLICY_MAX_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "policy store would serialize to {} bytes, over the {POLICY_MAX_BYTES}-byte read cap",
                    bytes.len()
                ),
            ));
        }
        ipc::write_private_atomic(&Self::path(), &bytes)
    }
}

// ---- History: the rollback ring (data, never authority) ---------------------

/// The current policy-history schema version.
pub const POLICY_HISTORY_VERSION: u32 = 1;

/// Cap on `policy-history.json`: the eviction in [`history_bytes_capped`]
/// keeps the serialized ring at or under this, and reads refuse anything
/// larger.
const POLICY_HISTORY_MAX_BYTES: usize = 256 * 1024;

/// Superseded policy records, oldest first: the data a future rollback
/// surface offers back to the user. Data, never authority - no enforcement
/// path reads this file, and a rollback built from it is an ordinary
/// [`set_signed`] / [`restrict`] write with the full checks of those seams.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyHistory {
    /// Schema version; see [`POLICY_HISTORY_VERSION`].
    pub version: u32,
    pub entries: Vec<PolicyHistoryEntry>,
}

/// One superseded [`PolicyStore`] record, plus when it was superseded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyHistoryEntry {
    pub baseline_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlay: Option<PolicyOverlay>,
    /// Unix seconds when the record stopped being the current store.
    pub superseded_unix: u64,
}

impl PolicyHistory {
    /// Path of the history ring in the 0700 per-user runtime directory.
    pub fn path() -> std::path::PathBuf {
        ipc::runtime_dir().join("policy-history.json")
    }
}

/// Read the history ring. `Ok(None)` when absent; corrupt, oversized, or
/// wrong-version is an error, same posture as every other on-disk record.
/// Only the future rollback surface reads this - no enforcement path calls
/// it, and a damaged ring never affects [`PolicyStore::load`] or the seams
/// (their writer replaces it and moves on, see [`push_history_locked`]).
pub fn load_history() -> io::Result<Option<PolicyHistory>> {
    let Some(bytes) = ipc::read_capped(&PolicyHistory::path(), POLICY_HISTORY_MAX_BYTES)? else {
        return Ok(None);
    };
    let history: PolicyHistory = serde_json::from_slice(&bytes).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("policy history decode: {e}"),
        )
    })?;
    if history.version != POLICY_HISTORY_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "policy history version {} is not supported (this binary understands {})",
                history.version, POLICY_HISTORY_VERSION
            ),
        ));
    }
    Ok(Some(history))
}

/// Push the superseded store record onto the ring, inside the caller's
/// runtime-lock hold. Best-effort by contract: history failures NEVER fail
/// the policy write they trail - an unreadable ring is logged and replaced
/// (it is rollback data, never authority; refusing the policy write over it
/// would let a corrupt convenience file deny service to enforcement), and a
/// failed write is logged and dropped.
fn push_history_locked(_lock: &ipc::RuntimeLockToken, prev: &PolicyStore) {
    let mut history = match load_history() {
        Ok(Some(history)) => history,
        Ok(None) => PolicyHistory {
            version: POLICY_HISTORY_VERSION,
            entries: Vec::new(),
        },
        Err(e) => {
            log_warn!(
                "policy",
                "policy history is unreadable ({e}); starting a fresh ring \
                 (history is rollback data, never authority; the policy write \
                 itself is unaffected)"
            );
            PolicyHistory {
                version: POLICY_HISTORY_VERSION,
                entries: Vec::new(),
            }
        }
    };
    history.entries.push(PolicyHistoryEntry {
        baseline_b64: prev.baseline_b64.clone(),
        sig_b64: prev.sig_b64.clone(),
        key_id: prev.key_id.clone(),
        overlay: prev.overlay.clone(),
        superseded_unix: now_unix(),
    });
    match history_bytes_capped(&mut history, POLICY_HISTORY_MAX_BYTES) {
        Ok(bytes) => {
            if let Err(e) = ipc::write_private_atomic(&PolicyHistory::path(), &bytes) {
                log_warn!(
                    "policy",
                    "policy history write failed ({e}); the policy write itself is unaffected"
                );
            }
        }
        Err(e) => log_warn!(
            "policy",
            "policy history serialize failed ({e}); the policy write itself is unaffected"
        ),
    }
}

/// Serialize the ring, evicting oldest entries until the bytes fit `cap`.
/// Pure eviction (no I/O), parameterized on the cap so the loop is
/// unit-testable; production passes [`POLICY_HISTORY_MAX_BYTES`]. The empty
/// envelope is returned even in the pathological case where it alone
/// exceeds the cap (it cannot, at ~30 bytes against 256 KiB).
fn history_bytes_capped(history: &mut PolicyHistory, cap: usize) -> serde_json::Result<Vec<u8>> {
    loop {
        let bytes = serde_json::to_vec_pretty(history)?;
        if bytes.len() <= cap || history.entries.is_empty() {
            return Ok(bytes);
        }
        history.entries.remove(0);
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---- The write seams (ADR-0032 decisions 3 and 5) ----------------------------

/// What a grant-writing surface is entitled to when the hardware rung is
/// genuinely unavailable (ADR-0032 decision 5). A REFUSED hardware prompt
/// never consults this - the no-downgrade rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyGrantFloor {
    /// The desktop app's interactive floor: the one surface allowed to
    /// store an unsigned baseline on a keyless machine, after its own modal
    /// confirmation (the same obligation as [`crate::presence::Floor::AppConfirm`]).
    AppConfirm,
    /// The CLI (and any other surface without an interactive floor of its
    /// own): the grant path exists only as the signature, and refuses
    /// outright where no enclave key exists - a floor-gated CLI grant would
    /// quietly create a baseline-writing path on every platform the CLI
    /// ships to (decision 5's non-macOS hole).
    SignatureOnly,
}

/// Why a policy write did not happen. Every variant leaves the store
/// untouched.
#[derive(Debug)]
pub enum PolicyWriteError {
    /// The request was malformed (empty touched set, a touched set that
    /// does not name every field the write relaxes, invalid document);
    /// refused BEFORE the signing prompt, so a bad request can never raise
    /// a hardware sheet.
    Invalid(&'static str),
    /// The hardware rung ran and did not sign. Never downgraded to a floor,
    /// already audited.
    Refused(String),
    /// No enclave signing key exists and the surface's grant path is
    /// signature-only (ADR-0032 decision 5). Promptless, audited.
    NoSigningKey,
    /// `restrict` found no baseline: there is nothing to restrict.
    NoBaseline,
    /// The merged overlay would relax the current effective policy;
    /// relaxations are the signed lane's business.
    NotARestriction,
    /// The next revision would exceed [`JS_SAFE_INT_MAX`]; refused
    /// promptless.
    RevisionOverflow,
    /// The store's baseline revision or restriction overlay moved between
    /// the pre-prompt read and the locked write: a concurrent writer
    /// superseded the state the user approved against, so this write
    /// refuses rather than overwriting it.
    Conflict,
    /// The store could not be read or written.
    Io(io::Error),
}

impl std::fmt::Display for PolicyWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyWriteError::Invalid(m) => write!(f, "invalid policy write: {m}"),
            PolicyWriteError::Refused(e) => write!(f, "policy signing refused: {e}"),
            PolicyWriteError::NoSigningKey => write!(
                f,
                "no enclave signing key on this machine; this surface's grant \
                 path is signature-only and refuses (pair first, or use the app)"
            ),
            PolicyWriteError::NoBaseline => {
                write!(f, "no policy baseline exists; there is nothing to restrict")
            }
            PolicyWriteError::NotARestriction => write!(
                f,
                "the overlay would relax the current effective policy; \
                 relaxations require a signed baseline write"
            ),
            PolicyWriteError::RevisionOverflow => write!(
                f,
                "the policy revision counter would exceed the JS-safe integer bound (2^53 - 1)"
            ),
            PolicyWriteError::Conflict => write!(
                f,
                "the policy store changed while this write awaited its \
                 signature; refusing to overwrite the concurrent write"
            ),
            PolicyWriteError::Io(e) => write!(f, "policy store: {e}"),
        }
    }
}

/// Write a new signed policy baseline (ADR-0032 decision 3), the one grant path every editing surface shares;
/// `restrict` is the free lane. The Enclave signing over the document bytes IS the Touch ID approval
/// ([`crate::presence::sign_policy_as_presence`]), so this seam never takes a pre-made attestation and cannot
/// double-prompt; everything is validated BEFORE the prompt so a malformed request never raises a sheet (ADR-0031).
/// ```text
/// hardware refused       -> terminal, never downgraded to `floor`
/// hardware unavailable   -> `floor` decides; only the app's floor may store an unsigned baseline (decision 5)
/// retained overlay       -> survives minus its entries on the `touched` fields, which the tap covers
///                           (the touched set travels inside the signed bytes)
/// ```
/// Returns the presence rung that authorized the write. Every sign outcome is audited, log-after-decide, outside the lock.
pub fn set_signed(
    values: PolicyValues,
    touched: Vec<PolicyField>,
    surface: crate::audit::Surface,
    floor: PolicyGrantFloor,
) -> Result<PresencePath, PolicyWriteError> {
    if touched.is_empty() {
        return Err(PolicyWriteError::Invalid(
            "the touched set is empty (a write must name the fields it edits)",
        ));
    }
    // The pre-prompt observation the user's tap covers; the locked write refuses (Conflict) if a concurrent
    // writer moved any of it, since landing THESE bytes over another store would silently discard that write.
    //   baseline revision  -> a concurrent signed write
    //   overlay            -> a restrict landing mid-prompt
    //   host-key epoch     -> a disposal completing mid-prompt; it clears the baseline, so a first write sees None
    //                         before AND after and the store guard alone would land a baseline signed by a dead key
    // Read before the prompt and fail closed on an unreadable record: no sheet for a write that cannot land.
    let host_key_epoch = crate::revocation::Revocation::current()
        .map_err(PolicyWriteError::Io)?
        .host_key_epoch;
    let (store_observation, baseline_anchor, effective_anchor) =
        match PolicyStore::load().map_err(PolicyWriteError::Io)? {
            Some(store) => {
                let doc = store.baseline_doc().map_err(PolicyWriteError::Io)?;
                // effective() direction-checks the fold, so a tampered store
                // (an overlay relaxing its baseline) refuses the write here
                // rather than anchoring the relaxation checks on values
                // nobody vouched for.
                let anchor = store.effective().map_err(PolicyWriteError::Io)?;
                (
                    Some(StoreObservation {
                        revision: doc.revision,
                        overlay: store.overlay,
                    }),
                    doc.values(),
                    anchor,
                )
            }
            // With no store, the anchor for "what does this write relax" is
            // the deny baseline: it is what the extension enforces in the
            // no-stored-policy state (ADR-0032 decision 4), so a first
            // write's grants are relaxations against it and must be named in
            // `touched`.
            None => (None, PolicyValues::default(), PolicyValues::default()),
        };
    let observed = PrePromptObservation {
        store: store_observation,
        host_key_epoch,
    };
    let revision = next_revision(observed.store.as_ref().map(|o| o.revision))?;
    // Decision 3: the signed document carries BASELINE values, not effective
    // ones, on fields it does not touch. An untouched field departing from
    // the current baseline (in either direction - a restrictive drift is
    // still an unnamed edit) would break the invariant every retained
    // overlay entry depends on: an entry written at-or-under the old
    // baseline value stays at-or-under it only if untouched baseline values
    // carry. Promptless, like every validity refusal here.
    if PolicyField::ALL.iter().any(|f| {
        !touched.contains(f)
            && (field_relaxes(*f, &values, &baseline_anchor)
                || field_relaxes(*f, &baseline_anchor, &values))
    }) {
        return Err(PolicyWriteError::Invalid(
            "an untouched field departs from the current baseline (the signed document \
             carries baseline values on fields it does not touch)",
        ));
    }
    // Every field this write relaxes must be named in `touched`, or the signed set would under-state what the tap
    // granted. The anchor is the post-write EFFECTIVE policy: an untouched field whose overlay entry survives is not
    // relaxed by baseline bytes the overlay still covers, and the extension's ratchet compares the same fold (it
    // independently refuses a push relaxing a field outside the signed touched set).
    let would_be_effective = fold(
        &values,
        &retained_overlay(
            observed
                .store
                .as_ref()
                .and_then(|o| o.overlay.clone())
                .unwrap_or_default(),
            &touched,
        ),
    );
    if PolicyField::ALL
        .iter()
        .any(|f| field_relaxes(*f, &would_be_effective, &effective_anchor) && !touched.contains(f))
    {
        return Err(PolicyWriteError::Invalid(
            "the touched set does not name every field this write relaxes",
        ));
    }
    let doc = PolicyDoc::from_values(&values, revision, touched.clone());
    doc.validate().map_err(PolicyWriteError::Invalid)?;
    // Serialized ONCE: these exact bytes are what the prompt covers, what
    // the signature signs, and what the store persists.
    let doc_bytes = serde_json::to_vec(&doc)
        .map_err(io::Error::from)
        .map_err(PolicyWriteError::Io)?;

    match crate::presence::sign_policy_as_presence(&doc_bytes) {
        PolicySignOutcome::Signed {
            sig,
            key_id,
            pubkey_b64: _,
        } => commit_signed_baseline(
            observed,
            &doc_bytes,
            Some(base64_encode(&sig)),
            Some(key_id),
            &touched,
            surface,
            PresencePath::TouchId,
        ),
        PolicySignOutcome::Refused(e) => {
            // Log-after-decide: the refusal has already happened; the
            // no-downgrade rule makes it terminal, never a floor.
            crate::audit::record(
                crate::audit::AuditRecord::new(crate::audit::AuditKind::PolicyWrite)
                    .surface(surface)
                    .outcome("refused")
                    .detail(&format!(
                        "presence: {e}; touched={}",
                        wire_name_list(&touched)
                    )),
            );
            Err(PolicyWriteError::Refused(e))
        }
        PolicySignOutcome::Unavailable => match floor {
            PolicyGrantFloor::AppConfirm => commit_signed_baseline(
                observed,
                &doc_bytes,
                None,
                None,
                &touched,
                surface,
                PresencePath::AppConfirm,
            ),
            PolicyGrantFloor::SignatureOnly => {
                crate::audit::record(
                    crate::audit::AuditRecord::new(crate::audit::AuditKind::PolicyWrite)
                        .surface(surface)
                        .outcome("refused")
                        .detail(&format!(
                            "no signing key on a signature-only surface; touched={}",
                            wire_name_list(&touched)
                        )),
                );
                Err(PolicyWriteError::NoSigningKey)
            }
        },
    }
}

/// The store state [`set_signed`] observed before its prompt: the baseline
/// revision AND the restriction overlay. The locked write re-checks both,
/// so a concurrent signed write (revision moved) or a concurrent restrict
/// (overlay moved) surfaces as [`PolicyWriteError::Conflict`] instead of
/// being silently half-clobbered.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StoreObservation {
    revision: u64,
    overlay: Option<PolicyOverlay>,
}

/// Everything [`set_signed`] observed before its prompt: the store state
/// (`None` when no store exists) plus the revocation record's host-key
/// epoch. The epoch travels separately from the store observation because
/// the guard it feeds must fire even when both sides of the store
/// comparison are `None` - a disposal completing during the prompt clears
/// the store, so on a first write only the epoch (bumped inside the
/// disposal's critical section) betrays that the signing key died
/// mid-prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PrePromptObservation {
    store: Option<StoreObservation>,
    host_key_epoch: u64,
}

/// The revision a grant write mints: one past the observed baseline's (1
/// for the first write), refused at the JS-safe bound rather than wrapped
/// or saturated - a wrapped revision would re-arm the extension's ratchet
/// with a stale-looking number, and a saturated one would let two distinct
/// baselines share it.
fn next_revision(observed: Option<u64>) -> Result<u64, PolicyWriteError> {
    observed
        .unwrap_or(0)
        .checked_add(1)
        .filter(|r| *r <= JS_SAFE_INT_MAX)
        .ok_or(PolicyWriteError::RevisionOverflow)
}

/// The locked half of a grant write plus its audit record: take the runtime
/// lock, land the baseline through [`write_baseline_locked`], then record
/// the outcome outside the lock (audit I/O never runs inside a critical
/// section). `rung` is the presence rung that authorized the write - the
/// hardware tap, or the app's interactive floor.
fn commit_signed_baseline(
    observed: PrePromptObservation,
    doc_bytes: &[u8],
    sig_b64: Option<String>,
    key_id: Option<String>,
    touched: &[PolicyField],
    surface: crate::audit::Surface,
    rung: PresencePath,
) -> Result<PresencePath, PolicyWriteError> {
    let result = match ipc::with_runtime_lock(|lock| {
        Ok(write_baseline_locked(
            lock, observed, doc_bytes, sig_b64, key_id, touched,
        ))
    }) {
        Ok(inner) => inner,
        Err(e) => Err(PolicyWriteError::Io(e)),
    };
    // Log-after-decide (ADR-0030): the write is done (or refused) and the
    // lock is released. Fifteen wire names fit well inside audit.rs's
    // per-field truncation bound.
    let record = crate::audit::AuditRecord::new(crate::audit::AuditKind::PolicyWrite)
        .surface(surface)
        .detail(&format!(
            "auth={}; touched={}",
            rung.wire_name(),
            wire_name_list(touched)
        ));
    match &result {
        Ok(()) => crate::audit::record(record.outcome("ok")),
        Err(e) => crate::audit::record(record.outcome("error").detail(&format!(
            "auth={}; touched={}; write refused: {e}",
            rung.wire_name(),
            wire_name_list(touched)
        ))),
    }
    result.map(|()| rung)
}

/// The critical section of a grant write. The host-key epoch is re-checked with the revision and overlay because
/// that is what makes "a baseline never survives its key" hold across the prompt gap (see [`PrePromptObservation`]).
/// ```text
/// re-check guard -> write store -> bump policy epoch -> push the superseded record to history
/// ```
/// History trails the store write by contract: a history write that fails (logged, never propagated) or a crash
/// before the history step leaves the new baseline visible with no entry for the record it replaced. A failed
/// epoch bump is logged and does not skip the history step.
fn write_baseline_locked(
    lock: &ipc::RuntimeLockToken,
    observed: PrePromptObservation,
    doc_bytes: &[u8],
    sig_b64: Option<String>,
    key_id: Option<String>,
    touched: &[PolicyField],
) -> Result<(), PolicyWriteError> {
    let host_key_epoch = crate::revocation::Revocation::current()
        .map_err(PolicyWriteError::Io)?
        .host_key_epoch;
    if host_key_epoch != observed.host_key_epoch {
        return Err(PolicyWriteError::Conflict);
    }
    let prev = PolicyStore::load().map_err(PolicyWriteError::Io)?;
    let current = match &prev {
        Some(store) => Some(StoreObservation {
            revision: store.baseline_doc().map_err(PolicyWriteError::Io)?.revision,
            overlay: store.overlay.clone(),
        }),
        None => None,
    };
    if current != observed.store {
        return Err(PolicyWriteError::Conflict);
    }
    let overlay = retained_overlay(
        prev.as_ref()
            .and_then(|s| s.overlay.clone())
            .unwrap_or_default(),
        touched,
    );
    let next = PolicyStore {
        version: POLICY_STORE_VERSION,
        baseline_b64: base64_encode(doc_bytes),
        sig_b64,
        key_id,
        overlay: normalize_overlay(overlay),
    };
    if prev.is_none() {
        // First baseline: durably CLOSE the import window BEFORE committing it, in the same critical section, and
        // refuse the whole write if that fails (Io is retryable: the user re-taps once I/O is fixed); closing after
        // the write would let revision 1 land with the window still open post-disposal, the forged-bag hole the
        // tombstone exists to close. The Consuming record RETAINS the bag, so a crash between here and the write
        // below leaves the window closed and the bag re-offered; the finalize after the write disposes of it.
        crate::pending_import::begin_consume_locked(lock).map_err(PolicyWriteError::Io)?;
    }
    next.write(lock).map_err(PolicyWriteError::Io)?;
    if prev.is_none() {
        // Finalize the mid-consume record to the bagless tombstone only over a DURABLE baseline: the store's atomic
        // write does not fsync while the tombstone write does, so without fsync-first a power loss after the finalize
        // could keep the tombstone and take back the baseline (Consumed, no baseline, no bag). attest_baseline_durable
        // fsyncs and mints the proof finalize_consume_locked demands, so the wrong order does not compile.
        //   attest_baseline_durable fails -> the Consuming record stands and the reconcile heals it
        //   finalize fails                -> the same, or the tombstone already landed with only its fsync lost
        //   either                        -> the window stays closed; the landed baseline is NOT repainted as a failed write
        match crate::pending_import::attest_baseline_durable(lock) {
            Ok(proof) => {
                if let Err(e) = crate::pending_import::finalize_consume_locked(lock, proof) {
                    log_warn!(
                        "policy",
                        "first baseline written but the pending-import finalize failed ({e}); \
                         the import window stays closed with the bag retained in the \
                         mid-consume record until a reconcile heals it"
                    );
                }
            }
            Err(e) => log_warn!(
                "policy",
                "first baseline written but could not be fsynced ({e}); deferring the \
                 pending-import finalize so the retained bag outlives any power loss \
                 that takes the baseline back"
            ),
        }
    }
    bump_policy_epoch_locked(lock);
    if let Some(prev) = &prev {
        push_history_locked(lock, prev);
    }
    Ok(())
}

/// Apply an unsigned restriction overlay (ADR-0032 decision 3's free lane).
/// Takes no attestation and can never prompt, by construction: restrictions
/// only remove capability, and failing closed is the direction every
/// forgery is allowed to point. The given overlay merges over the stored
/// one entry-wise (a present entry wins, absent entries keep their stored
/// value), and the merged result must restrict-or-hold the CURRENT
/// EFFECTIVE policy field by field - an "undo" of an earlier restriction
/// relaxes the effective policy and is refused here; it belongs to the
/// signed lane.
pub fn restrict(
    overlay: PolicyOverlay,
    surface: crate::audit::Surface,
) -> Result<(), PolicyWriteError> {
    let restricted = wire_name_list(&overlay_present_fields(&overlay));
    let result = match ipc::with_runtime_lock(|lock| Ok(restrict_locked(lock, overlay))) {
        Ok(inner) => inner,
        Err(e) => Err(PolicyWriteError::Io(e)),
    };
    // Log-after-decide, outside the lock. auth=none is deliberate:
    // restrictions are free, and the trail must never suggest a presence
    // rung vouched for one. Refusals and write failures are audited too;
    // only the promptless preconditions (NoBaseline, Invalid) stay
    // unaudited, the pair_client InvalidName precedent.
    let record =
        crate::audit::AuditRecord::new(crate::audit::AuditKind::PolicyWrite).surface(surface);
    match &result {
        Ok(()) => crate::audit::record(
            record
                .outcome("ok")
                .detail(&format!("auth=none; restricted={restricted}")),
        ),
        Err(PolicyWriteError::NotARestriction) => {
            crate::audit::record(record.outcome("refused").detail(&format!(
                "auth=none; restricted={restricted}; refused: relaxes the effective policy"
            )))
        }
        Err(PolicyWriteError::Io(e)) => crate::audit::record(
            record
                .outcome("error")
                .detail(&format!("auth=none; restricted={restricted}; store: {e}")),
        ),
        Err(_) => {}
    }
    result
}

/// The critical section of [`restrict`]: load, merge, direction-check
/// against the current effective policy, push history, write.
fn restrict_locked(
    lock: &ipc::RuntimeLockToken,
    overlay: PolicyOverlay,
) -> Result<(), PolicyWriteError> {
    let Some(prev) = PolicyStore::load().map_err(PolicyWriteError::Io)? else {
        return Err(PolicyWriteError::NoBaseline);
    };
    let baseline = prev.baseline_doc().map_err(PolicyWriteError::Io)?.values();
    let stored = prev.overlay.clone().unwrap_or_default();
    // The validating read, not a raw fold: restricting on top of a tampered
    // store (an overlay already relaxing its baseline) would quietly write a
    // fresh record over evidence; refusing surfaces the tamper here, the
    // same posture as set_signed's anchor read.
    let effective_now = prev.effective().map_err(PolicyWriteError::Io)?;
    let merged = merge_overlay(&stored, overlay);
    if let Some(tools) = &merged.disabled_tools {
        validate_disabled_tools(tools).map_err(PolicyWriteError::Invalid)?;
    }
    if !restricts_or_equal(&fold(&baseline, &merged), &effective_now) {
        return Err(PolicyWriteError::NotARestriction);
    }
    let next = PolicyStore {
        overlay: normalize_overlay(merged),
        ..prev.clone()
    };
    next.write(lock).map_err(PolicyWriteError::Io)?;
    bump_policy_epoch_locked(lock);
    push_history_locked(lock, &prev);
    Ok(())
}

/// Bump the revocation record's policy epoch inside the caller's runtime-lock
/// hold (ADR-0032 decision 4), so the native host's watch pushes
/// `policy_current` to a connected extension on the next tick. Best-effort by
/// the same contract as the host-key bump: the epoch is a change notice, not
/// authority (the signed baseline just written is the authority), so a failed
/// bump loses only the proactive push - a connected extension still picks the
/// change up on its next connect - and is logged, never fatal to the write it
/// trails.
fn bump_policy_epoch_locked(lock: &ipc::RuntimeLockToken) {
    if let Err(e) = crate::revocation::bump_locked(lock, crate::revocation::Scope::Policy) {
        log_warn!(
            "policy",
            "policy written but the policy epoch bump failed ({e}); a connected \
             extension notices the change only at its next connect"
        );
    }
}

/// Clear the signed baseline (ADR-0032 decision 3's key disposal): a baseline signed by a deleted enrollment key must
/// not outlive the key. The superseded record goes onto the history ring first, where the document survives as an
/// unsigned draft the app re-signs after re-pairing (the overlay travels inside that record because the store type
/// cannot represent an overlay with no baseline).
///
/// ```text
/// caller's runtime lock -> held by the enrollment-disposal seam across the key deletion, this clear, and the host-key
///                          epoch bump, so no concurrent WRITER lands a fresh baseline in between
/// readers               -> take no lock; can see the baseline for the instant after the key is gone
/// ```
pub fn clear_baseline_locked(lock: &ipc::RuntimeLockToken) -> io::Result<()> {
    let Some(prev) = PolicyStore::load()? else {
        return Ok(());
    };
    push_history_locked(lock, &prev);
    match std::fs::remove_file(PolicyStore::path()) {
        Ok(()) => {
            // The clear is a policy change like any write: bump the policy
            // epoch (best-effort, same contract as the write paths) so a
            // connected host pushes the cleared state - the extension drops
            // to its deny baseline now, not at its next connect.
            bump_policy_epoch_locked(lock);
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

impl PolicyDoc {
    /// A document carrying `values` under the given scoping fields. Private
    /// to the seams: surfaces pass [`PolicyValues`] and a touched set;
    /// revision arithmetic belongs to [`set_signed`] alone.
    fn from_values(values: &PolicyValues, revision: u64, touched: Vec<PolicyField>) -> PolicyDoc {
        PolicyDoc {
            v: POLICY_DOC_VERSION,
            revision,
            touched,
            cdp_mode: values.cdp_mode,
            file_upload_enabled: values.file_upload_enabled,
            handle_dialog_enabled: values.handle_dialog_enabled,
            page_eval_enabled: values.page_eval_enabled,
            confirm_high_risk_click: values.confirm_high_risk_click,
            confirm_page_eval: values.confirm_page_eval,
            touch_id_confirm: values.touch_id_confirm,
            confirm_tab_close: values.confirm_tab_close,
            warn_precise_snapshot: values.warn_precise_snapshot,
            eval_mask: values.eval_mask,
            host_reverify_ms: values.host_reverify_ms,
            confirm_grace_ms: values.confirm_grace_ms,
            click_toast_timeout_ms: values.click_toast_timeout_ms,
            eval_toast_timeout_ms: values.eval_toast_timeout_ms,
            disabled_tools: values.disabled_tools.clone(),
        }
    }
}

/// The overlay a grant write leaves behind: the stored entries minus those
/// on the `touched` fields (the tapped edit supersedes them, ADR-0032
/// decision 3). One function on purpose - the pre-prompt relaxation-coverage
/// check and the locked write must compute the same retention or the check
/// guards a different store than the one written.
fn retained_overlay(mut overlay: PolicyOverlay, touched: &[PolicyField]) -> PolicyOverlay {
    for field in touched {
        clear_overlay_entry(&mut overlay, *field);
    }
    overlay
}

/// Clear the overlay entry for one field. Exhaustive with no wildcard, like
/// the direction table: a new field fails to compile here until it says how
/// its overlay entry clears, so touched-field supersession can never
/// silently skip one.
fn clear_overlay_entry(overlay: &mut PolicyOverlay, field: PolicyField) {
    match field {
        PolicyField::CdpMode => overlay.cdp_mode = None,
        PolicyField::FileUploadEnabled => overlay.file_upload_enabled = None,
        PolicyField::HandleDialogEnabled => overlay.handle_dialog_enabled = None,
        PolicyField::PageEvalEnabled => overlay.page_eval_enabled = None,
        PolicyField::ConfirmHighRiskClick => overlay.confirm_high_risk_click = None,
        PolicyField::ConfirmPageEval => overlay.confirm_page_eval = None,
        PolicyField::TouchIdConfirm => overlay.touch_id_confirm = None,
        PolicyField::ConfirmTabClose => overlay.confirm_tab_close = None,
        PolicyField::WarnPreciseSnapshot => overlay.warn_precise_snapshot = None,
        PolicyField::EvalMask => overlay.eval_mask = None,
        PolicyField::HostReverifyMs => overlay.host_reverify_ms = None,
        PolicyField::ConfirmGraceMs => overlay.confirm_grace_ms = None,
        PolicyField::ClickToastTimeoutMs => overlay.click_toast_timeout_ms = None,
        PolicyField::EvalToastTimeoutMs => overlay.eval_toast_timeout_ms = None,
        PolicyField::DisabledTools => overlay.disabled_tools = None,
    }
}

/// Whether the overlay carries an entry for `field`. Exhaustive for the
/// same reason as [`clear_overlay_entry`].
fn overlay_entry_present(overlay: &PolicyOverlay, field: PolicyField) -> bool {
    match field {
        PolicyField::CdpMode => overlay.cdp_mode.is_some(),
        PolicyField::FileUploadEnabled => overlay.file_upload_enabled.is_some(),
        PolicyField::HandleDialogEnabled => overlay.handle_dialog_enabled.is_some(),
        PolicyField::PageEvalEnabled => overlay.page_eval_enabled.is_some(),
        PolicyField::ConfirmHighRiskClick => overlay.confirm_high_risk_click.is_some(),
        PolicyField::ConfirmPageEval => overlay.confirm_page_eval.is_some(),
        PolicyField::TouchIdConfirm => overlay.touch_id_confirm.is_some(),
        PolicyField::ConfirmTabClose => overlay.confirm_tab_close.is_some(),
        PolicyField::WarnPreciseSnapshot => overlay.warn_precise_snapshot.is_some(),
        PolicyField::EvalMask => overlay.eval_mask.is_some(),
        PolicyField::HostReverifyMs => overlay.host_reverify_ms.is_some(),
        PolicyField::ConfirmGraceMs => overlay.confirm_grace_ms.is_some(),
        PolicyField::ClickToastTimeoutMs => overlay.click_toast_timeout_ms.is_some(),
        PolicyField::EvalToastTimeoutMs => overlay.eval_toast_timeout_ms.is_some(),
        PolicyField::DisabledTools => overlay.disabled_tools.is_some(),
    }
}

/// The fields the overlay carries entries for, in catalogue order.
fn overlay_present_fields(overlay: &PolicyOverlay) -> Vec<PolicyField> {
    PolicyField::ALL
        .iter()
        .copied()
        .filter(|f| overlay_entry_present(overlay, *f))
        .collect()
}

/// Merge `arg` over `stored` entry-wise: a present `arg` entry wins, an
/// absent one keeps the stored entry. Pure shape work - whether the result
/// restricts is the caller's direction check, never assumed here.
fn merge_overlay(stored: &PolicyOverlay, arg: PolicyOverlay) -> PolicyOverlay {
    PolicyOverlay {
        cdp_mode: arg.cdp_mode.or(stored.cdp_mode),
        file_upload_enabled: arg.file_upload_enabled.or(stored.file_upload_enabled),
        handle_dialog_enabled: arg.handle_dialog_enabled.or(stored.handle_dialog_enabled),
        page_eval_enabled: arg.page_eval_enabled.or(stored.page_eval_enabled),
        confirm_high_risk_click: arg
            .confirm_high_risk_click
            .or(stored.confirm_high_risk_click),
        confirm_page_eval: arg.confirm_page_eval.or(stored.confirm_page_eval),
        touch_id_confirm: arg.touch_id_confirm.or(stored.touch_id_confirm),
        confirm_tab_close: arg.confirm_tab_close.or(stored.confirm_tab_close),
        warn_precise_snapshot: arg.warn_precise_snapshot.or(stored.warn_precise_snapshot),
        eval_mask: arg.eval_mask.or(stored.eval_mask),
        host_reverify_ms: arg.host_reverify_ms.or(stored.host_reverify_ms),
        confirm_grace_ms: arg.confirm_grace_ms.or(stored.confirm_grace_ms),
        click_toast_timeout_ms: arg.click_toast_timeout_ms.or(stored.click_toast_timeout_ms),
        eval_toast_timeout_ms: arg.eval_toast_timeout_ms.or(stored.eval_toast_timeout_ms),
        disabled_tools: arg.disabled_tools.or_else(|| stored.disabled_tools.clone()),
    }
}

/// `Some(overlay)` when it carries any entry, `None` for the empty overlay,
/// so the store never persists a meaningless `{}`.
fn normalize_overlay(overlay: PolicyOverlay) -> Option<PolicyOverlay> {
    (overlay != PolicyOverlay::default()).then_some(overlay)
}

/// Comma-joined wire names, for audit details.
fn wire_name_list(fields: &[PolicyField]) -> String {
    fields
        .iter()
        .map(|f| f.wire_name())
        .collect::<Vec<_>>()
        .join(",")
}

/// Store, history, and seam tests. Every disk-touching test points `runtime_dir()` at its own scratch directory
/// through `RuntimeDirGuard` (test_support.rs); signing outcomes come from `presence::policy_test_hook`, never a
/// real prompt (the real backend is compiled out under cfg(test)).
#[cfg(test)]
mod store_tests;

/// Property coverage of the revision seam, the policy `mod proptests`
/// pattern. [`next_revision`] IS the arithmetic `set_signed` runs (extracted,
/// not reimplemented), proptested directly because staging a seeded store per
/// case would cost a runtime directory each; the same boundaries through the
/// full seam are pinned by `revision_overflow_refuses_before_any_prompt` and
/// `the_last_js_safe_revision_still_writes` in `store_tests`.
#[cfg(test)]
mod proptests;
