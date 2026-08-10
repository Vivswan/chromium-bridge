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

/// The persisted policy state (ADR-0032 decision 5): the signed baseline as
/// the EXACT bytes the signature covers (base64, so the artifact survives
/// the JSON hop byte-for-byte), its signature, and the current restriction
/// overlay. The file is storage, not authority: nothing here is trusted for
/// enforcement - the extension verifies the signature against its own pin
/// and the host re-derives everything from the bytes.
///
/// Validation splits deliberately across two seams. [`load`](Self::load) is
/// the FILE authority: size cap, strict JSON shape, store version - cheap,
/// no base64 work, so callers that only need the envelope (the watch tick,
/// `doctor`) never pay for or depend on the baseline decode.
/// [`baseline_doc`](Self::baseline_doc) is the BYTE authority: strict base64
/// decode plus the strict [`PolicyDoc`] parse of the exact signed bytes, so
/// there is exactly one place a damaged baseline surfaces and it fails
/// closed there.
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

    /// The effective policy this store describes: the baseline with the
    /// stored restriction overlay folded over it (ADR-0032 decision 3's
    /// comparison anchor).
    ///
    /// The fold is direction-checked: every legitimate write leaves the
    /// overlay restricting-or-holding the baseline ([`restrict`] only adds
    /// entries at or under the effective policy, and [`set_signed`] carries
    /// baseline values on untouched fields and drops the touched entries),
    /// so a fold that relaxes the baseline anywhere is a tampered or
    /// corrupted store and reads as an error - never as the relaxed values.
    /// Enforcement (the dispatch gate, the `policy_current` push, status
    /// surfaces) fails closed on it, same as an unparsable baseline; the
    /// extension applies the same direction check independently.
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

/// Write a new signed policy baseline (ADR-0032 decision 3): the one grant
/// path every editing surface shares. Validates the document BEFORE any
/// prompt can appear (a malformed request never raises a sheet, the
/// ADR-0031 tap-phishing rule), obtains presence through
/// [`crate::presence::sign_policy_as_presence`] - the Enclave signing over
/// the document bytes IS the Touch ID approval, so this seam never takes a
/// pre-made attestation and can never double-prompt - and persists the
/// EXACT signed bytes atomically under the runtime lock. `restrict` is the
/// other lane; restrictions are free.
///
/// A refused hardware prompt is terminal (no-downgrade); only genuinely
/// unavailable hardware consults `floor`, and only the app's floor may
/// store the unsigned baseline (decision 5). The retained restriction
/// overlay survives the write minus its entries on the `touched` fields:
/// the tap covers exactly those fields (the touched set travels inside the
/// signed bytes), so entries on untouched fields stay overlay, never
/// silently folded into the baseline.
///
/// Returns the presence rung that authorized the write, for the surface to
/// show. Every sign outcome is audited ([`crate::audit::AuditKind::PolicyWrite`]),
/// log-after-decide, outside the lock.
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
    // The pre-prompt observation: the store state the user's tap will cover.
    // The locked write below re-checks that the store still matches it -
    // baseline revision AND overlay - and refuses (Conflict) if a concurrent
    // writer moved either: the prompt showed THESE bytes against THAT store,
    // so landing them over anything else (a restrict landing mid-prompt
    // included) would silently discard the concurrent write. The ADR is
    // silent on the interleave; failing closed is the only honest option.
    //
    // The host-key epoch is observed alongside (and re-checked in the same
    // critical section) because the store observation alone cannot see a
    // disposal that ran to completion during the prompt: dispose clears the
    // baseline, so a first write observes None before AND after and the
    // store guard passes - landing a baseline signed by the just-deleted
    // key. A baseline must never outlive (or postdate) its key. Read before
    // the prompt, fail-closed on an unreadable record (validate-before-
    // prompt: no sheet is raised for a write that cannot land).
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
    // Every field this write relaxes must be named in `touched`, or the
    // signed set would under-state what the tap granted. The comparison
    // anchors on the post-write EFFECTIVE policy - the new values under the
    // retained overlay - because an untouched field whose overlay entry
    // survives the write (decision 3's retention rule) is not relaxed by
    // baseline bytes the overlay still covers; the extension's ratchet
    // compares the same fold. Defense in depth for surface bugs: the
    // extension independently refuses a push relaxing a field outside its
    // signed touched set, so a write that slipped through here would brick
    // the push wholesale. Promptless, like every validity refusal here.
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

/// The critical section of a grant write: re-check the observation guard
/// (baseline revision, overlay, AND the host-key epoch), retain the previous
/// overlay minus the touched entries, push the superseded record to history,
/// and write the store.
///
/// The host-key epoch re-check is what makes "a baseline never survives its
/// key" hold across the prompt gap: a disposal completing during the tap
/// clears the store, so on a first write the store guard sees None on both
/// sides and passes - only the epoch (bumped inside the disposal's own
/// critical section) betrays that the signing key died mid-prompt. An
/// unreadable revocation record refuses too (fail closed).
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
    next.write(lock).map_err(PolicyWriteError::Io)?;
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

/// Clear the signed baseline (ADR-0032 decision 3's key disposal): a baseline
/// signed by a now-deleted enrollment key is an artifact of a dead key, so it
/// must not outlive the key. The superseded record - baseline bytes,
/// signature, key id, AND the overlay - is first pushed onto the history ring,
/// where the document content survives as an unsigned draft the app re-signs
/// after re-pairing; then the live `policy.json` is removed. History is kept
/// (this only appends to it); the overlay is preserved inside that history
/// record rather than as a live orphan, because the store type binds an
/// overlay to a baseline and an overlay with no baseline is not representable.
///
/// A no-op when there is no store. Runs under the caller's runtime lock (the
/// [`ipc::RuntimeLockToken`] witness), which the shared enrollment-disposal
/// seam holds across the key deletion, the baseline clear, and the host-key
/// epoch bump, so no concurrent reader can observe the baseline outliving its
/// key.
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

/// Store, history, and seam tests. Every test that touches disk points
/// `runtime_dir()` at its own scratch directory through [`RuntimeDirGuard`]
/// (the ScratchDir idea from ipc/lockfile.rs, lifted to the env var because
/// the store and the seams resolve their paths internally); signing
/// outcomes come from `presence::policy_test_hook`, never a real prompt
/// (the real backend is compiled out under cfg(test)).
#[cfg(test)]
mod store_tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use super::*;
    use crate::audit::Surface;
    use crate::presence::policy_test_hook::{self, Mock};

    #[cfg(unix)]
    const RUNTIME_ENV: &str = "XDG_RUNTIME_DIR";
    #[cfg(windows)]
    const RUNTIME_ENV: &str = "LOCALAPPDATA";

    /// Serializes the env-mutating tests within one process. cargo-nextest
    /// runs each test in its own process, making this a no-op there; under
    /// plain `cargo test` it keeps parallel threads from racing the env var.
    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    /// Points `runtime_dir()` at a fresh scratch directory for one test,
    /// restoring the previous environment and removing the directory on
    /// drop, so no test can read or write the user's real runtime state.
    struct RuntimeDirGuard {
        _serial: MutexGuard<'static, ()>,
        dir: PathBuf,
        prev: Option<std::ffi::OsString>,
    }

    impl RuntimeDirGuard {
        fn new(test: &str) -> Self {
            let serial = env_lock().lock().unwrap_or_else(|e| e.into_inner());
            let dir = std::env::temp_dir().join(format!(
                "chromium-bridge-policy-test-{}-{test}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            let prev = std::env::var_os(RUNTIME_ENV);
            std::env::set_var(RUNTIME_ENV, &dir);
            RuntimeDirGuard {
                _serial: serial,
                dir,
                prev,
            }
        }
    }

    impl Drop for RuntimeDirGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(RUNTIME_ENV, v),
                None => std::env::remove_var(RUNTIME_ENV),
            }
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    /// A signed-looking store seeded directly on disk: a baseline document
    /// with `revision` over `values`, plus `overlay`. Returns the store as
    /// written.
    fn seed_store(
        revision: u64,
        values: &PolicyValues,
        overlay: Option<PolicyOverlay>,
    ) -> PolicyStore {
        let doc = PolicyDoc::from_values(values, revision, vec![]);
        let bytes = serde_json::to_vec(&doc).unwrap();
        let store = PolicyStore {
            version: POLICY_STORE_VERSION,
            baseline_b64: base64_encode(&bytes),
            sig_b64: Some(base64_encode(b"seed-sig")),
            key_id: Some("seed-kid".into()),
            overlay,
        };
        ipc::with_runtime_lock(|lock| store.write(lock)).unwrap();
        store
    }

    fn signed_mock() -> Mock {
        Mock::Return(PolicySignOutcome::Signed {
            sig: [7; 64],
            key_id: "kid-1".into(),
            pubkey_b64: "pk".into(),
        })
    }

    /// The audit trail written into the scratch runtime dir, as one string.
    fn audit_text() -> String {
        fs::read_to_string(crate::audit::audit_path()).unwrap_or_default()
    }

    #[test]
    fn store_round_trips_the_exact_baseline_bytes() {
        let _dir = RuntimeDirGuard::new("round-trip");
        let doc = PolicyDoc {
            revision: 7,
            touched: vec![PolicyField::PageEvalEnabled],
            page_eval_enabled: true,
            ..PolicyDoc::default()
        };
        let bytes = serde_json::to_vec(&doc).unwrap();
        let store = PolicyStore {
            version: POLICY_STORE_VERSION,
            baseline_b64: base64_encode(&bytes),
            sig_b64: Some("c2ln".into()),
            key_id: Some("kid".into()),
            overlay: Some(PolicyOverlay {
                confirm_grace_ms: Some(0),
                ..PolicyOverlay::default()
            }),
        };
        ipc::with_runtime_lock(|lock| store.write(lock)).unwrap();
        let back = PolicyStore::load().unwrap().unwrap();
        assert_eq!(back, store);
        // The signed artifact survives byte-for-byte: decode returns the
        // exact bytes, and the strict parse reads the same document back.
        assert_eq!(base64_decode(&back.baseline_b64).unwrap(), bytes);
        assert_eq!(back.baseline_doc().unwrap(), doc);
    }

    #[test]
    fn a_flipped_baseline_byte_still_parses_but_changes_the_doc() {
        let _dir = RuntimeDirGuard::new("tamper-flip");
        let store = seed_store(1, &PolicyValues::default(), None);
        let mut bytes = base64_decode(&store.baseline_b64).unwrap();
        // Flip the revision digit: still valid JSON, different document.
        let pos = bytes
            .windows(12)
            .position(|w| w == b"\"revision\":1")
            .unwrap()
            + 11;
        bytes[pos] = b'2';
        let tampered = PolicyStore {
            baseline_b64: base64_encode(&bytes),
            ..store
        };
        ipc::with_runtime_lock(|lock| tampered.write(lock)).unwrap();
        // The parse succeeding is fine, by design: this file is storage,
        // not authority. The signature stored beside the bytes no longer
        // covers them, and signature verification is the EXTENSION's job
        // against its own pinned key (ADR-0032 decision 5) - the host store
        // cannot self-certify, so the host does not pretend to.
        let doc = PolicyStore::load()
            .unwrap()
            .unwrap()
            .baseline_doc()
            .unwrap();
        assert_eq!(doc.revision, 2);
    }

    #[test]
    fn a_flipped_byte_that_breaks_json_fails_baseline_doc_not_load() {
        let _dir = RuntimeDirGuard::new("tamper-break");
        let store = seed_store(1, &PolicyValues::default(), None);
        let mut bytes = base64_decode(&store.baseline_b64).unwrap();
        bytes[0] = b'X';
        let tampered = PolicyStore {
            baseline_b64: base64_encode(&bytes),
            ..store
        };
        ipc::with_runtime_lock(|lock| tampered.write(lock)).unwrap();
        // The load/baseline_doc split: the store envelope is intact, so
        // load() passes; the byte authority refuses the damaged document.
        let back = PolicyStore::load().unwrap().unwrap();
        assert!(back.baseline_doc().is_err());
        assert!(back.effective().is_err());
    }

    #[test]
    fn a_non_base64_baseline_fails_baseline_doc_not_load() {
        let _dir = RuntimeDirGuard::new("tamper-b64");
        let store = PolicyStore {
            version: POLICY_STORE_VERSION,
            baseline_b64: "not base64!".into(),
            sig_b64: None,
            key_id: None,
            overlay: None,
        };
        ipc::with_runtime_lock(|lock| store.write(lock)).unwrap();
        let back = PolicyStore::load().unwrap().unwrap();
        assert!(back.baseline_doc().is_err());
    }

    #[test]
    fn load_is_fail_closed_on_shape_size_and_version() {
        let _dir = RuntimeDirGuard::new("load-fail-closed");
        // Absent -> Ok(None): the legitimate no-policy-yet state.
        assert!(PolicyStore::load().unwrap().is_none());
        // An unknown field is refused, never skimmed over.
        fs::write(
            PolicyStore::path(),
            br#"{"version":1,"baseline_b64":"e30=","surprise":true}"#,
        )
        .unwrap();
        assert!(PolicyStore::load().is_err());
        // A wrong version is refused.
        fs::write(
            PolicyStore::path(),
            br#"{"version":99,"baseline_b64":"e30="}"#,
        )
        .unwrap();
        assert!(PolicyStore::load().is_err());
        // An oversized file is refused without being slurped.
        fs::write(PolicyStore::path(), vec![b' '; POLICY_MAX_BYTES + 1]).unwrap();
        assert!(PolicyStore::load().is_err());
    }

    #[test]
    fn set_signed_writes_the_exact_signed_bytes_and_bumps_revisions() {
        let _dir = RuntimeDirGuard::new("set-signed-happy");
        let _reset = policy_test_hook::ResetOnDrop;
        policy_test_hook::set(signed_mock());

        let values = PolicyValues {
            page_eval_enabled: true,
            ..PolicyValues::default()
        };
        let rung = set_signed(
            values.clone(),
            vec![PolicyField::PageEvalEnabled],
            Surface::Core,
            PolicyGrantFloor::SignatureOnly,
        )
        .unwrap();
        assert_eq!(rung, PresencePath::TouchId);

        let first = PolicyStore::load().unwrap().unwrap();
        let doc = first.baseline_doc().unwrap();
        assert_eq!(doc.revision, 1);
        assert_eq!(doc.touched, vec![PolicyField::PageEvalEnabled]);
        assert_eq!(doc.values(), values);
        assert_eq!(
            first.sig_b64.as_deref(),
            Some(base64_encode(&[7; 64]).as_str())
        );
        assert_eq!(first.key_id.as_deref(), Some("kid-1"));
        assert!(first.overlay.is_none());
        // No previous store existed, so nothing was pushed.
        assert!(load_history().unwrap().is_none());

        // The second write supersedes the first: revision 2, and the ring
        // holds the exact previous record.
        policy_test_hook::set(signed_mock());
        set_signed(
            PolicyValues::default(),
            vec![PolicyField::PageEvalEnabled],
            Surface::Core,
            PolicyGrantFloor::SignatureOnly,
        )
        .unwrap();
        let second = PolicyStore::load().unwrap().unwrap();
        assert_eq!(second.baseline_doc().unwrap().revision, 2);
        let history = load_history().unwrap().unwrap();
        assert_eq!(history.entries.len(), 1);
        let entry = &history.entries[0];
        assert_eq!(entry.baseline_b64, first.baseline_b64);
        assert_eq!(entry.sig_b64, first.sig_b64);
        assert_eq!(entry.key_id, first.key_id);
        assert_eq!(entry.overlay, first.overlay);
        assert!(entry.superseded_unix > 0);
        // The trail names the rung and the touched fields.
        let trail = audit_text();
        assert!(trail.contains("policy_write"), "{trail}");
        assert!(trail.contains("auth=touch_id"), "{trail}");
        assert!(trail.contains("touched=pageEvalEnabled"), "{trail}");
    }

    #[test]
    fn set_signed_clears_touched_overlay_entries_and_keeps_the_rest() {
        let _dir = RuntimeDirGuard::new("overlay-retention");
        let _reset = policy_test_hook::ResetOnDrop;
        let overlay = PolicyOverlay {
            confirm_grace_ms: Some(1_000),
            disabled_tools: Some(vec!["page_eval".into()]),
            ..PolicyOverlay::default()
        };
        seed_store(1, &PolicyValues::default(), Some(overlay));

        policy_test_hook::set(signed_mock());
        set_signed(
            PolicyValues {
                confirm_grace_ms: 1_000,
                ..PolicyValues::default()
            },
            vec![PolicyField::ConfirmGraceMs],
            Surface::Core,
            PolicyGrantFloor::SignatureOnly,
        )
        .unwrap();

        let store = PolicyStore::load().unwrap().unwrap();
        // The tapped edit superseded the overlay entry on its field; the
        // untouched entry survives as overlay.
        assert_eq!(
            store.overlay,
            Some(PolicyOverlay {
                disabled_tools: Some(vec!["page_eval".into()]),
                ..PolicyOverlay::default()
            })
        );
    }

    #[test]
    fn folding_the_effective_values_leaves_effective_unchanged() {
        let _dir = RuntimeDirGuard::new("overlay-fold");
        let _reset = policy_test_hook::ResetOnDrop;
        // A baseline with grants on, restricted by overlay.
        let baseline_values = PolicyValues {
            page_eval_enabled: true,
            ..PolicyValues::default()
        };
        let overlay = PolicyOverlay {
            page_eval_enabled: Some(false),
            confirm_grace_ms: Some(0),
            disabled_tools: Some(vec!["page_upload".into()]),
            ..PolicyOverlay::default()
        };
        let seeded = seed_store(3, &baseline_values, Some(overlay));
        let effective_before = seeded.effective().unwrap();

        // The explicit fold act (ADR-0032 decision 3): a new revision
        // carrying the folded fields' EFFECTIVE values with exactly those
        // fields touched.
        policy_test_hook::set(signed_mock());
        set_signed(
            effective_before.clone(),
            vec![
                PolicyField::PageEvalEnabled,
                PolicyField::ConfirmGraceMs,
                PolicyField::DisabledTools,
            ],
            Surface::Core,
            PolicyGrantFloor::SignatureOnly,
        )
        .unwrap();

        let store = PolicyStore::load().unwrap().unwrap();
        assert_eq!(store.effective().unwrap(), effective_before);
        assert_eq!(store.baseline_doc().unwrap().revision, 4);
        // Exactly the folded entries emptied - and they were the whole
        // overlay, so it normalizes away.
        assert!(store.overlay.is_none());
    }

    #[test]
    fn set_signed_signs_exactly_the_bytes_it_stores() {
        let _dir = RuntimeDirGuard::new("signed-bytes-identity");
        let _reset = policy_test_hook::ResetOnDrop;
        policy_test_hook::set(signed_mock());
        let values = PolicyValues {
            page_eval_enabled: true,
            ..PolicyValues::default()
        };
        let touched = vec![PolicyField::PageEvalEnabled];
        set_signed(
            values.clone(),
            touched.clone(),
            Surface::Core,
            PolicyGrantFloor::SignatureOnly,
        )
        .unwrap();
        // The bytes the signing primitive was called with are the bytes the
        // store persists, byte for byte: the signature can only ever cover
        // exactly what is stored.
        let signed = policy_test_hook::last_doc_bytes().unwrap();
        let store = PolicyStore::load().unwrap().unwrap();
        assert_eq!(base64_decode(&store.baseline_b64).unwrap(), signed);
        // And those bytes parse back to a document scoped by exactly the
        // touched set and values that were passed.
        let doc: PolicyDoc = serde_json::from_slice(&signed).unwrap();
        assert_eq!(doc.touched, touched);
        assert_eq!(doc.values(), values);
    }

    #[test]
    fn an_empty_touched_set_refuses_before_any_prompt() {
        let _dir = RuntimeDirGuard::new("empty-touched");
        let _reset = policy_test_hook::ResetOnDrop;
        // The mock panics if the signing primitive is reached: the refusal
        // must be promptless.
        policy_test_hook::set(Mock::PanicIfCalled);
        let err = set_signed(
            PolicyValues::default(),
            vec![],
            Surface::Core,
            PolicyGrantFloor::AppConfirm,
        )
        .unwrap_err();
        assert!(matches!(err, PolicyWriteError::Invalid(_)));
        assert!(PolicyStore::load().unwrap().is_none());
    }

    #[test]
    fn revision_overflow_refuses_before_any_prompt() {
        let _dir = RuntimeDirGuard::new("revision-overflow");
        let _reset = policy_test_hook::ResetOnDrop;
        seed_store(JS_SAFE_INT_MAX, &PolicyValues::default(), None);
        policy_test_hook::set(Mock::PanicIfCalled);
        let err = set_signed(
            PolicyValues::default(),
            vec![PolicyField::CdpMode],
            Surface::Core,
            PolicyGrantFloor::AppConfirm,
        )
        .unwrap_err();
        assert!(matches!(err, PolicyWriteError::RevisionOverflow));
    }

    #[test]
    fn the_last_js_safe_revision_still_writes() {
        // The near-boundary through the full seam: MAX - 1 mints exactly
        // MAX, the last legal revision (the overflow test above pins that
        // MAX itself refuses).
        let _dir = RuntimeDirGuard::new("revision-at-bound");
        let _reset = policy_test_hook::ResetOnDrop;
        seed_store(JS_SAFE_INT_MAX - 1, &PolicyValues::default(), None);
        policy_test_hook::set(signed_mock());
        set_signed(
            PolicyValues::default(),
            vec![PolicyField::CdpMode],
            Surface::Core,
            PolicyGrantFloor::SignatureOnly,
        )
        .unwrap();
        assert_eq!(
            PolicyStore::load()
                .unwrap()
                .unwrap()
                .baseline_doc()
                .unwrap()
                .revision,
            JS_SAFE_INT_MAX
        );
    }

    #[test]
    fn the_revision_seam_covers_its_boundaries() {
        // Deterministic edges of next_revision (the proptest below sweeps
        // the range): no store mints 1, MAX - 1 mints MAX, MAX overflows.
        assert_eq!(next_revision(None).unwrap(), 1);
        assert_eq!(
            next_revision(Some(JS_SAFE_INT_MAX - 1)).unwrap(),
            JS_SAFE_INT_MAX
        );
        assert!(matches!(
            next_revision(Some(JS_SAFE_INT_MAX)),
            Err(PolicyWriteError::RevisionOverflow)
        ));
    }

    #[test]
    fn a_refused_signature_never_falls_to_the_floor() {
        let _dir = RuntimeDirGuard::new("refused-no-floor");
        let _reset = policy_test_hook::ResetOnDrop;
        let seeded = seed_store(1, &PolicyValues::default(), None);
        policy_test_hook::set(Mock::Return(PolicySignOutcome::Refused(
            "user cancelled".into(),
        )));
        // The APP floor is offered and must not be consulted: a refusal is
        // terminal (the no-downgrade rule), never an unsigned write.
        let err = set_signed(
            PolicyValues::default(),
            vec![PolicyField::CdpMode],
            Surface::Core,
            PolicyGrantFloor::AppConfirm,
        )
        .unwrap_err();
        assert!(matches!(err, PolicyWriteError::Refused(_)));
        assert_eq!(PolicyStore::load().unwrap().unwrap(), seeded);
        assert!(audit_text().contains("\"outcome\":\"refused\""));
    }

    #[test]
    fn unavailable_hardware_refuses_a_signature_only_surface() {
        let _dir = RuntimeDirGuard::new("signature-only");
        let _reset = policy_test_hook::ResetOnDrop;
        // The default mock is Unavailable: a keyless machine.
        let err = set_signed(
            PolicyValues::default(),
            vec![PolicyField::CdpMode],
            Surface::Cli,
            PolicyGrantFloor::SignatureOnly,
        )
        .unwrap_err();
        assert!(matches!(err, PolicyWriteError::NoSigningKey));
        assert!(PolicyStore::load().unwrap().is_none());
        assert!(audit_text().contains("no signing key"));
    }

    #[test]
    fn unavailable_hardware_writes_unsigned_on_the_app_floor() {
        let _dir = RuntimeDirGuard::new("app-floor");
        let _reset = policy_test_hook::ResetOnDrop;
        // Default Unavailable mock: the app's interactive floor stores the
        // SAME document bytes unsigned (ADR-0032 decision 3).
        let rung = set_signed(
            PolicyValues::default(),
            vec![PolicyField::ConfirmGraceMs],
            Surface::Core,
            PolicyGrantFloor::AppConfirm,
        )
        .unwrap();
        assert_eq!(rung, PresencePath::AppConfirm);
        let store = PolicyStore::load().unwrap().unwrap();
        assert!(store.sig_b64.is_none());
        assert!(store.key_id.is_none());
        assert_eq!(store.baseline_doc().unwrap().revision, 1);
        assert!(audit_text().contains("auth=app_confirm"));
    }

    #[test]
    fn restrict_without_a_baseline_refuses() {
        let _dir = RuntimeDirGuard::new("restrict-no-baseline");
        let err = restrict(
            PolicyOverlay {
                page_eval_enabled: Some(false),
                ..PolicyOverlay::default()
            },
            Surface::Cli,
        )
        .unwrap_err();
        assert!(matches!(err, PolicyWriteError::NoBaseline));
        // A promptless precondition stays unaudited (the pair_client
        // InvalidName precedent), unlike the direction refusal.
        assert_eq!(audit_text(), "");
    }

    #[test]
    fn a_restricting_overlay_applies_and_pushes_history() {
        let _dir = RuntimeDirGuard::new("restrict-applies");
        let seeded = seed_store(
            1,
            &PolicyValues {
                page_eval_enabled: true,
                ..PolicyValues::default()
            },
            None,
        );
        restrict(
            PolicyOverlay {
                page_eval_enabled: Some(false),
                ..PolicyOverlay::default()
            },
            Surface::Cli,
        )
        .unwrap();
        let store = PolicyStore::load().unwrap().unwrap();
        assert!(!store.effective().unwrap().page_eval_enabled);
        // The baseline itself is untouched; only the overlay moved.
        assert_eq!(store.baseline_b64, seeded.baseline_b64);
        let history = load_history().unwrap().unwrap();
        assert_eq!(history.entries.len(), 1);
        assert_eq!(history.entries[0].overlay, None);
        assert!(audit_text().contains("auth=none; restricted=pageEvalEnabled"));
    }

    #[test]
    fn a_relaxing_overlay_is_refused_with_the_store_unchanged() {
        let _dir = RuntimeDirGuard::new("restrict-relaxing");
        let seeded = seed_store(
            1,
            &PolicyValues {
                page_eval_enabled: true,
                ..PolicyValues::default()
            },
            Some(PolicyOverlay {
                page_eval_enabled: Some(false),
                ..PolicyOverlay::default()
            }),
        );
        // "Undo the restriction" equals the baseline value but RELAXES the
        // effective policy: the free lane refuses it (it is the signed
        // lane's business, ADR-0032 decision 3).
        let err = restrict(
            PolicyOverlay {
                page_eval_enabled: Some(true),
                ..PolicyOverlay::default()
            },
            Surface::Cli,
        )
        .unwrap_err();
        assert!(matches!(err, PolicyWriteError::NotARestriction));
        assert_eq!(PolicyStore::load().unwrap().unwrap(), seeded);
        assert!(load_history().unwrap().is_none());
        // The refusal is in the trail (log-after-decide), naming the
        // offending posture.
        let trail = audit_text();
        assert!(trail.contains("\"outcome\":\"refused\""), "{trail}");
        assert!(
            trail.contains(
                "auth=none; restricted=pageEvalEnabled; refused: relaxes the effective policy"
            ),
            "{trail}"
        );
    }

    #[test]
    fn restrict_merges_entrywise_keeping_unnamed_entries() {
        let _dir = RuntimeDirGuard::new("restrict-merge");
        seed_store(
            1,
            &PolicyValues {
                page_eval_enabled: true,
                ..PolicyValues::default()
            },
            Some(PolicyOverlay {
                page_eval_enabled: Some(false),
                ..PolicyOverlay::default()
            }),
        );
        restrict(
            PolicyOverlay {
                confirm_grace_ms: Some(0),
                ..PolicyOverlay::default()
            },
            Surface::Cli,
        )
        .unwrap();
        let store = PolicyStore::load().unwrap().unwrap();
        assert_eq!(
            store.overlay,
            Some(PolicyOverlay {
                page_eval_enabled: Some(false),
                confirm_grace_ms: Some(0),
                ..PolicyOverlay::default()
            })
        );
    }

    #[test]
    fn history_evicts_oldest_entries_at_the_cap() {
        let entry = |tag: u64| PolicyHistoryEntry {
            baseline_b64: base64_encode(format!("baseline-{tag:04}").as_bytes()),
            sig_b64: None,
            key_id: None,
            overlay: None,
            superseded_unix: tag,
        };
        let mut history = PolicyHistory {
            version: POLICY_HISTORY_VERSION,
            entries: (0..20).map(entry).collect(),
        };
        // A cap that holds a handful of entries: the ring drops from the
        // FRONT (oldest) until it fits, keeping the newest.
        let bytes = history_bytes_capped(&mut history, 800).unwrap();
        assert!(bytes.len() <= 800);
        assert!(!history.entries.is_empty());
        assert!(history.entries.len() < 20);
        assert_eq!(history.entries.last().unwrap().superseded_unix, 19);
        assert_eq!(
            history.entries.first().unwrap().superseded_unix,
            20 - history.entries.len() as u64
        );
        // A cap below a single entry empties the ring but still serializes
        // the envelope.
        let mut tiny = PolicyHistory {
            version: POLICY_HISTORY_VERSION,
            entries: vec![entry(1)],
        };
        let bytes = history_bytes_capped(&mut tiny, 60).unwrap();
        assert!(tiny.entries.is_empty());
        assert!(serde_json::from_slice::<PolicyHistory>(&bytes).is_ok());
    }

    #[test]
    fn a_corrupt_history_file_never_blocks_policy_writes() {
        let _dir = RuntimeDirGuard::new("history-corrupt");
        let _reset = policy_test_hook::ResetOnDrop;
        seed_store(1, &PolicyValues::default(), None);
        fs::write(PolicyHistory::path(), b"garbage, not json").unwrap();
        // Reading it fails closed for the (future) rollback surface...
        assert!(load_history().is_err());
        // ...but the enforcement paths and both seams stay fully functional:
        // the writer logs, replaces the ring, and the policy writes land.
        assert!(PolicyStore::load().unwrap().is_some());
        policy_test_hook::set(signed_mock());
        set_signed(
            PolicyValues::default(),
            vec![PolicyField::CdpMode],
            Surface::Core,
            PolicyGrantFloor::SignatureOnly,
        )
        .unwrap();
        restrict(
            PolicyOverlay {
                confirm_grace_ms: Some(0),
                ..PolicyOverlay::default()
            },
            Surface::Cli,
        )
        .unwrap();
        // The fresh ring holds the records superseded after the corruption.
        assert_eq!(load_history().unwrap().unwrap().entries.len(), 2);
    }

    #[test]
    fn a_moved_baseline_revision_conflicts_instead_of_overwriting() {
        let _dir = RuntimeDirGuard::new("revision-guard");
        seed_store(2, &PolicyValues::default(), None);
        let doc = PolicyDoc::from_values(&PolicyValues::default(), 3, vec![PolicyField::CdpMode]);
        let bytes = serde_json::to_vec(&doc).unwrap();
        // The guard, staged directly at the locked write: a pre-prompt
        // observation that no longer matches the store refuses (the
        // concurrent write survives), a matching one lands.
        let observation = |revision| PrePromptObservation {
            store: Some(StoreObservation {
                revision,
                overlay: None,
            }),
            host_key_epoch: 0,
        };
        let stale = ipc::with_runtime_lock(|lock| {
            Ok(write_baseline_locked(
                lock,
                observation(1),
                &bytes,
                None,
                None,
                &[PolicyField::CdpMode],
            ))
        })
        .unwrap();
        assert!(matches!(stale, Err(PolicyWriteError::Conflict)));
        assert_eq!(
            PolicyStore::load()
                .unwrap()
                .unwrap()
                .baseline_doc()
                .unwrap()
                .revision,
            2
        );
        // An observation of "no store" while one exists is the same refusal.
        let stale_none = ipc::with_runtime_lock(|lock| {
            Ok(write_baseline_locked(
                lock,
                PrePromptObservation {
                    store: None,
                    host_key_epoch: 0,
                },
                &bytes,
                None,
                None,
                &[PolicyField::CdpMode],
            ))
        })
        .unwrap();
        assert!(matches!(stale_none, Err(PolicyWriteError::Conflict)));
        let fresh = ipc::with_runtime_lock(|lock| {
            Ok(write_baseline_locked(
                lock,
                observation(2),
                &bytes,
                None,
                None,
                &[PolicyField::CdpMode],
            ))
        })
        .unwrap();
        assert!(fresh.is_ok());
        assert_eq!(
            PolicyStore::load()
                .unwrap()
                .unwrap()
                .baseline_doc()
                .unwrap()
                .revision,
            3
        );
    }

    #[test]
    fn an_overlay_moved_mid_prompt_conflicts_instead_of_clobbering() {
        let _dir = RuntimeDirGuard::new("overlay-guard");
        seed_store(
            2,
            &PolicyValues {
                page_eval_enabled: true,
                ..PolicyValues::default()
            },
            None,
        );
        // The observation a prompt would cover: revision 2, no overlay.
        let observed = PrePromptObservation {
            store: Some(StoreObservation {
                revision: 2,
                overlay: None,
            }),
            host_key_epoch: 0,
        };
        // A restrict lands mid-prompt (staged through the internal fn, like
        // the revision test above): same revision, moved overlay.
        let restriction = PolicyOverlay {
            page_eval_enabled: Some(false),
            ..PolicyOverlay::default()
        };
        ipc::with_runtime_lock(|lock| Ok(restrict_locked(lock, restriction.clone())))
            .unwrap()
            .unwrap();
        let doc = PolicyDoc::from_values(&PolicyValues::default(), 3, vec![PolicyField::CdpMode]);
        let bytes = serde_json::to_vec(&doc).unwrap();
        let stale = ipc::with_runtime_lock(|lock| {
            Ok(write_baseline_locked(
                lock,
                observed,
                &bytes,
                None,
                None,
                &[PolicyField::CdpMode],
            ))
        })
        .unwrap();
        assert!(matches!(stale, Err(PolicyWriteError::Conflict)));
        // The concurrent restriction survives, un-clobbered.
        let store = PolicyStore::load().unwrap().unwrap();
        assert_eq!(store.baseline_doc().unwrap().revision, 2);
        assert_eq!(store.overlay, Some(restriction.clone()));
        // An observation carrying the moved overlay lands.
        let fresh = ipc::with_runtime_lock(|lock| {
            Ok(write_baseline_locked(
                lock,
                PrePromptObservation {
                    store: Some(StoreObservation {
                        revision: 2,
                        overlay: Some(restriction),
                    }),
                    host_key_epoch: 0,
                },
                &bytes,
                None,
                None,
                &[PolicyField::CdpMode],
            ))
        })
        .unwrap();
        assert!(fresh.is_ok());
    }

    #[test]
    fn a_disposal_during_the_prompt_conflicts_even_with_no_store_on_both_sides() {
        let _dir = RuntimeDirGuard::new("dispose-guard");
        // A first write's pre-prompt observation: no store, and the host-key
        // epoch as it stood before the tap.
        let doc = PolicyDoc::from_values(&PolicyValues::default(), 1, vec![PolicyField::CdpMode]);
        let bytes = serde_json::to_vec(&doc).unwrap();
        let observed_epoch = crate::revocation::Revocation::current()
            .unwrap()
            .host_key_epoch;
        // The disposal seam runs to completion mid-prompt: key deleted,
        // baseline cleared (a no-op here, no store exists), host-key epoch
        // bumped inside its critical section.
        ipc::with_runtime_lock(|lock| {
            crate::revocation::bump_locked(lock, crate::revocation::Scope::HostKey)
        })
        .unwrap();
        // The store guard alone cannot see it (no store observed, no store
        // current); the epoch guard refuses, so a signature minted by the
        // just-deleted key never lands as a baseline.
        let stale = ipc::with_runtime_lock(|lock| {
            Ok(write_baseline_locked(
                lock,
                PrePromptObservation {
                    store: None,
                    host_key_epoch: observed_epoch,
                },
                &bytes,
                Some("c2ln".into()),
                Some("key-id".into()),
                &[PolicyField::CdpMode],
            ))
        })
        .unwrap();
        assert!(matches!(stale, Err(PolicyWriteError::Conflict)));
        assert!(PolicyStore::load().unwrap().is_none());
    }

    #[test]
    fn a_tampered_overlay_that_relaxes_the_baseline_refuses_every_read() {
        let _dir = RuntimeDirGuard::new("overlay-tamper");
        // No legitimate write produces this state (restrict only tightens,
        // set_signed carries baseline values on untouched fields), so a
        // schema-valid overlay flipping a grant ON over a denying baseline
        // is a hand-edited policy.json - and it reads as damage, never as
        // the relaxed values.
        seed_store(
            3,
            &PolicyValues::default(),
            Some(PolicyOverlay {
                page_eval_enabled: Some(true),
                ..PolicyOverlay::default()
            }),
        );
        let store = PolicyStore::load().unwrap().unwrap();
        let err = store.effective().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("relaxes the signed baseline"));
        // The baseline itself still parses: the refusal is the direction
        // check, not collateral corruption.
        assert_eq!(store.baseline_doc().unwrap().revision, 3);
    }

    #[test]
    fn clearing_the_baseline_bumps_the_policy_epoch_once() {
        let _dir = RuntimeDirGuard::new("clear-epoch");
        seed_store(1, &PolicyValues::default(), None);
        let before = crate::revocation::Revocation::current()
            .unwrap()
            .policy_epoch;
        ipc::with_runtime_lock(clear_baseline_locked).unwrap();
        assert!(PolicyStore::load().unwrap().is_none());
        let after = crate::revocation::Revocation::current()
            .unwrap()
            .policy_epoch;
        assert!(
            after > before,
            "a connected host only pushes the cleared state if the epoch moved"
        );
        // Clearing an already-absent store is a no-op: no epoch churn.
        ipc::with_runtime_lock(clear_baseline_locked).unwrap();
        let again = crate::revocation::Revocation::current()
            .unwrap()
            .policy_epoch;
        assert_eq!(again, after);
    }

    #[test]
    fn a_relaxation_outside_the_touched_set_refuses_before_any_prompt() {
        let _dir = RuntimeDirGuard::new("touched-coverage");
        let _reset = policy_test_hook::ResetOnDrop;
        seed_store(1, &PolicyValues::default(), None);
        // page_eval_enabled: true relaxes the effective anchor, but touched
        // names only cdpMode: promptless refusal (the mock panics if the
        // signing primitive is reached).
        policy_test_hook::set(Mock::PanicIfCalled);
        let relaxing = PolicyValues {
            page_eval_enabled: true,
            ..PolicyValues::default()
        };
        let err = set_signed(
            relaxing.clone(),
            vec![PolicyField::CdpMode],
            Surface::Core,
            PolicyGrantFloor::AppConfirm,
        )
        .unwrap_err();
        assert!(matches!(err, PolicyWriteError::Invalid(_)));
        // With no store at all the anchor is the deny baseline: an
        // undeclared first-write grant refuses the same way.
        fs::remove_file(PolicyStore::path()).unwrap();
        let err = set_signed(
            relaxing,
            vec![PolicyField::CdpMode],
            Surface::Core,
            PolicyGrantFloor::AppConfirm,
        )
        .unwrap_err();
        assert!(matches!(err, PolicyWriteError::Invalid(_)));
        assert!(PolicyStore::load().unwrap().is_none());
    }

    #[test]
    fn a_touched_superset_of_the_relaxations_passes() {
        let _dir = RuntimeDirGuard::new("touched-superset");
        let _reset = policy_test_hook::ResetOnDrop;
        seed_store(1, &PolicyValues::default(), None);
        policy_test_hook::set(signed_mock());
        set_signed(
            PolicyValues {
                page_eval_enabled: true,
                ..PolicyValues::default()
            },
            vec![PolicyField::PageEvalEnabled, PolicyField::CdpMode],
            Surface::Core,
            PolicyGrantFloor::SignatureOnly,
        )
        .unwrap();
        assert!(
            PolicyStore::load()
                .unwrap()
                .unwrap()
                .effective()
                .unwrap()
                .page_eval_enabled
        );
    }

    #[test]
    fn a_restriction_lands_when_named_and_refuses_as_untouched_drift() {
        let _dir = RuntimeDirGuard::new("touched-restriction");
        let _reset = policy_test_hook::ResetOnDrop;
        seed_store(
            1,
            &PolicyValues {
                page_eval_enabled: true,
                ..PolicyValues::default()
            },
            None,
        );
        // Turning page_eval OFF is a restriction, but the signed document
        // carries baseline values on fields it does not touch (decision 3):
        // changing it under an unrelated touched field is an unnamed edit
        // and refuses promptless, in EITHER direction.
        policy_test_hook::set(Mock::PanicIfCalled);
        let drift = set_signed(
            PolicyValues::default(),
            vec![PolicyField::ConfirmGraceMs],
            Surface::Core,
            PolicyGrantFloor::SignatureOnly,
        );
        assert!(matches!(drift, Err(PolicyWriteError::Invalid(_))));
        // Named in touched, the same restriction lands (the coverage check
        // binds relaxations only; restrictions just need naming).
        policy_test_hook::set(signed_mock());
        set_signed(
            PolicyValues::default(),
            vec![PolicyField::PageEvalEnabled],
            Surface::Core,
            PolicyGrantFloor::SignatureOnly,
        )
        .unwrap();
        assert!(
            !PolicyStore::load()
                .unwrap()
                .unwrap()
                .effective()
                .unwrap()
                .page_eval_enabled
        );
    }

    #[test]
    fn restrict_bounds_the_merged_disabled_tools() {
        use crate::policy::{DISABLED_TOOLS_MAX_ENTRIES, DISABLED_TOOL_NAME_MAX_BYTES};
        let _dir = RuntimeDirGuard::new("restrict-tools-bounds");
        let seeded = seed_store(1, &PolicyValues::default(), None);
        // Growing the set restricts, so only the bounds can refuse these.
        let with_tools = |tools: Vec<String>| PolicyOverlay {
            disabled_tools: Some(tools),
            ..PolicyOverlay::default()
        };
        let err = restrict(
            with_tools(vec!["t".into(); DISABLED_TOOLS_MAX_ENTRIES + 1]),
            Surface::Cli,
        )
        .unwrap_err();
        assert!(matches!(err, PolicyWriteError::Invalid(_)));
        let err = restrict(
            with_tools(vec!["a".repeat(DISABLED_TOOL_NAME_MAX_BYTES + 1)]),
            Surface::Cli,
        )
        .unwrap_err();
        assert!(matches!(err, PolicyWriteError::Invalid(_)));
        assert_eq!(PolicyStore::load().unwrap().unwrap(), seeded);
        // At the bounds it applies - and the resulting store still loads,
        // which is what the bounds are for.
        restrict(
            with_tools(vec![
                "a".repeat(DISABLED_TOOL_NAME_MAX_BYTES);
                DISABLED_TOOLS_MAX_ENTRIES
            ]),
            Surface::Cli,
        )
        .unwrap();
        assert_eq!(
            PolicyStore::load()
                .unwrap()
                .unwrap()
                .effective()
                .unwrap()
                .disabled_tools
                .len(),
            DISABLED_TOOLS_MAX_ENTRIES
        );
    }

    #[test]
    fn store_write_refuses_bytes_over_the_read_cap() {
        let _dir = RuntimeDirGuard::new("write-cap");
        let store = PolicyStore {
            version: POLICY_STORE_VERSION,
            baseline_b64: "A".repeat(POLICY_MAX_BYTES),
            sig_b64: None,
            key_id: None,
            overlay: None,
        };
        let err = ipc::with_runtime_lock(|lock| store.write(lock)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        // Nothing was persisted: load cannot be handed what it must refuse.
        assert!(PolicyStore::load().unwrap().is_none());
    }

    #[test]
    fn clear_baseline_removes_the_store_and_keeps_history() {
        let _dir = RuntimeDirGuard::new("clear-baseline");
        // A signed baseline plus a surviving restriction overlay.
        let seeded = seed_store(
            3,
            &PolicyValues {
                page_eval_enabled: true,
                ..PolicyValues::default()
            },
            Some(PolicyOverlay {
                confirm_grace_ms: Some(0),
                ..PolicyOverlay::default()
            }),
        );
        ipc::with_runtime_lock(clear_baseline_locked).unwrap();
        // The live store is gone (baseline/sig/key_id cleared): a baseline
        // signed by a now-deleted key must not outlive it.
        assert!(PolicyStore::load().unwrap().is_none());
        // The disposed record - baseline, sig, key id, AND overlay - survives
        // in the history ring as the re-signable draft.
        let history = load_history().unwrap().unwrap();
        assert_eq!(history.entries.len(), 1);
        let entry = &history.entries[0];
        assert_eq!(entry.baseline_b64, seeded.baseline_b64);
        assert_eq!(entry.sig_b64, seeded.sig_b64);
        assert_eq!(entry.key_id, seeded.key_id);
        assert_eq!(entry.overlay, seeded.overlay);
    }

    #[test]
    fn clear_baseline_is_a_noop_without_a_store() {
        let _dir = RuntimeDirGuard::new("clear-baseline-empty");
        ipc::with_runtime_lock(clear_baseline_locked).unwrap();
        assert!(PolicyStore::load().unwrap().is_none());
        assert!(load_history().unwrap().is_none());
    }

    #[test]
    fn a_signed_write_bumps_the_policy_epoch() {
        let _dir = RuntimeDirGuard::new("policy-epoch-signed");
        let _reset = policy_test_hook::ResetOnDrop;
        let before = crate::revocation::Revocation::current()
            .unwrap()
            .policy_epoch;
        policy_test_hook::set(signed_mock());
        set_signed(
            PolicyValues {
                page_eval_enabled: true,
                ..PolicyValues::default()
            },
            vec![PolicyField::PageEvalEnabled],
            Surface::Core,
            PolicyGrantFloor::SignatureOnly,
        )
        .unwrap();
        let after = crate::revocation::Revocation::current()
            .unwrap()
            .policy_epoch;
        assert!(after > before, "a signed write must bump the policy epoch");
    }

    #[test]
    fn a_restriction_bumps_the_policy_epoch() {
        let _dir = RuntimeDirGuard::new("policy-epoch-restrict");
        seed_store(
            1,
            &PolicyValues {
                page_eval_enabled: true,
                ..PolicyValues::default()
            },
            None,
        );
        let before = crate::revocation::Revocation::current()
            .unwrap()
            .policy_epoch;
        restrict(
            PolicyOverlay {
                page_eval_enabled: Some(false),
                ..PolicyOverlay::default()
            },
            Surface::Cli,
        )
        .unwrap();
        let after = crate::revocation::Revocation::current()
            .unwrap()
            .policy_epoch;
        assert!(after > before, "a restriction must bump the policy epoch");
    }
}

/// Property coverage of the revision seam, the policy/mod.rs `mod proptests`
/// pattern. [`next_revision`] IS the arithmetic `set_signed` runs (extracted,
/// not reimplemented), proptested directly because staging a seeded store per
/// case would cost a runtime directory each; the same boundaries through the
/// full seam are pinned by `revision_overflow_refuses_before_any_prompt` and
/// `the_last_js_safe_revision_still_writes` above.
#[cfg(test)]
mod proptests {
    use proptest::prelude::*;

    use super::{next_revision, PolicyWriteError, JS_SAFE_INT_MAX};

    /// Baseline revisions across the whole JS-safe range, weighted so the
    /// bound edges occur in every run, not just by luck.
    fn arb_revision() -> impl Strategy<Value = u64> {
        prop_oneof![
            0..=JS_SAFE_INT_MAX,
            Just(0u64),
            Just(JS_SAFE_INT_MAX - 1),
            Just(JS_SAFE_INT_MAX),
        ]
    }

    proptest! {
        /// Monotonicity with no wraparound (ADR-0032): a store observed at
        /// baseline revision r mints exactly r + 1, still JS-safe, and the
        /// bound itself refuses (`RevisionOverflow`) instead of wrapping,
        /// saturating, or panicking.
        #[test]
        fn a_grant_write_mints_exactly_the_next_revision(r in arb_revision()) {
            if r == JS_SAFE_INT_MAX {
                prop_assert!(matches!(
                    next_revision(Some(r)),
                    Err(PolicyWriteError::RevisionOverflow)
                ));
            } else {
                let next = next_revision(Some(r)).unwrap();
                prop_assert_eq!(next, r + 1);
                prop_assert!(next <= JS_SAFE_INT_MAX);
            }
        }
    }
}
