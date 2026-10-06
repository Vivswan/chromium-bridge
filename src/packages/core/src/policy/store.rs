//! The on-disk policy store, the history ring, and the write seams: two
//! [`RuntimeRecord`]s behind public seams.

use std::io;

use serde::{Deserialize, Serialize};

use super::{
    field_differs, field_relaxes, fold, restricts_or_equal, validate_disabled_tools, PolicyDoc,
    PolicyField, PolicyOverlay, PolicyValues, JS_SAFE_INT_MAX,
};
use crate::enclave::{base64_decode, base64_encode, EnrollmentKey};
use crate::ipc;
use crate::presence::{PresenceAttestation, PresenceError, PresencePath};
use crate::runtime_record::{Ladder, Record, RuntimeRecord};

// ---- The on-disk store ------------------------------------------------------

/// The persisted policy state (`policy.json`): the signed baseline as the EXACT bytes the signature covers
/// (base64, so the artifact survives the JSON hop byte-for-byte), its signature, and the restriction overlay.
/// Storage, not authority: the extension verifies the signature against its own pin and the host re-derives
/// everything from the bytes. An unreadable store means refuse at every caller, never a default that could
/// mask a tamper.
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
    /// The exact signed document bytes, base64 (strict alphabet, one
    /// accepted spelling per byte string - see [`base64_decode`]).
    pub baseline_b64: String,
    /// The host key's signature over the policy-domain message, base64. `None`
    /// is an unsigned baseline, which no host write path produces anymore.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig_b64: Option<String>,
    /// The signing key id, host bookkeeping only: the extension verifies
    /// against its own pinned key and never trusts this field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// The current unsigned restriction overlay, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlay: Option<PolicyOverlay>,
}

impl Record for PolicyStore {
    const FILE: &'static str = "policy.json";
    const MAX_BYTES: usize = 256 * 1024;
    const LADDER: Ladder = crate::migrations::policy::LADDER;
}

impl PolicyStore {
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
}

// ---- History: the rollback ring (data, never authority) ---------------------

/// Superseded policy records (`policy-history.json`), oldest first: the data a rollback
/// surface offers back to the user. Data, never authority - no enforcement
/// path reads this file, and a rollback built from it is an ordinary
/// [`set_signed`] / [`restrict`] write with the full checks of those seams. A damaged ring
/// never affects the store's [`RuntimeRecord::load`] or the seams: their writer replaces it and moves on
/// ([`push_history_locked`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyHistory {
    pub entries: Vec<PolicyHistoryEntry>,
}

impl Record for PolicyHistory {
    const FILE: &'static str = "policy-history.json";
    const MAX_BYTES: usize = 256 * 1024;
    const LADDER: Ladder = crate::migrations::policy_history::LADDER;
}

/// One superseded [`PolicyStore`] record, plus when it was superseded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyHistoryEntry {
    pub baseline_b64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlay: Option<PolicyOverlay>,
    /// Unix seconds when the record stopped being the current store.
    pub superseded_unix: u64,
}

/// Push the superseded store record onto the ring, inside the caller's runtime-lock hold. A history failure
/// never fails the policy write it trails: an unreadable ring is replaced and a failed write dropped, both
/// logged, because a corrupt convenience file must not deny service to enforcement.
fn push_history_locked(lock: &ipc::RuntimeLockToken, prev: &PolicyStore) {
    let mut history = match PolicyHistory::load() {
        Ok(Some(history)) => history,
        Ok(None) => PolicyHistory::default(),
        Err(e) => {
            log_warn!(
                "policy",
                "policy history is unreadable ({e}); starting a fresh ring \
                 (history is rollback data, never authority; the policy write \
                 itself is unaffected)"
            );
            PolicyHistory::default()
        }
    };
    history.entries.push(PolicyHistoryEntry {
        baseline_b64: prev.baseline_b64.clone(),
        sig_b64: prev.sig_b64.clone(),
        key_id: prev.key_id.clone(),
        overlay: prev.overlay.clone(),
        superseded_unix: now_unix(),
    });
    evict_to_fit(&mut history);
    if let Err(e) = history.write(lock) {
        log_warn!(
            "policy",
            "policy history write failed ({e}); the policy write itself is unaffected"
        );
    }
}

/// Drop oldest entries until the ring encodes under its read cap, so the ring is never written in a
/// shape its own load refuses. An empty ring always fits.
fn evict_to_fit(history: &mut PolicyHistory) {
    while !history.entries.is_empty() && history.encode().is_err() {
        history.entries.remove(0);
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---- The write seams: the signed grant and the free restriction --------------

/// Why a policy write did not happen. Every variant leaves the store
/// untouched.
#[derive(Debug)]
pub enum PolicyWriteError {
    /// The request was malformed (empty touched set, a touched set that
    /// does not name every field the write relaxes, invalid document);
    /// refused BEFORE the presence prompt, so a bad request can never put a
    /// prompt in front of the user.
    Invalid(&'static str),
    /// Presence was not attested. Terminal, already audited.
    Refused(String),
    /// No host key exists: a grant is a signed baseline, and a keyless
    /// machine has no path to one on any surface. Promptless, audited.
    NoSigningKey,
    /// A host key record exists but the key is unusable (planted, malformed,
    /// or its store unreachable): refused rather than prompting against a
    /// suspect key. Promptless, audited.
    KeyUnusable(String),
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
            PolicyWriteError::Refused(e) => write!(f, "policy grant refused: {e}"),
            PolicyWriteError::NoSigningKey => write!(
                f,
                "no host key on this machine; a policy grant is a signed baseline \
                 and refuses without one (pair first)"
            ),
            PolicyWriteError::KeyUnusable(e) => write!(
                f,
                "the host key is unusable ({e}); refusing to sign a policy grant \
                 (run `chromium-bridge pair --reset` to replace it)"
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

/// Write a new signed policy baseline, the one grant path every editing surface shares; `restrict` is the free
/// lane. `attest` is the surface's presence prompt (today the typed phrase on the CLI's terminal), run only after
/// the request validated and the host key was found, so a malformed request or a
/// keyless machine never puts a prompt in front of the user; the host key then signs the exact document bytes.
/// ```text
/// presence refused       -> terminal, never downgraded to a softer prompt
/// no host key            -> refused (`NoSigningKey`): the grant exists only as the signature, so a keyless
///                           machine has no baseline-writing path on any surface
/// retained overlay       -> survives minus its entries on the `touched` fields, which the attestation covers
///                           (the touched set travels inside the signed bytes)
/// ```
/// Returns the presence path that authorized the write. Every outcome past validation is audited,
/// log-after-decide, outside the lock.
pub fn set_signed(
    values: PolicyValues,
    touched: Vec<PolicyField>,
    surface: crate::audit::Surface,
    attest: impl FnOnce() -> Result<PresenceAttestation, PresenceError>,
) -> Result<PresencePath, PolicyWriteError> {
    if touched.is_empty() {
        return Err(PolicyWriteError::Invalid(
            "the touched set is empty (a write must name the fields it edits)",
        ));
    }
    // The pre-prompt observation the user's tap covers (PrePromptObservation), read before the prompt and
    // failing closed on an unreadable record: no sheet for a write that cannot land.
    let host_key_epoch = crate::trust::TrustState::current()
        .map_err(PolicyWriteError::Io)?
        .host_key_epoch();
    let (store_observation, baseline_anchor, effective_anchor) =
        match PolicyStore::load().map_err(PolicyWriteError::Io)? {
            Some(store) => {
                let doc = store.baseline_doc().map_err(PolicyWriteError::Io)?;
                // effective() direction-checks the fold: a tampered store refuses here instead of anchoring
                // the relaxation checks on values nobody vouched for.
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
            // No store: the anchor is the deny baseline the extension enforces, so a first write's grants
            // are relaxations against it and must be named in `touched`.
            None => (None, PolicyValues::default(), PolicyValues::default()),
        };
    let observed = PrePromptObservation {
        store: store_observation,
        host_key_epoch,
    };
    let revision = next_revision(observed.store.as_ref().map(|o| o.revision))?;
    // Untouched fields carry BASELINE values: every retained overlay entry was written at-or-under the old
    // baseline value and stays there only if those values carry, so a departure in either direction is an
    // unnamed edit, refused promptless.
    if PolicyField::ALL
        .iter()
        .any(|f| !touched.contains(f) && field_differs(*f, &values, &baseline_anchor))
    {
        return Err(PolicyWriteError::Invalid(
            "an untouched field departs from the current baseline (the signed document \
             carries baseline values on fields it does not touch)",
        ));
    }
    // Every field this write relaxes must be in `touched`, or the signed set under-states what the tap granted.
    // The anchor is the post-write EFFECTIVE policy, the same fold the extension's ratchet compares: a surviving
    // overlay entry still covers the baseline bytes beneath it.
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
    // Serialized ONCE: these exact bytes are what the signature signs and what the store persists.
    let doc_bytes = serde_json::to_vec(&doc)
        .map_err(io::Error::from)
        .map_err(PolicyWriteError::Io)?;

    let refused = |detail: String| {
        crate::audit::record(
            crate::audit::AuditRecord::new(crate::audit::AuditKind::PolicyWrite)
                .surface(surface)
                .outcome("refused")
                .detail(&format!("{detail}; touched={}", wire_name_list(&touched))),
        );
    };
    let key = match EnrollmentKey::lookup() {
        Ok(Some(key)) => key,
        Ok(None) => {
            refused("no signing key".into());
            return Err(PolicyWriteError::NoSigningKey);
        }
        Err(e) => {
            refused(format!("host key unusable: {e}"));
            return Err(PolicyWriteError::KeyUnusable(e.to_string()));
        }
    };
    let key_id = key.public_key().fingerprint_hex();
    let auth = attest().map_err(|e| {
        // The refusal has already happened; the no-downgrade rule makes it terminal, never a floor.
        refused(format!("presence: {e}"));
        PolicyWriteError::Refused(e.to_string())
    })?;
    let sig = key.sign_policy(&doc_bytes).map_err(|e| {
        refused(format!("signing: {e}"));
        PolicyWriteError::KeyUnusable(e.to_string())
    })?;
    commit_signed_baseline(
        observed,
        &doc_bytes,
        base64_encode(&sig),
        key_id,
        &touched,
        surface,
        auth,
    )
}

/// The store half of a [`PrePromptObservation`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct StoreObservation {
    revision: u64,
    overlay: Option<PolicyOverlay>,
}

/// What [`set_signed`] observed before its prompt. The locked write refuses with [`PolicyWriteError::Conflict`]
/// when any of it moved, since landing the signed bytes over another store would silently discard that write.
///
/// ```text
/// baseline revision  -> a concurrent signed write
/// overlay            -> a restrict landing mid-prompt
/// host-key epoch     -> a disposal completing mid-prompt; it clears the baseline, so a first write sees no store
///                       before AND after and the store half alone would land a baseline signed by a dead key
/// ```
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
/// section). Consumes the attestation: one tap, one write.
fn commit_signed_baseline(
    observed: PrePromptObservation,
    doc_bytes: &[u8],
    sig_b64: String,
    key_id: String,
    touched: &[PolicyField],
    surface: crate::audit::Surface,
    auth: PresenceAttestation,
) -> Result<PresencePath, PolicyWriteError> {
    let rung = auth.path().clone();
    let result = match ipc::with_runtime_lock(|lock| {
        Ok(write_baseline_locked(
            lock, observed, doc_bytes, sig_b64, key_id, touched,
        ))
    }) {
        Ok(inner) => inner,
        Err(e) => Err(PolicyWriteError::Io(e)),
    };
    // Fifteen wire names fit well inside audit.rs's per-field truncation
    // bound.
    let record = crate::audit::AuditRecord::new(crate::audit::AuditKind::PolicyWrite)
        .surface(surface)
        .detail(&format!(
            "auth={}; touched={}",
            rung.audit_label(),
            wire_name_list(touched)
        ));
    match &result {
        Ok(()) => crate::audit::record(record.outcome("ok")),
        Err(e) => crate::audit::record(record.outcome("error").detail(&format!(
            "auth={}; touched={}; write refused: {e}",
            rung.audit_label(),
            wire_name_list(touched)
        ))),
    }
    result.map(|()| rung)
}

/// The critical section of a grant write; the re-check is the [`PrePromptObservation`] guard.
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
    sig_b64: String,
    key_id: String,
    touched: &[PolicyField],
) -> Result<(), PolicyWriteError> {
    let host_key_epoch = crate::trust::TrustState::current()
        .map_err(PolicyWriteError::Io)?
        .host_key_epoch();
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
        baseline_b64: base64_encode(doc_bytes),
        sig_b64: Some(sig_b64),
        key_id: Some(key_id),
        overlay: normalize_overlay(overlay),
    };
    next.write(lock).map_err(PolicyWriteError::Io)?;
    bump_policy_epoch_locked(lock);
    if let Some(prev) = &prev {
        push_history_locked(lock, prev);
    }
    Ok(())
}

/// Apply an unsigned restriction overlay, the free lane: restrictions only remove capability, and failing
/// closed is the direction every forgery is allowed to point, so no attestation is taken.
///
/// ```text
/// merge                  -> entry-wise over the stored overlay; a present entry wins
/// merged result          -> must restrict-or-hold the CURRENT EFFECTIVE policy, field by field
/// "undo" of an earlier restriction -> relaxes the effective policy: refused, the signed lane's business
/// ```
pub fn restrict(
    overlay: PolicyOverlay,
    surface: crate::audit::Surface,
) -> Result<(), PolicyWriteError> {
    let restricted = wire_name_list(&overlay_present_fields(&overlay));
    let result = match ipc::with_runtime_lock(|lock| Ok(restrict_locked(lock, overlay))) {
        Ok(inner) => inner,
        Err(e) => Err(PolicyWriteError::Io(e)),
    };
    // auth=none: the trail must never suggest a presence rung vouched for a free write. The promptless
    // preconditions (NoBaseline, Invalid) stay unaudited.
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

/// The critical section of [`restrict`]; history trails the store write as in [`write_baseline_locked`].
fn restrict_locked(
    lock: &ipc::RuntimeLockToken,
    overlay: PolicyOverlay,
) -> Result<(), PolicyWriteError> {
    let Some(prev) = PolicyStore::load().map_err(PolicyWriteError::Io)? else {
        return Err(PolicyWriteError::NoBaseline);
    };
    let baseline = prev.baseline_doc().map_err(PolicyWriteError::Io)?.values();
    let stored = prev.overlay.clone().unwrap_or_default();
    // The validating read, not a raw fold: a restriction over a tampered store would write a fresh record
    // over evidence.
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

/// Bump the trust record's policy epoch inside the caller's runtime-lock hold, so the native host's watch
/// pushes `policy_current` on its next tick. The epoch is a change notice, not authority: a failed bump loses
/// only the proactive push and is logged, never fatal to the write it trails.
fn bump_policy_epoch_locked(lock: &ipc::RuntimeLockToken) {
    if let Err(e) = crate::trust::Trust::mutate_locked(lock, crate::trust::Scope::Policy, |_| {}) {
        log_warn!(
            "policy",
            "policy written but the policy epoch bump failed ({e}); a connected \
             extension notices the change only at its next connect"
        );
    }
}

/// Clear the signed baseline on key disposal: a baseline signed by a deleted enrollment key must
/// not outlive the key. The superseded record goes onto the history ring first, where the document survives as an
/// unsigned draft to re-sign after re-pairing (the overlay travels inside that record because the store type
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
    PolicyStore::remove(lock)?;
    // A clear is a policy change like any write: on a successful bump the push drops the extension to its deny
    // baseline on the next tick; a failed bump (best-effort, logged) leaves it until its next connect.
    bump_policy_epoch_locked(lock);
    Ok(())
}

/// The overlay a grant write leaves behind: the stored entries minus those on the `touched` fields. The
/// pre-prompt coverage check and the locked write both call this, or the check would guard a different store
/// than the one written.
fn retained_overlay(mut overlay: PolicyOverlay, touched: &[PolicyField]) -> PolicyOverlay {
    for field in touched {
        overlay.clear(*field);
    }
    overlay
}

/// The fields the overlay carries entries for, in catalogue order.
fn overlay_present_fields(overlay: &PolicyOverlay) -> Vec<PolicyField> {
    PolicyField::ALL
        .iter()
        .copied()
        .filter(|f| overlay.has(*f))
        .collect()
}

/// Merge `arg` over `stored` entry-wise: a present `arg` entry wins, an
/// absent one keeps the stored entry. Pure shape work - whether the result
/// restricts is the caller's direction check, never assumed here.
fn merge_overlay(stored: &PolicyOverlay, mut arg: PolicyOverlay) -> PolicyOverlay {
    for field in PolicyField::ALL {
        if !arg.has(*field) {
            arg.copy_entry(*field, stored);
        }
    }
    arg
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

/// Store, history, and seam tests. Every disk-touching test points the runtime dir at its own scratch directory
/// through `RuntimeDirGuard` (test_support.rs); the host key is minted into that directory's file record, and the
/// injected `attest` closures stand in for the prompt, so no test reads a terminal.
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
