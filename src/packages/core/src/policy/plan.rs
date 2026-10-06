//! The pre-prompt half of a grant, shared by every surface that can mint one (the CLI's `policy set` and
//! `policy rollback`, the options page's frames through the native host): what a request would write,
//! decided before any presence prompt, so a malformed or impossible request never puts a prompt in front
//! of the user. The write itself is [`set_signed`](super::set_signed) / [`restrict`](super::restrict).
//!
//! ```text
//! plan_grant     -> the overlay folded over the current BASELINE (never the effective policy) and the fields it
//!                   names as the touched set
//! plan_rollback  -> a past revision's effective policy diffed against the current one: nothing, a free
//!                   restriction, or a fresh signed baseline over the current one with only the changed fields
//! ```

use super::{
    field_differs, fold, restricts_or_equal, FieldKind, PolicyDoc, PolicyField, PolicyHistory,
    PolicyOverlay, PolicyStore, PolicyValues, PolicyWriteError,
};
use crate::audit::{AuditKind, AuditRecord, Surface};
use crate::enclave::base64_decode;
use crate::presence::PresenceError;
use crate::runtime_record::RuntimeRecord as _;

/// What a grant will write, as planned before any prompt: the values the baseline will carry and the fields the
/// tap is told it edits. [`prepare_grant`](super::prepare_grant) turns it into the bytes that are signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub values: PolicyValues,
    pub touched: Vec<PolicyField>,
}

impl Grant {
    /// The touched fields with their new values, in catalogue order, in the spellings the CLI's flags take, as
    /// a presence prompt shows them: `cdpMode=on,confirmGraceMs=30000,disabledTools=[page_eval,page_upload]`.
    pub fn summary(&self) -> String {
        self.touched
            .iter()
            .map(|field| {
                let value = match field.kind() {
                    FieldKind::Bool(f) => {
                        if self.values.get_bool(f) {
                            "on".to_string()
                        } else {
                            "off".to_string()
                        }
                    }
                    FieldKind::Ms(f) => self.values.get_ms(f).to_string(),
                    FieldKind::ToolSet(f) => format!("[{}]", self.values.get_tools(f).join(",")),
                };
                format!("{}={value}", field.wire_name())
            })
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// What `policy set` writes for `overlay`: the touched set is the fields the overlay names, in catalogue order,
/// and untouched fields carry the current BASELINE values, so the edits fold over the baseline, never the
/// effective policy. `Err` is the refusal as every surface reports it.
pub fn plan_grant(overlay: &PolicyOverlay) -> Result<Grant, String> {
    let touched = touched_fields(overlay);
    let base = match PolicyStore::load() {
        Ok(Some(store)) => store
            .baseline_doc()
            .map_err(|e| format!("the current baseline is unreadable ({e}); refusing"))?
            .values(),
        Ok(None) => PolicyValues::default(),
        Err(e) => return Err(format!("the policy store is unreadable ({e}); refusing")),
    };
    Ok(Grant {
        values: fold(&base, overlay),
        touched,
    })
}

/// The fields an overlay names, in catalogue order: a set's touched set.
pub fn touched_fields(overlay: &PolicyOverlay) -> Vec<PolicyField> {
    PolicyField::ALL
        .iter()
        .copied()
        .filter(|field| overlay.has(*field))
        .collect()
}

/// The grant lane's trail for a refused witness or key lookup: the same record on both surfaces, whichever
/// step refused. The promptless validity preconditions write none (store.rs says why).
pub fn audit_grant_refused(surface: Surface, touched: &[PolicyField], detail: &str) {
    crate::audit::record(
        AuditRecord::new(AuditKind::PolicyWrite)
            .surface(surface)
            .outcome("refused")
            .detail(&format!("{detail}; touched={}", wire_names(touched))),
    );
}

/// The refusal a presence gate's answer earns, audited, as the lane reports it.
pub fn refused_grant(surface: Surface, touched: &[PolicyField], e: &PresenceError) -> String {
    audit_grant_refused(surface, touched, &format!("presence: {e}"));
    PolicyWriteError::Refused(e.to_string()).to_string()
}

/// What a rollback will do, decided by diffing a past revision's effective
/// policy against the current effective policy.
#[derive(Debug, PartialEq, Eq)]
pub enum RollbackPlan {
    /// The target already equals the current effective policy.
    NoChange,
    /// The target only tightens (or holds): the free lane re-derives it as a
    /// fresh restriction overlay - no tap, no old artifact.
    Tighten {
        overlay: PolicyOverlay,
        fields: Vec<PolicyField>,
    },
    /// The target relaxes something: one signed tap mints a fresh baseline, never the old signed bytes back.
    ///
    /// ```text
    /// values   -> the CURRENT baseline with only the changed fields set to the target; the historical effective
    ///             wholesale would fold overlay-covered untouched fields into the baseline
    /// touched  -> the changed fields, a superset of the relaxed ones as the coverage check requires
    /// ```
    Relax(Grant),
}

/// Plan a rollback from `current` effective to `target` effective, over the
/// current `baseline` values. Pure and unit-testable: the tighten/relax
/// decision is exactly the direction lattice the extension recomputes, so a
/// rollback can never smuggle a relaxation into the free lane.
pub fn plan_rollback(
    target: &PolicyValues,
    current: &PolicyValues,
    baseline: &PolicyValues,
) -> RollbackPlan {
    let (overlay, fields) = diff_overlay(target, current);
    if fields.is_empty() {
        RollbackPlan::NoChange
    } else if restricts_or_equal(target, current) {
        RollbackPlan::Tighten { overlay, fields }
    } else {
        let mut values = baseline.clone();
        for field in fields.iter().copied() {
            values.copy_field(field, target);
        }
        RollbackPlan::Relax(Grant {
            values,
            touched: fields,
        })
    }
}

/// An overlay carrying `target`'s value on exactly the fields where it differs
/// from `current` (under the lattice, so the tool list differs as a set),
/// plus those fields in catalogue order. Folding this overlay (free lane) or
/// minting a baseline of `target` (signed lane) both land the effective
/// policy on `target`.
fn diff_overlay(
    target: &PolicyValues,
    current: &PolicyValues,
) -> (PolicyOverlay, Vec<PolicyField>) {
    let mut overlay = PolicyOverlay::default();
    let mut fields = Vec::new();
    for field in PolicyField::ALL
        .iter()
        .copied()
        .filter(|f| field_differs(*f, target, current))
    {
        overlay.set_from(field, target);
        fields.push(field);
    }
    (overlay, fields)
}

/// Comma-joined wire names, for the plan description and the trail.
pub fn wire_names(fields: &[PolicyField]) -> String {
    fields
        .iter()
        .map(|f| f.wire_name())
        .collect::<Vec<_>>()
        .join(",")
}

/// The three effective/baseline states a rollback is planned over.
pub struct RollbackInputs {
    /// The target revision's effective policy, re-derived from the history.
    pub target: PolicyValues,
    /// The current effective policy.
    pub current: PolicyValues,
    /// The current baseline's values (what a relaxing plan folds over).
    pub baseline: PolicyValues,
}

impl RollbackInputs {
    pub fn plan(&self) -> RollbackPlan {
        plan_rollback(&self.target, &self.current, &self.baseline)
    }
}

/// The disk reads behind a rollback, output-free so every surface shares one path and one set of refusals.
pub fn rollback_inputs(revision: u64) -> Result<RollbackInputs, String> {
    let history = match PolicyHistory::load() {
        Ok(Some(h)) => h,
        Ok(None) => return Err("there is no policy history on this machine.".to_string()),
        Err(e) => return Err(format!("the policy history is unreadable ({e}).")),
    };
    let target = find_history_effective(&history, revision)?;
    let (current, baseline) = match PolicyStore::load() {
        Ok(Some(store)) => match (store.effective(), store.baseline_doc()) {
            (Ok(effective), Ok(doc)) => (effective, doc.values()),
            (Err(e), _) | (_, Err(e)) => {
                return Err(format!(
                    "the current baseline is unreadable ({e}); refusing"
                ));
            }
        },
        Ok(None) => {
            return Err("there is no current policy baseline to roll back from; \
                 sign one first with `chromium-bridge policy set`."
                .to_string());
        }
        Err(e) => return Err(format!("the policy store is unreadable ({e}); refusing")),
    };
    Ok(RollbackInputs {
        target,
        current,
        baseline,
    })
}

/// The effective policy of the history entry at `revision`, folding that
/// record's baseline and overlay. Unreadable ring entries are skipped (never
/// fatal); a miss names the revisions that ARE available. A revision can
/// appear more than once (every restriction while it was current pushed an
/// entry at the unchanged baseline revision): identical effective states are
/// fine, but differing ones are refused as ambiguous rather than silently
/// picking one - a rollback must land exactly the state the user asked for.
fn find_history_effective(history: &PolicyHistory, revision: u64) -> Result<PolicyValues, String> {
    let mut available = Vec::new();
    let mut matches: Vec<PolicyValues> = Vec::new();
    for entry in &history.entries {
        let Ok(doc) = decode_entry_doc(&entry.baseline_b64) else {
            continue;
        };
        if !available.contains(&doc.revision) {
            available.push(doc.revision);
        }
        if doc.revision == revision {
            let overlay = entry.overlay.clone().unwrap_or_default();
            matches.push(fold(&doc.values(), &overlay));
        }
    }
    match matches.first() {
        None => {
            let available = available
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            Err(format!(
                "no history entry at revision {revision}; available revisions: [{available}]"
            ))
        }
        Some(first) if matches.iter().all(|m| m == first) => Ok(first.clone()),
        Some(_) => Err(format!(
            "revision {revision} appears {} times in the history with different \
             effective policies (its restrictions changed while it was current), so \
             rolling back \"to revision {revision}\" is ambiguous; re-create the state \
             you want directly with `chromium-bridge policy set` / `policy restrict`.",
            matches.len()
        )),
    }
}

/// Strict-parse a stored/history baseline (base64, `deny_unknown_fields`
/// JSON, [`PolicyDoc::validate`]) - the same byte-authority discipline as
/// [`PolicyStore::baseline_doc`], reused for history entries.
pub fn decode_entry_doc(baseline_b64: &str) -> Result<PolicyDoc, String> {
    let bytes = base64_decode(baseline_b64).map_err(|e| e.to_string())?;
    let doc: PolicyDoc = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    doc.validate().map_err(str::to_string)?;
    Ok(doc)
}

#[cfg(test)]
mod tests;
