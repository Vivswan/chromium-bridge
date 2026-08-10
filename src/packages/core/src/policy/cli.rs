//! CLI runners for `chromium-bridge policy` (ADR-0032 decision 5), and the
//! versioned status/history reports the co-equal desktop app parses back.
//!
//! The two write lanes map straight onto the Phase-1 seams: `set` is the
//! signed GRANT lane ([`set_signed`] with [`PolicyGrantFloor::SignatureOnly`],
//! refused up front where no enclave key exists), `restrict` is the free lane
//! ([`restrict`]). `rollback` is neither a new lane nor a replay: it
//! re-derives a past revision's EFFECTIVE policy and re-applies it as a FRESH
//! write - the free lane when it only tightens, one signed tap when it relaxes
//! anything - so the lower revision keeps failing the extension's ratchet
//! (never the old signed artifact back on the wire).
//!
//! The reports mirror the enclave-status precedent: a versioned, typed struct
//! serialized through `serde_json::Value` (sorted keys, a frozen wire
//! contract), `deny_unknown_fields` and `ts_rs`-exported so the host that
//! emits it and the app that parses it share one Rust definition. The doctor
//! row renders from the same [`PolicyStatusReport`].

use serde::{Deserialize, Serialize};

use super::{
    fold, load_history, restrict, restricts_or_equal, set_signed, PolicyDoc, PolicyField,
    PolicyGrantFloor, PolicyHistory, PolicyOverlay, PolicyStore, PolicyValues,
};
use crate::audit::Surface;
use crate::cli::{policy_args, PolicyCommand};
use crate::enclave::{base64_decode, EnclaveError, EnrollmentKey};

// ---- The reports (typed, versioned, ts_rs-exported) -------------------------

/// The store state a status report distinguishes. `none` is the pre-cutover
/// state and is HEALTHY - it is not an error (the extension enforces the deny
/// baseline until a first policy signs). `error` is a present-but-unreadable
/// store, which fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(rename_all = "lowercase")]
pub enum PolicyStoreState {
    /// No policy baseline on this machine yet (pre-cutover; deny baseline).
    None,
    /// A baseline exists and parsed.
    Present,
    /// The store is present but unreadable (corrupt, oversized, wrong
    /// version, or an undecodable baseline): fail closed.
    Error,
}

/// The versioned, machine-readable policy status: the exact object
/// `chromium-bridge policy show --json` prints (ADR-0032), the typed mirror
/// the desktop app parses back, and the shape the doctor row renders from.
///
/// The wire form is frozen: a consumer refuses an unrecognized `v` before it
/// trusts any other field, so field names and `v` must not change without a
/// version bump. `deny_unknown_fields` makes an unexpected shape a loud
/// refusal on the parsing side. The fields below carry data only when the
/// store is `present`; `detail` only when it is `error`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(deny_unknown_fields)]
pub struct PolicyStatusReport {
    /// Schema version. `1` today; a newer value must be refused before any
    /// field below is read (fail closed).
    pub v: u32,
    /// The store's state.
    pub store: PolicyStoreState,
    /// The signed baseline's monotonic revision; present only when
    /// `store == present`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub revision: Option<u64>,
    /// Whether the stored baseline carries an enclave signature (`true`) or is
    /// an app-floor UNSIGNED baseline (`false`). Present only when
    /// `store == present`. Host-side this is only "a signature is stored" -
    /// the host never self-certifies; the extension verifies it against its
    /// pinned key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub signed: Option<bool>,
    /// Whether an unsigned restriction overlay is active on top of the
    /// baseline. Present only when `store == present`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub overlay_active: Option<bool>,
    /// The effective policy: the baseline with the overlay folded over it -
    /// what the bridge actually enforces. Present only when `store == present`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub effective: Option<PolicyValues>,
    /// Human detail for a `store == error` state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub detail: Option<String>,
}

impl PolicyStatusReport {
    /// The pre-cutover no-baseline report (healthy).
    fn none() -> Self {
        PolicyStatusReport {
            v: 1,
            store: PolicyStoreState::None,
            revision: None,
            signed: None,
            overlay_active: None,
            effective: None,
            detail: None,
        }
    }

    /// The fail-closed unreadable-store report.
    fn error(detail: String) -> Self {
        PolicyStatusReport {
            v: 1,
            store: PolicyStoreState::Error,
            revision: None,
            signed: None,
            overlay_active: None,
            effective: None,
            detail: Some(detail),
        }
    }
}

/// The versioned policy-history report: the superseded-revision ring, oldest
/// first, as `chromium-bridge policy history --json` prints it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(deny_unknown_fields)]
pub struct PolicyHistoryReport {
    /// Schema version.
    pub v: u32,
    pub entries: Vec<PolicyHistoryEntryReport>,
}

/// One superseded record, reduced to what a rollback surface needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(deny_unknown_fields)]
pub struct PolicyHistoryEntryReport {
    /// The record's baseline revision, or `null` if that historical baseline
    /// is unreadable (a damaged ring entry never blocks the report).
    pub revision: Option<u64>,
    /// Whether the superseded baseline carried a signature.
    pub signed: bool,
    /// Whether it carried a restriction overlay.
    pub overlay_active: bool,
    /// Unix seconds when the record stopped being the current store.
    pub superseded_unix: u64,
}

// ---- Gathering (I/O) and pure builders --------------------------------------

/// The current policy status, read fail-closed from the store. Infallible: an
/// unreadable store becomes the `error` state, never a panic or a silent
/// default. Public so the doctor row shares exactly this read (ADR-0032
/// decision 5: the CLI reports and doctor reports the same state).
pub fn gather_policy_status() -> PolicyStatusReport {
    match PolicyStore::load() {
        Ok(None) => PolicyStatusReport::none(),
        Ok(Some(store)) => status_from_store(&store),
        Err(e) => PolicyStatusReport::error(e.to_string()),
    }
}

/// Build a status report from a loaded store (pure: no disk). The baseline
/// bytes are decoded and the overlay direction-checked here (both via
/// [`PolicyStore::effective`]), so a store whose envelope loaded but whose
/// content is damaged or tampered surfaces as `error` - the same fail-closed
/// reading the dispatch gate and the `policy_current` push apply.
fn status_from_store(store: &PolicyStore) -> PolicyStatusReport {
    match (store.baseline_doc(), store.effective()) {
        (Err(e), _) | (_, Err(e)) => PolicyStatusReport::error(e.to_string()),
        (Ok(doc), Ok(effective)) => PolicyStatusReport {
            v: 1,
            store: PolicyStoreState::Present,
            revision: Some(doc.revision),
            signed: Some(store.sig_b64.is_some()),
            overlay_active: Some(store.overlay.is_some()),
            effective: Some(effective),
            detail: None,
        },
    }
}

/// The history report, read fail-closed. `Err` only when the ring itself is
/// unreadable; an absent ring is the empty report.
fn gather_history_report() -> Result<PolicyHistoryReport, String> {
    match load_history().map_err(|e| e.to_string())? {
        None => Ok(PolicyHistoryReport {
            v: 1,
            entries: Vec::new(),
        }),
        Some(history) => Ok(history_report(&history)),
    }
}

/// Build a history report from a loaded ring (pure: no disk). A ring entry
/// whose baseline is unreadable keeps its slot with a `null` revision.
fn history_report(history: &PolicyHistory) -> PolicyHistoryReport {
    PolicyHistoryReport {
        v: 1,
        entries: history
            .entries
            .iter()
            .map(|e| PolicyHistoryEntryReport {
                revision: decode_entry_doc(&e.baseline_b64).ok().map(|d| d.revision),
                signed: e.sig_b64.is_some(),
                overlay_active: e.overlay.is_some(),
                superseded_unix: e.superseded_unix,
            })
            .collect(),
    }
}

/// Strict-parse a stored/history baseline (base64, `deny_unknown_fields`
/// JSON, [`PolicyDoc::validate`]) - the same byte-authority discipline as
/// [`PolicyStore::baseline_doc`], reused for history entries.
fn decode_entry_doc(baseline_b64: &str) -> Result<PolicyDoc, String> {
    let bytes = base64_decode(baseline_b64).map_err(|e| e.to_string())?;
    let doc: PolicyDoc = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    doc.validate().map_err(str::to_string)?;
    Ok(doc)
}

// ---- Rendering (pure) -------------------------------------------------------

/// The human `policy show` text.
fn render_status(r: &PolicyStatusReport) -> String {
    let mut out = String::from("chromium-bridge policy\n");
    match r.store {
        PolicyStoreState::None => {
            out.push_str(
                "store:      none yet (pre-cutover; the deny baseline is enforced until a\n            \
                 baseline is signed via the app or `chromium-bridge policy set`)\n",
            );
        }
        PolicyStoreState::Error => {
            out.push_str(&format!(
                "store:      present but UNREADABLE ({}) - failing closed\n",
                r.detail.as_deref().unwrap_or("unknown")
            ));
        }
        PolicyStoreState::Present => {
            out.push_str(&format!(
                "store:      present (revision {})\n",
                r.revision.unwrap_or(0)
            ));
            out.push_str(&format!("baseline:   {}\n", signed_line(r.signed)));
            out.push_str(&format!(
                "overlay:    {}\n",
                if r.overlay_active.unwrap_or(false) {
                    "restriction overlay active"
                } else {
                    "none"
                }
            ));
            if let Some(values) = &r.effective {
                out.push_str("effective policy:\n");
                out.push_str(&render_values(values));
            }
        }
    }
    out
}

/// The signed/unsigned line, never claiming host-side verification (the
/// extension verifies against its pinned key; this binary cannot).
fn signed_line(signed: Option<bool>) -> &'static str {
    match signed {
        Some(true) => {
            "signed (the extension verifies it against its pinned key; not verifiable here)"
        }
        Some(false) => "unsigned (app-floor baseline)",
        None => "unknown",
    }
}

/// The effective values, one field per line in catalogue order.
fn render_values(v: &PolicyValues) -> String {
    let mut out = String::new();
    let mut bool_row = |name: &str, value: bool| {
        out.push_str(&format!(
            "  {name:<22} {}\n",
            if value { "on" } else { "off" }
        ));
    };
    bool_row("cdpMode", v.cdp_mode);
    bool_row("fileUploadEnabled", v.file_upload_enabled);
    bool_row("handleDialogEnabled", v.handle_dialog_enabled);
    bool_row("pageEvalEnabled", v.page_eval_enabled);
    bool_row("confirmHighRiskClick", v.confirm_high_risk_click);
    bool_row("confirmPageEval", v.confirm_page_eval);
    bool_row("touchIdConfirm", v.touch_id_confirm);
    bool_row("confirmTabClose", v.confirm_tab_close);
    bool_row("warnPreciseSnapshot", v.warn_precise_snapshot);
    bool_row("evalMask", v.eval_mask);
    out.push_str(&format!(
        "  {:<22} {}\n",
        "hostReverifyMs", v.host_reverify_ms
    ));
    out.push_str(&format!(
        "  {:<22} {}\n",
        "confirmGraceMs", v.confirm_grace_ms
    ));
    out.push_str(&format!(
        "  {:<22} {}\n",
        "clickToastTimeoutMs", v.click_toast_timeout_ms
    ));
    out.push_str(&format!(
        "  {:<22} {}\n",
        "evalToastTimeoutMs", v.eval_toast_timeout_ms
    ));
    out.push_str(&format!(
        "  {:<22} {}\n",
        "disabledTools",
        if v.disabled_tools.is_empty() {
            "(none)".to_string()
        } else {
            v.disabled_tools.join(",")
        }
    ));
    out
}

/// The human `policy history` text.
fn render_history(r: &PolicyHistoryReport) -> String {
    if r.entries.is_empty() {
        return "chromium-bridge policy history\n  (empty)\n".to_string();
    }
    let mut out = String::from("chromium-bridge policy history (oldest first)\n");
    for e in &r.entries {
        let revision = e
            .revision
            .map(|n| n.to_string())
            .unwrap_or_else(|| "?".to_string());
        out.push_str(&format!(
            "  revision {revision:<6} {} {} superseded_unix={}\n",
            if e.signed { "signed  " } else { "unsigned" },
            if e.overlay_active {
                "overlay"
            } else {
                "no-overlay"
            },
            e.superseded_unix,
        ));
    }
    out
}

// ---- The signature-only grant gate (ADR-0032 decision 5) --------------------

/// The enrollment-key lookup reduced to the states the grant gate branches
/// on, so [`grant_key_gate`] is pure and unit-testable without the keychain.
enum GrantKey {
    /// A usable enrollment key exists: the signature path is available.
    Present,
    /// No key on this machine (macOS, unenrolled): refuse (pair first).
    Absent,
    /// No Secure Enclave at all (non-macOS): refuse (no grant surface here).
    Unsupported,
    /// A key exists but is unusable (planted/malformed/keychain error):
    /// refuse rather than raise a prompt against a suspect key.
    Unusable(String),
}

/// Decide whether the CLI's signature-only grant path may proceed (ADR-0032
/// decision 5), BEFORE any prompt could appear. Pure: the up-front refusal
/// gives a clear message; the seam's own `SignatureOnly` `NoSigningKey` is the
/// belt-and-suspenders behind it. This is the deliberate exception to
/// ADR-0031's ladder - the CLI grant path has NO interactive floor, so where
/// no key exists it refuses outright rather than writing an unsigned baseline.
fn grant_key_gate(key: GrantKey) -> Result<(), String> {
    match key {
        GrantKey::Present => Ok(()),
        GrantKey::Absent => Err(
            "no enrollment key on this machine; the CLI's policy grant path is \
             signature-only and refuses (ADR-0032 decision 5). Run `chromium-bridge pair` \
             first, or grant through the desktop app (its interactive floor can store an \
             unsigned baseline on an unenrolled Mac)."
                .to_string(),
        ),
        GrantKey::Unsupported => Err(
            "this platform has no Secure Enclave, so a policy grant cannot be signed and the \
             CLI refuses (non-macOS ships no grant surface, ADR-0032 decision 8)."
                .to_string(),
        ),
        GrantKey::Unusable(e) => Err(format!(
            "the enrollment key is unusable ({e}); refusing to sign a policy grant. \
             Run `chromium-bridge pair --reset` to replace it."
        )),
    }
}

/// The keychain lookup behind [`grant_key_gate`]. Never reached by unit tests
/// (they drive `grant_key_gate` directly), so no test touches the real
/// keychain; on non-macOS this is always `Unsupported`.
fn require_grant_key() -> Result<(), String> {
    let key = match EnrollmentKey::lookup() {
        Ok(Some(_)) => GrantKey::Present,
        Ok(None) => GrantKey::Absent,
        Err(EnclaveError::Unsupported) => GrantKey::Unsupported,
        Err(e) => GrantKey::Unusable(e.to_string()),
    };
    grant_key_gate(key)
}

// ---- Rollback planning (pure) -----------------------------------------------

/// What a rollback will do, decided by diffing a past revision's effective
/// policy against the current effective policy (ADR-0032 rollback rule).
#[derive(Debug, PartialEq, Eq)]
enum RollbackPlan {
    /// The target already equals the current effective policy.
    NoChange,
    /// The target only tightens (or holds): the free lane re-derives it as a
    /// fresh restriction overlay - no tap, no old artifact.
    Tighten {
        overlay: PolicyOverlay,
        fields: Vec<PolicyField>,
    },
    /// The target relaxes something: one signed tap mints a fresh baseline -
    /// the CURRENT baseline with only the changed fields set to the target
    /// (decision 3: the signed document carries baseline values on fields it
    /// does not touch), the changed fields as its touched set (a superset of
    /// the relaxed fields, which is what the coverage check requires). NEVER
    /// the old signed bytes back, and never the historical effective
    /// wholesale (that would silently fold overlay-covered untouched fields
    /// into the baseline).
    Relax {
        values: PolicyValues,
        touched: Vec<PolicyField>,
        fields: Vec<PolicyField>,
    },
}

/// Plan a rollback from `current` effective to `target` effective, over the
/// current `baseline` values. Pure and unit-testable: the tighten/relax
/// decision is exactly the direction lattice the extension recomputes, so a
/// rollback can never smuggle a relaxation into the free lane.
fn plan_rollback(
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
            set_value_to_target(&mut values, field, target);
        }
        RollbackPlan::Relax {
            values,
            touched: fields.clone(),
            fields,
        }
    }
}

/// An overlay carrying `target`'s value on exactly the fields where it differs
/// from `current`, plus those fields in catalogue order. Folding this overlay
/// (free lane) or minting a baseline of `target` (signed lane) both land the
/// effective policy on `target`. Exhaustive with no wildcard: a new policy
/// field fails to compile until it says how it diffs.
fn diff_overlay(
    target: &PolicyValues,
    current: &PolicyValues,
) -> (PolicyOverlay, Vec<PolicyField>) {
    let mut overlay = PolicyOverlay::default();
    let mut fields = Vec::new();
    for field in PolicyField::ALL.iter().copied() {
        let differs = match field {
            PolicyField::CdpMode => target.cdp_mode != current.cdp_mode,
            PolicyField::FileUploadEnabled => {
                target.file_upload_enabled != current.file_upload_enabled
            }
            PolicyField::HandleDialogEnabled => {
                target.handle_dialog_enabled != current.handle_dialog_enabled
            }
            PolicyField::PageEvalEnabled => target.page_eval_enabled != current.page_eval_enabled,
            PolicyField::ConfirmHighRiskClick => {
                target.confirm_high_risk_click != current.confirm_high_risk_click
            }
            PolicyField::ConfirmPageEval => target.confirm_page_eval != current.confirm_page_eval,
            PolicyField::TouchIdConfirm => target.touch_id_confirm != current.touch_id_confirm,
            PolicyField::ConfirmTabClose => target.confirm_tab_close != current.confirm_tab_close,
            PolicyField::WarnPreciseSnapshot => {
                target.warn_precise_snapshot != current.warn_precise_snapshot
            }
            PolicyField::EvalMask => target.eval_mask != current.eval_mask,
            PolicyField::HostReverifyMs => target.host_reverify_ms != current.host_reverify_ms,
            PolicyField::ConfirmGraceMs => target.confirm_grace_ms != current.confirm_grace_ms,
            PolicyField::ClickToastTimeoutMs => {
                target.click_toast_timeout_ms != current.click_toast_timeout_ms
            }
            PolicyField::EvalToastTimeoutMs => {
                target.eval_toast_timeout_ms != current.eval_toast_timeout_ms
            }
            PolicyField::DisabledTools => {
                tools_differ(&target.disabled_tools, &current.disabled_tools)
            }
        };
        if differs {
            set_overlay_to_target(&mut overlay, field, target);
            fields.push(field);
        }
    }
    (overlay, fields)
}

/// Whether two disabled-tool lists differ as SETS (order and duplicates carry
/// no meaning, matching the direction table's set semantics).
fn tools_differ(a: &[String], b: &[String]) -> bool {
    !(a.iter().all(|t| b.contains(t)) && b.iter().all(|t| a.contains(t)))
}

/// Copy `target`'s value for `field` into `values`. Exhaustive, same reason
/// as [`diff_overlay`].
fn set_value_to_target(values: &mut PolicyValues, field: PolicyField, target: &PolicyValues) {
    match field {
        PolicyField::CdpMode => values.cdp_mode = target.cdp_mode,
        PolicyField::FileUploadEnabled => values.file_upload_enabled = target.file_upload_enabled,
        PolicyField::HandleDialogEnabled => {
            values.handle_dialog_enabled = target.handle_dialog_enabled
        }
        PolicyField::PageEvalEnabled => values.page_eval_enabled = target.page_eval_enabled,
        PolicyField::ConfirmHighRiskClick => {
            values.confirm_high_risk_click = target.confirm_high_risk_click
        }
        PolicyField::ConfirmPageEval => values.confirm_page_eval = target.confirm_page_eval,
        PolicyField::TouchIdConfirm => values.touch_id_confirm = target.touch_id_confirm,
        PolicyField::ConfirmTabClose => values.confirm_tab_close = target.confirm_tab_close,
        PolicyField::WarnPreciseSnapshot => {
            values.warn_precise_snapshot = target.warn_precise_snapshot
        }
        PolicyField::EvalMask => values.eval_mask = target.eval_mask,
        PolicyField::HostReverifyMs => values.host_reverify_ms = target.host_reverify_ms,
        PolicyField::ConfirmGraceMs => values.confirm_grace_ms = target.confirm_grace_ms,
        PolicyField::ClickToastTimeoutMs => {
            values.click_toast_timeout_ms = target.click_toast_timeout_ms
        }
        PolicyField::EvalToastTimeoutMs => {
            values.eval_toast_timeout_ms = target.eval_toast_timeout_ms
        }
        PolicyField::DisabledTools => values.disabled_tools = target.disabled_tools.clone(),
    }
}

/// Copy `target`'s value for `field` into the overlay. Exhaustive, same
/// reason as [`diff_overlay`].
fn set_overlay_to_target(overlay: &mut PolicyOverlay, field: PolicyField, target: &PolicyValues) {
    match field {
        PolicyField::CdpMode => overlay.cdp_mode = Some(target.cdp_mode),
        PolicyField::FileUploadEnabled => {
            overlay.file_upload_enabled = Some(target.file_upload_enabled)
        }
        PolicyField::HandleDialogEnabled => {
            overlay.handle_dialog_enabled = Some(target.handle_dialog_enabled)
        }
        PolicyField::PageEvalEnabled => overlay.page_eval_enabled = Some(target.page_eval_enabled),
        PolicyField::ConfirmHighRiskClick => {
            overlay.confirm_high_risk_click = Some(target.confirm_high_risk_click)
        }
        PolicyField::ConfirmPageEval => overlay.confirm_page_eval = Some(target.confirm_page_eval),
        PolicyField::TouchIdConfirm => overlay.touch_id_confirm = Some(target.touch_id_confirm),
        PolicyField::ConfirmTabClose => overlay.confirm_tab_close = Some(target.confirm_tab_close),
        PolicyField::WarnPreciseSnapshot => {
            overlay.warn_precise_snapshot = Some(target.warn_precise_snapshot)
        }
        PolicyField::EvalMask => overlay.eval_mask = Some(target.eval_mask),
        PolicyField::HostReverifyMs => overlay.host_reverify_ms = Some(target.host_reverify_ms),
        PolicyField::ConfirmGraceMs => overlay.confirm_grace_ms = Some(target.confirm_grace_ms),
        PolicyField::ClickToastTimeoutMs => {
            overlay.click_toast_timeout_ms = Some(target.click_toast_timeout_ms)
        }
        PolicyField::EvalToastTimeoutMs => {
            overlay.eval_toast_timeout_ms = Some(target.eval_toast_timeout_ms)
        }
        PolicyField::DisabledTools => overlay.disabled_tools = Some(target.disabled_tools.clone()),
    }
}

/// Comma-joined wire names, for the plan description.
fn wire_names(fields: &[PolicyField]) -> String {
    fields
        .iter()
        .map(|f| f.wire_name())
        .collect::<Vec<_>>()
        .join(",")
}

// ---- The subcommand runners -------------------------------------------------

/// Dispatch `chromium-bridge policy <sub>` (ADR-0032 decision 5). Parses via
/// [`policy_args`] for a rich error, then runs the selected lane.
pub fn run_policy(args: &[String]) -> i32 {
    let cmd = match policy_args(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("policy: {e}");
            return 2;
        }
    };
    match cmd {
        PolicyCommand::Show { json } => run_show(json),
        PolicyCommand::History { json } => run_history(json),
        PolicyCommand::Set { overlay, touched } => run_set(overlay, touched),
        PolicyCommand::Restrict { overlay } => run_restrict(overlay),
        PolicyCommand::Rollback { revision } => run_rollback(revision),
    }
}

/// `policy show [--json]`: read-only. `--json` emits the typed report through
/// `Value` (sorted keys, the enclave-status precedent).
fn run_show(json: bool) -> i32 {
    let report = gather_policy_status();
    if json {
        match serde_json::to_value(&report) {
            Ok(value) => {
                println!("{value}");
                0
            }
            Err(e) => {
                eprintln!("policy show --json failed to serialize the report: {e}");
                1
            }
        }
    } else {
        print!("{}", render_status(&report));
        0
    }
}

/// `policy history [--json]`: read-only.
fn run_history(json: bool) -> i32 {
    match gather_history_report() {
        Ok(report) => {
            if json {
                match serde_json::to_value(&report) {
                    Ok(value) => {
                        println!("{value}");
                        0
                    }
                    Err(e) => {
                        eprintln!("policy history --json failed to serialize the report: {e}");
                        1
                    }
                }
            } else {
                print!("{}", render_history(&report));
                0
            }
        }
        Err(e) => {
            eprintln!("policy history: {e}");
            1
        }
    }
}

/// `policy set <field flags>`: the GRANT lane. The keyless refusal runs UP
/// FRONT (decision 5), before any prompt could appear and before a floor is
/// ever constructed. Untouched fields carry the current BASELINE values
/// (decision 3), so the edits fold over the baseline, never the effective
/// policy.
fn run_set(overlay: PolicyOverlay, touched: Vec<PolicyField>) -> i32 {
    if let Err(msg) = require_grant_key() {
        eprintln!("policy set: {msg}");
        return 1;
    }
    let base = match PolicyStore::load() {
        Ok(Some(store)) => match store.baseline_doc() {
            Ok(doc) => doc.values(),
            Err(e) => {
                eprintln!("policy set: the current baseline is unreadable ({e}); refusing");
                return 1;
            }
        },
        Ok(None) => PolicyValues::default(),
        Err(e) => {
            eprintln!("policy set: the policy store is unreadable ({e}); refusing");
            return 1;
        }
    };
    let values = fold(&base, &overlay);
    match set_signed(
        values,
        touched,
        Surface::Cli,
        PolicyGrantFloor::SignatureOnly,
    ) {
        Ok(rung) => {
            println!(
                "policy updated: a fresh signed baseline (authorized by {}).",
                rung.wire_name()
            );
            0
        }
        Err(e) => {
            eprintln!("policy set failed: {e}");
            1
        }
    }
}

/// `policy restrict <field flags>`: the FREE lane. Never prompts; the seam's
/// direction check refuses anything that would relax the effective policy.
fn run_restrict(overlay: PolicyOverlay) -> i32 {
    match restrict(overlay, Surface::Cli) {
        Ok(()) => {
            println!("policy restriction applied (unsigned overlay).");
            0
        }
        Err(e) => {
            eprintln!("policy restrict failed: {e}");
            1
        }
    }
}

/// `policy rollback --revision <n>`: re-derive revision `n`'s effective policy
/// and re-apply it as a FRESH write - tighten-only rides `restrict` free, any
/// relaxation is one `set_signed` tap. The old signed artifact is never
/// written back: a lower revision must keep failing the extension's ratchet.
fn run_rollback(revision: u64) -> i32 {
    let history = match load_history() {
        Ok(Some(h)) => h,
        Ok(None) => {
            eprintln!("policy rollback: there is no policy history on this machine.");
            return 1;
        }
        Err(e) => {
            eprintln!("policy rollback: the policy history is unreadable ({e}).");
            return 1;
        }
    };
    let target = match find_history_effective(&history, revision) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("policy rollback: {msg}");
            return 1;
        }
    };
    let (current, baseline) = match PolicyStore::load() {
        Ok(Some(store)) => match (store.effective(), store.baseline_doc()) {
            (Ok(effective), Ok(doc)) => (effective, doc.values()),
            (Err(e), _) | (_, Err(e)) => {
                eprintln!("policy rollback: the current baseline is unreadable ({e}); refusing");
                return 1;
            }
        },
        Ok(None) => {
            eprintln!(
                "policy rollback: there is no current policy baseline to roll back from; \
                 sign one first with `chromium-bridge policy set`."
            );
            return 1;
        }
        Err(e) => {
            eprintln!("policy rollback: the policy store is unreadable ({e}); refusing");
            return 1;
        }
    };
    match plan_rollback(&target, &current, &baseline) {
        RollbackPlan::NoChange => {
            println!(
                "policy already matches revision {revision}'s effective policy; nothing to do."
            );
            0
        }
        RollbackPlan::Tighten { overlay, fields } => {
            println!(
                "rolling back to revision {revision}: tighten-only (free) - restricting {}",
                wire_names(&fields)
            );
            match restrict(overlay, Surface::Cli) {
                Ok(()) => {
                    println!(
                        "done: a fresh restriction overlay (the old artifact is never replayed)."
                    );
                    0
                }
                Err(e) => {
                    eprintln!("policy rollback failed: {e}");
                    1
                }
            }
        }
        RollbackPlan::Relax {
            values,
            touched,
            fields,
        } => {
            println!(
                "rolling back to revision {revision}: this relaxes the effective policy \
                 ({}), so it mints a fresh signed revision (never a replay of the old \
                 artifact) and requires one Touch ID tap.",
                wire_names(&fields)
            );
            if let Err(msg) = require_grant_key() {
                eprintln!("policy rollback: {msg}");
                return 1;
            }
            match set_signed(
                values,
                touched,
                Surface::Cli,
                PolicyGrantFloor::SignatureOnly,
            ) {
                Ok(rung) => {
                    println!(
                        "done: a fresh signed revision (authorized by {}).",
                        rung.wire_name()
                    );
                    0
                }
                Err(e) => {
                    eprintln!("policy rollback failed: {e}");
                    1
                }
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::base64_encode;

    /// A `PolicyStore` seeded in memory (no disk): a baseline document over
    /// `values` at `revision`, optionally signed, with `overlay`.
    fn store(
        revision: u64,
        values: &PolicyValues,
        signed: bool,
        overlay: Option<PolicyOverlay>,
    ) -> PolicyStore {
        let doc = PolicyDoc {
            revision,
            page_eval_enabled: values.page_eval_enabled,
            cdp_mode: values.cdp_mode,
            file_upload_enabled: values.file_upload_enabled,
            handle_dialog_enabled: values.handle_dialog_enabled,
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
            ..PolicyDoc::default()
        };
        let bytes = serde_json::to_vec(&doc).unwrap();
        PolicyStore {
            version: super::super::POLICY_STORE_VERSION,
            baseline_b64: base64_encode(&bytes),
            sig_b64: signed.then(|| base64_encode(b"sig")),
            key_id: signed.then(|| "kid".to_string()),
            overlay,
        }
    }

    #[test]
    fn status_none_is_the_pre_cutover_state() {
        let r = PolicyStatusReport::none();
        assert_eq!(r.store, PolicyStoreState::None);
        assert!(r.revision.is_none());
        // The wire form omits the absent fields entirely.
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["store"], "none");
        assert!(v.get("revision").is_none());
        assert!(v.get("effective").is_none());
    }

    #[test]
    fn status_present_carries_revision_signed_overlay_and_effective() {
        let base = PolicyValues {
            page_eval_enabled: true,
            ..PolicyValues::default()
        };
        let overlay = PolicyOverlay {
            page_eval_enabled: Some(false),
            ..PolicyOverlay::default()
        };
        let r = status_from_store(&store(3, &base, true, Some(overlay)));
        assert_eq!(r.store, PolicyStoreState::Present);
        assert_eq!(r.revision, Some(3));
        assert_eq!(r.signed, Some(true));
        assert_eq!(r.overlay_active, Some(true));
        // Effective folds the overlay: pageEval restricted back off.
        assert!(!r.effective.as_ref().unwrap().page_eval_enabled);
        // The signed line never claims host-side verification.
        assert!(render_status(&r).contains("not verifiable here"));
    }

    #[test]
    fn status_of_a_damaged_baseline_is_error_not_a_default() {
        let mut s = store(1, &PolicyValues::default(), false, None);
        s.baseline_b64 = "not base64!".into();
        let r = status_from_store(&s);
        assert_eq!(r.store, PolicyStoreState::Error);
        assert!(r.detail.is_some());
        // An unsigned baseline reads as unsigned, never "invalid".
        let unsigned = status_from_store(&store(1, &PolicyValues::default(), false, None));
        assert_eq!(unsigned.signed, Some(false));
        assert!(render_status(&unsigned).contains("unsigned"));
    }

    #[test]
    fn status_report_round_trips_and_rejects_unknown_fields() {
        let r = status_from_store(&store(2, &PolicyValues::default(), true, None));
        let json = serde_json::to_string(&r).unwrap();
        let back: PolicyStatusReport = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
        // deny_unknown_fields is the app's fail-closed guard.
        let bad = r#"{"v":1,"store":"none","surprise":1}"#;
        assert!(serde_json::from_str::<PolicyStatusReport>(bad).is_err());
    }

    #[test]
    fn history_report_maps_entries_and_tolerates_a_damaged_one() {
        use super::super::{PolicyHistoryEntry, POLICY_HISTORY_VERSION};
        let good = PolicyDoc {
            revision: 5,
            ..PolicyDoc::default()
        };
        let history = PolicyHistory {
            version: POLICY_HISTORY_VERSION,
            entries: vec![
                PolicyHistoryEntry {
                    baseline_b64: base64_encode(&serde_json::to_vec(&good).unwrap()),
                    sig_b64: Some(base64_encode(b"s")),
                    key_id: None,
                    overlay: Some(PolicyOverlay {
                        page_eval_enabled: Some(false),
                        ..PolicyOverlay::default()
                    }),
                    superseded_unix: 111,
                },
                PolicyHistoryEntry {
                    baseline_b64: "garbage!".into(),
                    sig_b64: None,
                    key_id: None,
                    overlay: None,
                    superseded_unix: 222,
                },
            ],
        };
        let r = history_report(&history);
        assert_eq!(r.entries[0].revision, Some(5));
        assert!(r.entries[0].signed);
        assert!(r.entries[0].overlay_active);
        // A damaged entry keeps its slot with a null revision.
        assert_eq!(r.entries[1].revision, None);
        assert!(!r.entries[1].signed);
        assert_eq!(r.entries[1].superseded_unix, 222);
    }

    #[test]
    fn grant_gate_refuses_every_keyless_state_with_a_clear_message() {
        // The security-critical decision 5 mapping, driven purely (never the
        // real keychain): only a present key proceeds.
        assert!(grant_key_gate(GrantKey::Present).is_ok());
        assert!(grant_key_gate(GrantKey::Absent)
            .unwrap_err()
            .contains("signature-only"));
        assert!(grant_key_gate(GrantKey::Unsupported)
            .unwrap_err()
            .contains("no Secure Enclave"));
        assert!(grant_key_gate(GrantKey::Unusable("planted".into()))
            .unwrap_err()
            .contains("unusable"));
    }

    #[test]
    fn a_no_op_rollback_changes_nothing() {
        let v = PolicyValues::default();
        assert_eq!(plan_rollback(&v, &v, &v), RollbackPlan::NoChange);
    }

    #[test]
    fn a_tightening_rollback_uses_the_free_lane() {
        // current has pageEval ON; target (a past revision) has it OFF: rolling
        // back only tightens, so it rides the free restrict lane.
        let current = PolicyValues {
            page_eval_enabled: true,
            ..PolicyValues::default()
        };
        let target = PolicyValues::default();
        match plan_rollback(&target, &current, &current) {
            RollbackPlan::Tighten { overlay, fields } => {
                assert_eq!(fields, vec![PolicyField::PageEvalEnabled]);
                assert_eq!(overlay.page_eval_enabled, Some(false));
                // Folding the diff overlay over current lands exactly on target.
                assert_eq!(fold(&current, &overlay), target);
            }
            other => panic!("expected Tighten, got {other:?}"),
        }
    }

    #[test]
    fn a_relaxing_rollback_takes_the_signed_lane_with_the_changed_fields_touched() {
        // The current baseline and effective differ on confirmGraceMs (a
        // restriction overlay holds it at 30000 under a 45000 baseline).
        // Target (past revision) relaxes pageEval and evalMask but leaves
        // confirmGraceMs at its current effective value, so the plan must
        // build the fresh baseline over the CURRENT baseline - never the
        // historical effective wholesale - with only the changed fields
        // touched.
        let baseline = PolicyValues {
            confirm_grace_ms: 45_000,
            ..PolicyValues::default()
        };
        // The overlay restricts confirmGraceMs to 30000, so effective differs
        // from baseline on a field the rollback does NOT change.
        let current = PolicyValues {
            confirm_grace_ms: 30_000,
            ..PolicyValues::default()
        };
        let target = PolicyValues {
            page_eval_enabled: true,
            confirm_grace_ms: 30_000, // unchanged vs current effective
            eval_mask: false,         // also relax a second field
            ..PolicyValues::default()
        };
        match plan_rollback(&target, &current, &baseline) {
            RollbackPlan::Relax {
                values,
                touched,
                fields,
            } => {
                // Changed fields carry the target value; untouched fields
                // carry the BASELINE value (decision 3), so the overlay entry
                // on confirmGraceMs survives the write instead of being
                // silently folded into the signed baseline.
                assert!(values.page_eval_enabled);
                assert!(!values.eval_mask);
                assert_eq!(values.confirm_grace_ms, 45_000);
                assert!(touched.contains(&PolicyField::PageEvalEnabled));
                assert!(touched.contains(&PolicyField::EvalMask));
                assert!(!touched.contains(&PolicyField::ConfirmGraceMs));
                assert_eq!(touched, fields);
            }
            other => panic!("expected Relax, got {other:?}"),
        }
    }

    #[test]
    fn diff_overlay_treats_disabled_tools_as_a_set() {
        let a = PolicyValues {
            disabled_tools: vec!["x".into(), "y".into()],
            ..PolicyValues::default()
        };
        let b = PolicyValues {
            disabled_tools: vec!["y".into(), "x".into()],
            ..PolicyValues::default()
        };
        // Reordered but equal as sets: no diff.
        let (_, fields) = diff_overlay(&a, &b);
        assert!(fields.is_empty());
        // A genuinely different set diffs.
        let c = PolicyValues {
            disabled_tools: vec!["x".into()],
            ..PolicyValues::default()
        };
        let (_, fields) = diff_overlay(&a, &c);
        assert_eq!(fields, vec![PolicyField::DisabledTools]);
    }

    #[test]
    fn find_history_effective_folds_the_target_and_reports_misses() {
        use super::super::{PolicyHistoryEntry, POLICY_HISTORY_VERSION};
        let doc = PolicyDoc {
            revision: 4,
            page_eval_enabled: true,
            ..PolicyDoc::default()
        };
        let history = PolicyHistory {
            version: POLICY_HISTORY_VERSION,
            entries: vec![PolicyHistoryEntry {
                baseline_b64: base64_encode(&serde_json::to_vec(&doc).unwrap()),
                sig_b64: None,
                key_id: None,
                overlay: Some(PolicyOverlay {
                    page_eval_enabled: Some(false),
                    ..PolicyOverlay::default()
                }),
                superseded_unix: 1,
            }],
        };
        // The target effective folds the entry's overlay over its baseline.
        let effective = find_history_effective(&history, 4).unwrap();
        assert!(!effective.page_eval_enabled);
        // A miss names the available revisions.
        let err = find_history_effective(&history, 9).unwrap_err();
        assert!(err.contains("available revisions: [4]"));
    }

    #[test]
    fn find_history_effective_refuses_an_ambiguous_revision() {
        use super::super::{PolicyHistoryEntry, POLICY_HISTORY_VERSION};
        // Every restriction while a baseline is current pushes a history
        // entry at the UNCHANGED revision, so one revision can name several
        // distinct effective states. Rolling back must land exactly one.
        let doc = PolicyDoc {
            revision: 4,
            page_eval_enabled: true,
            ..PolicyDoc::default()
        };
        let baseline_b64 = base64_encode(&serde_json::to_vec(&doc).unwrap());
        let entry = |overlay| PolicyHistoryEntry {
            baseline_b64: baseline_b64.clone(),
            sig_b64: None,
            key_id: None,
            overlay,
            superseded_unix: 1,
        };
        let history = PolicyHistory {
            version: POLICY_HISTORY_VERSION,
            entries: vec![
                entry(None),
                entry(Some(PolicyOverlay {
                    page_eval_enabled: Some(false),
                    ..PolicyOverlay::default()
                })),
            ],
        };
        let err = find_history_effective(&history, 4).unwrap_err();
        assert!(err.contains("ambiguous"), "got: {err}");
        // Identical duplicates are NOT ambiguous: same effective state.
        let history = PolicyHistory {
            version: POLICY_HISTORY_VERSION,
            entries: vec![entry(None), entry(None)],
        };
        assert!(
            find_history_effective(&history, 4)
                .unwrap()
                .page_eval_enabled
        );
    }
}
