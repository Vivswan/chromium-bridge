//! Host-owned policy (ADR-0032): the field catalogue, the per-field
//! permissiveness directions, the comparison primitives, and the policy
//! document itself.
//!
//! This module is the Rust-canonical policy schema (decision 2): the 15
//! host-owned fields, each with a declared permissive pole so that
//! [`relaxes`] / [`restricts_or_equal`] can classify any candidate policy
//! against an anchor without trusting anyone's claim about which way a
//! change points. Decision 3 fixes the anchor: comparisons run against the
//! current EFFECTIVE policy (the signed baseline with its restriction
//! overlay applied, [`fold`]), never the baseline alone.
//!
//! The on-disk store (decision 5) and the two write seams (decision 3) live
//! in [`store`]: [`PolicyStore`] / [`PolicyHistory`] on the `Allowlist`
//! template (fail-closed loads, atomic runtime-locked writes), and
//! [`set_signed`] / [`restrict`], the only mutation paths every editing
//! surface shares. The host-side dispatch gate (decision 4) lives in
//! [`gating`]: the tool-to-grant table and the pure verdict the MCP handler
//! injects before any bridge traffic. Deliberately absent here, owned
//! elsewhere: the signing domain and the sign-as-presence primitive
//! ([`crate::presence::sign_policy_as_presence`]) and the control frames
//! that carry the document (`crate::protocol`).

mod cli;
mod store;

pub mod gating;

pub use cli::{
    gather_history_report, gather_policy_status, run_policy, PolicyErrorReport,
    PolicyHistoryEntryReport, PolicyHistoryReport, PolicyStatusReport, PolicyStoreState,
};
pub use store::{
    clear_baseline_locked, load_history, restrict, set_signed, PolicyGrantFloor, PolicyHistory,
    PolicyHistoryEntry, PolicyStore, PolicyWriteError, POLICY_HISTORY_VERSION,
    POLICY_STORE_VERSION,
};

use serde::{Deserialize, Serialize};

/// The current policy document schema version. Bumped only on a
/// breaking-shape change; unknown-field parsing is fail-closed
/// (`deny_unknown_fields`) so a newer document is rejected rather than
/// misinterpreted by an older binary.
pub const POLICY_DOC_VERSION: u32 = 1;

/// The JS-safe integer bound, 2^53 - 1. [`PolicyDoc::revision`] and the four
/// millisecond fields are constrained to it (decision 3) so the Rust parser
/// and the generated Zod parser read the same number - the same posture as
/// [`crate::protocol::BridgeReq::id`], which stays inside the bound by
/// construction (server-assigned counter) with the Zod validator enforcing
/// it wire-side. These fields are parsed from untrusted bytes, so here the
/// bound is enforced in the parser itself (and in [`PolicyDoc::validate`]
/// for documents constructed in code): a value the generated Zod would
/// refuse must never sign or store, or the host signs a baseline the
/// extension can only reject.
pub const JS_SAFE_INT_MAX: u64 = 9_007_199_254_740_991;

/// Bounds on `disabledTools`: at most this many entries...
pub const DISABLED_TOOLS_MAX_ENTRIES: usize = 256;

/// ...of 1 to this many bytes each. Together with
/// [`DISABLED_TOOLS_MAX_ENTRIES`] this keeps any valid document or overlay
/// far under the store's read cap (never write what load cannot read back)
/// and bounds what an audit detail naming entries can carry; both bounds are
/// mirrored into the generated Zod validator so the two parsers stay
/// equivalent. Far above any real tool catalogue.
pub const DISABLED_TOOL_NAME_MAX_BYTES: usize = 128;

/// The shared `disabledTools` bound check: [`PolicyDoc::validate`] applies
/// it to documents, [`restrict`] to the merged overlay, so neither lane can
/// persist a list the other side's parser (or the store's own read cap)
/// would refuse.
pub(crate) fn validate_disabled_tools(tools: &[String]) -> Result<(), &'static str> {
    if tools.len() > DISABLED_TOOLS_MAX_ENTRIES {
        return Err("disabledTools carries more than 256 entries");
    }
    if tools
        .iter()
        .any(|t| t.is_empty() || t.len() > DISABLED_TOOL_NAME_MAX_BYTES)
    {
        return Err("a disabledTools entry is empty or longer than 128 bytes");
    }
    Ok(())
}

/// Ties every policy field to its camelCase wire name, once - the
/// `admin_request_kinds!` idea (protocol.rs) applied to the policy
/// catalogue. The same literal feeds the serde rename and `wire_name`, so
/// the two cannot drift, `wire_name`'s match is exhaustive with no wildcard,
/// and joining the list is the same edit that grows [`PolicyField::ALL`] -
/// the direction-totality test then refuses a field without a direction.
macro_rules! policy_fields {
    ($($Variant:ident => $wire:literal),+ $(,)?) => {
        /// One host-owned policy field (ADR-0032 decision 1). Serializes as
        /// its camelCase wire name; an unknown name fails the parse, so a
        /// `touched` set can never smuggle a field this catalogue does not
        /// own (`requireEnrollment` is retired, `uiLanguage` has its own
        /// lane and is deliberately not a policy field).
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        pub enum PolicyField {
            $(#[serde(rename = $wire)] $Variant,)+
        }

        impl PolicyField {
            /// Every policy field, in declaration order. Emitted by
            /// `policy_fields!` from the same list as `wire_name`, so it is
            /// exhaustive by construction.
            pub const ALL: &'static [PolicyField] = &[$(PolicyField::$Variant),+];

            /// The camelCase wire name this field serializes under - the
            /// exact literal the serde rename uses, from the same list.
            pub const fn wire_name(self) -> &'static str {
                match self {
                    $(PolicyField::$Variant => $wire,)+
                }
            }
        }
    };
}

policy_fields!(
    CdpMode => "cdpMode",
    FileUploadEnabled => "fileUploadEnabled",
    HandleDialogEnabled => "handleDialogEnabled",
    PageEvalEnabled => "pageEvalEnabled",
    ConfirmHighRiskClick => "confirmHighRiskClick",
    ConfirmPageEval => "confirmPageEval",
    TouchIdConfirm => "touchIdConfirm",
    ConfirmTabClose => "confirmTabClose",
    WarnPreciseSnapshot => "warnPreciseSnapshot",
    EvalMask => "evalMask",
    HostReverifyMs => "hostReverifyMs",
    ConfirmGraceMs => "confirmGraceMs",
    ClickToastTimeoutMs => "clickToastTimeoutMs",
    EvalToastTimeoutMs => "evalToastTimeoutMs",
    DisabledTools => "disabledTools",
);

/// A field's declared permissive pole (ADR-0032 decision 2): the value
/// direction that grants capability. The comparison primitives below are
/// computed from this table alone, so nobody's claim about which way a
/// change points is ever trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// The four capability grants: permissive at `true`.
    TruePermissive,
    /// The confirm*/warn*/evalMask flags and `touchIdConfirm`: permissive
    /// at `false` (a skipped confirmation is a grant).
    FalsePermissive,
    /// Millisecond windows that grant as they grow: `confirmGraceMs` (a
    /// longer no-reprompt window), `clickToastTimeoutMs`,
    /// `evalToastTimeoutMs` (declared conservative: a longer-lived toast is
    /// the permissive direction).
    GrowsPermissive,
    /// `hostReverifyMs`: grows permissive among positive values (a longer
    /// interval means fewer checks), except that 0 means never re-verify
    /// and is the MOST permissive value - it tops the scale, so 0 maps to
    /// infinity before comparing.
    GrowsPermissiveZeroTop,
    /// `disabledTools`: permissive as the set shrinks (dropping an entry
    /// re-enables a tool).
    ShrinksPermissiveSet,
}

/// The direction table. Exhaustive with no wildcard on purpose: a new field
/// fails to compile here until it declares a direction, so no setting can
/// exist that the comparisons silently ignore.
pub fn direction(f: PolicyField) -> Direction {
    match f {
        PolicyField::CdpMode => Direction::TruePermissive,
        PolicyField::FileUploadEnabled => Direction::TruePermissive,
        PolicyField::HandleDialogEnabled => Direction::TruePermissive,
        PolicyField::PageEvalEnabled => Direction::TruePermissive,
        PolicyField::ConfirmHighRiskClick => Direction::FalsePermissive,
        PolicyField::ConfirmPageEval => Direction::FalsePermissive,
        PolicyField::TouchIdConfirm => Direction::FalsePermissive,
        PolicyField::ConfirmTabClose => Direction::FalsePermissive,
        PolicyField::WarnPreciseSnapshot => Direction::FalsePermissive,
        PolicyField::EvalMask => Direction::FalsePermissive,
        PolicyField::HostReverifyMs => Direction::GrowsPermissiveZeroTop,
        PolicyField::ConfirmGraceMs => Direction::GrowsPermissive,
        PolicyField::ClickToastTimeoutMs => Direction::GrowsPermissive,
        PolicyField::EvalToastTimeoutMs => Direction::GrowsPermissive,
        PolicyField::DisabledTools => Direction::ShrinksPermissiveSet,
    }
}

/// The signed policy document (ADR-0032 decision 3): the exact bytes the
/// enclave signature covers. One flat struct on purpose - `#[serde(flatten)]`
/// silently disables `deny_unknown_fields`, and this parser must stay
/// fail-closed - so the two scoping fields (`revision`, `touched`) sit
/// beside the 15 policy fields inline.
///
/// `touched` is the set of fields the write that produced this document
/// explicitly edited, named by the editing surface and embedded in the
/// signed bytes so the tap covers it (a fresh signature warrants relaxation
/// on exactly these fields, never on the document at large). Vec-encoded on
/// the wire; membership is set semantics, order and duplication carry no
/// meaning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PolicyDoc {
    /// Schema version; see [`POLICY_DOC_VERSION`].
    pub v: u32,
    /// Monotonic write counter, bounded to [`JS_SAFE_INT_MAX`] in the
    /// parser itself so both sides read the same number.
    #[serde(deserialize_with = "de_js_safe_u64")]
    pub revision: u64,
    /// The fields the producing write explicitly edited (see the struct
    /// docs).
    pub touched: Vec<PolicyField>,
    pub cdp_mode: bool,
    pub file_upload_enabled: bool,
    pub handle_dialog_enabled: bool,
    pub page_eval_enabled: bool,
    pub confirm_high_risk_click: bool,
    pub confirm_page_eval: bool,
    pub touch_id_confirm: bool,
    pub confirm_tab_close: bool,
    pub warn_precise_snapshot: bool,
    pub eval_mask: bool,
    // The four millisecond windows share revision's JS-safe bound, parser
    // and validate() both (see JS_SAFE_INT_MAX).
    #[serde(deserialize_with = "de_js_safe_u64")]
    pub host_reverify_ms: u64,
    #[serde(deserialize_with = "de_js_safe_u64")]
    pub confirm_grace_ms: u64,
    #[serde(deserialize_with = "de_js_safe_u64")]
    pub click_toast_timeout_ms: u64,
    #[serde(deserialize_with = "de_js_safe_u64")]
    pub eval_toast_timeout_ms: u64,
    pub disabled_tools: Vec<String>,
}

fn de_js_safe_u64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    let value = u64::deserialize(d)?;
    if value > JS_SAFE_INT_MAX {
        return Err(serde::de::Error::custom(
            "value exceeds the JS-safe integer bound (2^53 - 1)",
        ));
    }
    Ok(value)
}

/// [`de_js_safe_u64`] for the overlay's optional millisecond fields: an
/// absent field stays `None`, a present one is bounded exactly like the
/// document's. Without this, a huge-but-restricting overlay value (a legal
/// restriction under the zero-top order) would store host-side and then fail
/// the extension's JS-safe frame parse - the same parser-differential class
/// the document fields close.
fn de_js_safe_opt_u64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    let value = Option::<u64>::deserialize(d)?;
    if let Some(v) = value {
        if v > JS_SAFE_INT_MAX {
            return Err(serde::de::Error::custom(
                "value exceeds the JS-safe integer bound (2^53 - 1)",
            ));
        }
    }
    Ok(value)
}

/// Just the 15 policy field values, detached from a document's version /
/// revision / touched scoping: the shape the comparisons and the effective
/// policy work in.
///
/// Serializable in camelCase (the wire field names) so it can be the
/// `effective` payload of [`crate::policy::PolicyStatusReport`] that the CLI
/// emits and the desktop app parses back; `ts_rs`-exported under the gen-only
/// feature, the same posture as the enclave report types. Strict on the way
/// in: serde does NOT inherit a container attribute from an embedding type,
/// so without its own `deny_unknown_fields` an unknown field inside a
/// report's `effective` would parse silently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyValues {
    pub cdp_mode: bool,
    pub file_upload_enabled: bool,
    pub handle_dialog_enabled: bool,
    pub page_eval_enabled: bool,
    pub confirm_high_risk_click: bool,
    pub confirm_page_eval: bool,
    pub touch_id_confirm: bool,
    pub confirm_tab_close: bool,
    pub warn_precise_snapshot: bool,
    pub eval_mask: bool,
    pub host_reverify_ms: u64,
    pub confirm_grace_ms: u64,
    pub click_toast_timeout_ms: u64,
    pub eval_toast_timeout_ms: u64,
    pub disabled_tools: Vec<String>,
}

impl Default for PolicyValues {
    /// The fail-closed deny baseline (ADR-0032 decision 4): what the
    /// extension enforces when no policy has ever applied, so every
    /// capability grant sits at its deny value and every confirmation is on.
    fn default() -> Self {
        PolicyValues {
            cdp_mode: false,
            file_upload_enabled: false,
            handle_dialog_enabled: false,
            // Deny baseline: deliberately false, unlike the legacy
            // settings.ts default of true.
            page_eval_enabled: false,
            confirm_high_risk_click: true,
            confirm_page_eval: true,
            touch_id_confirm: true,
            confirm_tab_close: true,
            warn_precise_snapshot: true,
            eval_mask: true,
            host_reverify_ms: 0,
            confirm_grace_ms: 60_000,
            click_toast_timeout_ms: 30_000,
            eval_toast_timeout_ms: 45_000,
            disabled_tools: Vec::new(),
        }
    }
}

impl Default for PolicyDoc {
    fn default() -> Self {
        let base = PolicyValues::default();
        PolicyDoc {
            v: POLICY_DOC_VERSION,
            revision: 0,
            touched: Vec::new(),
            cdp_mode: base.cdp_mode,
            file_upload_enabled: base.file_upload_enabled,
            handle_dialog_enabled: base.handle_dialog_enabled,
            page_eval_enabled: base.page_eval_enabled,
            confirm_high_risk_click: base.confirm_high_risk_click,
            confirm_page_eval: base.confirm_page_eval,
            touch_id_confirm: base.touch_id_confirm,
            confirm_tab_close: base.confirm_tab_close,
            warn_precise_snapshot: base.warn_precise_snapshot,
            eval_mask: base.eval_mask,
            host_reverify_ms: base.host_reverify_ms,
            confirm_grace_ms: base.confirm_grace_ms,
            click_toast_timeout_ms: base.click_toast_timeout_ms,
            eval_toast_timeout_ms: base.eval_toast_timeout_ms,
            disabled_tools: base.disabled_tools,
        }
    }
}

impl PolicyDoc {
    /// The document's 15 field values, detached from its scoping fields.
    pub fn values(&self) -> PolicyValues {
        PolicyValues {
            cdp_mode: self.cdp_mode,
            file_upload_enabled: self.file_upload_enabled,
            handle_dialog_enabled: self.handle_dialog_enabled,
            page_eval_enabled: self.page_eval_enabled,
            confirm_high_risk_click: self.confirm_high_risk_click,
            confirm_page_eval: self.confirm_page_eval,
            touch_id_confirm: self.touch_id_confirm,
            confirm_tab_close: self.confirm_tab_close,
            warn_precise_snapshot: self.warn_precise_snapshot,
            eval_mask: self.eval_mask,
            host_reverify_ms: self.host_reverify_ms,
            confirm_grace_ms: self.confirm_grace_ms,
            click_toast_timeout_ms: self.click_toast_timeout_ms,
            eval_toast_timeout_ms: self.eval_toast_timeout_ms,
            disabled_tools: self.disabled_tools.clone(),
        }
    }

    /// Structural validity: the facts that make this a well-formed v1
    /// document no matter who produced it or how it will be used - the
    /// schema version is ours, the revision and millisecond fields fit the
    /// JS-safe bound, and `disabledTools` fits its entry bounds (a parsed
    /// document already satisfies all of these; this covers documents
    /// constructed in code, which `set_signed` must validate BEFORE any
    /// presence prompt can appear). Deliberately nothing more: whether the
    /// revision is acceptable for a signed write (>= 1, strictly above the
    /// stored baseline's) is a property of the write, not of the bytes, and
    /// belongs to the store / `set_signed` lane.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.v != POLICY_DOC_VERSION {
            return Err("unsupported policy document version");
        }
        if self.revision > JS_SAFE_INT_MAX {
            return Err("revision exceeds the JS-safe integer bound (2^53 - 1)");
        }
        for (value, err) in [
            (
                self.host_reverify_ms,
                "hostReverifyMs exceeds the JS-safe integer bound (2^53 - 1)",
            ),
            (
                self.confirm_grace_ms,
                "confirmGraceMs exceeds the JS-safe integer bound (2^53 - 1)",
            ),
            (
                self.click_toast_timeout_ms,
                "clickToastTimeoutMs exceeds the JS-safe integer bound (2^53 - 1)",
            ),
            (
                self.eval_toast_timeout_ms,
                "evalToastTimeoutMs exceeds the JS-safe integer bound (2^53 - 1)",
            ),
        ] {
            if value > JS_SAFE_INT_MAX {
                return Err(err);
            }
        }
        validate_disabled_tools(&self.disabled_tools)?;
        Ok(())
    }
}

/// The unsigned restriction overlay (ADR-0032 decision 3): per-field
/// overrides on top of the signed baseline, `None` fields omitted from the
/// wire. The overlay travels free precisely because it may only restrict;
/// that direction check is the consumer's business ([`relaxes`] against the
/// effective policy), not this shape's.
///
/// `ts_rs`-exported under the gen-only feature: the desktop app's editor
/// sends its per-field edits in exactly this shape, strict-parsed by serde
/// at the Tauri boundary (`deny_unknown_fields`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(optional_fields))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PolicyOverlay {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cdp_mode: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_upload_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle_dialog_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_eval_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm_high_risk_click: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm_page_eval: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub touch_id_confirm: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm_tab_close: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warn_precise_snapshot: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eval_mask: Option<bool>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de_js_safe_opt_u64"
    )]
    pub host_reverify_ms: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de_js_safe_opt_u64"
    )]
    pub confirm_grace_ms: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de_js_safe_opt_u64"
    )]
    pub click_toast_timeout_ms: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de_js_safe_opt_u64"
    )]
    pub eval_toast_timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_tools: Option<Vec<String>>,
}

/// The effective policy: the baseline with the overlay's present entries
/// applied over it. Pure field-wise override - whether the overlay actually
/// restricts is checked by the consumer against the direction table, never
/// assumed here.
pub fn fold(baseline: &PolicyValues, overlay: &PolicyOverlay) -> PolicyValues {
    PolicyValues {
        cdp_mode: overlay.cdp_mode.unwrap_or(baseline.cdp_mode),
        file_upload_enabled: overlay
            .file_upload_enabled
            .unwrap_or(baseline.file_upload_enabled),
        handle_dialog_enabled: overlay
            .handle_dialog_enabled
            .unwrap_or(baseline.handle_dialog_enabled),
        page_eval_enabled: overlay
            .page_eval_enabled
            .unwrap_or(baseline.page_eval_enabled),
        confirm_high_risk_click: overlay
            .confirm_high_risk_click
            .unwrap_or(baseline.confirm_high_risk_click),
        confirm_page_eval: overlay
            .confirm_page_eval
            .unwrap_or(baseline.confirm_page_eval),
        touch_id_confirm: overlay
            .touch_id_confirm
            .unwrap_or(baseline.touch_id_confirm),
        confirm_tab_close: overlay
            .confirm_tab_close
            .unwrap_or(baseline.confirm_tab_close),
        warn_precise_snapshot: overlay
            .warn_precise_snapshot
            .unwrap_or(baseline.warn_precise_snapshot),
        eval_mask: overlay.eval_mask.unwrap_or(baseline.eval_mask),
        host_reverify_ms: overlay
            .host_reverify_ms
            .unwrap_or(baseline.host_reverify_ms),
        confirm_grace_ms: overlay
            .confirm_grace_ms
            .unwrap_or(baseline.confirm_grace_ms),
        click_toast_timeout_ms: overlay
            .click_toast_timeout_ms
            .unwrap_or(baseline.click_toast_timeout_ms),
        eval_toast_timeout_ms: overlay
            .eval_toast_timeout_ms
            .unwrap_or(baseline.eval_toast_timeout_ms),
        disabled_tools: overlay
            .disabled_tools
            .clone()
            .unwrap_or_else(|| baseline.disabled_tools.clone()),
    }
}

/// `hostReverifyMs` on the permissiveness scale: 0 means never re-verify,
/// the MOST permissive value, so it maps to the top before comparing.
fn zero_top_rank(ms: u64) -> u64 {
    if ms == 0 {
        u64::MAX
    } else {
        ms
    }
}

/// Whether `field` moves toward its permissive pole in `candidate` relative
/// to `anchor`. Each arm spells out its direction's grant condition;
/// [`field_restricts_or_equal`] spells out the restrictive reading
/// independently, and the proptests pin the two as exact complements.
fn field_relaxes(field: PolicyField, candidate: &PolicyValues, anchor: &PolicyValues) -> bool {
    match field {
        PolicyField::CdpMode => candidate.cdp_mode && !anchor.cdp_mode,
        PolicyField::FileUploadEnabled => {
            candidate.file_upload_enabled && !anchor.file_upload_enabled
        }
        PolicyField::HandleDialogEnabled => {
            candidate.handle_dialog_enabled && !anchor.handle_dialog_enabled
        }
        PolicyField::PageEvalEnabled => candidate.page_eval_enabled && !anchor.page_eval_enabled,
        PolicyField::ConfirmHighRiskClick => {
            !candidate.confirm_high_risk_click && anchor.confirm_high_risk_click
        }
        PolicyField::ConfirmPageEval => !candidate.confirm_page_eval && anchor.confirm_page_eval,
        PolicyField::TouchIdConfirm => !candidate.touch_id_confirm && anchor.touch_id_confirm,
        PolicyField::ConfirmTabClose => !candidate.confirm_tab_close && anchor.confirm_tab_close,
        PolicyField::WarnPreciseSnapshot => {
            !candidate.warn_precise_snapshot && anchor.warn_precise_snapshot
        }
        PolicyField::EvalMask => !candidate.eval_mask && anchor.eval_mask,
        PolicyField::HostReverifyMs => {
            zero_top_rank(candidate.host_reverify_ms) > zero_top_rank(anchor.host_reverify_ms)
        }
        PolicyField::ConfirmGraceMs => candidate.confirm_grace_ms > anchor.confirm_grace_ms,
        PolicyField::ClickToastTimeoutMs => {
            candidate.click_toast_timeout_ms > anchor.click_toast_timeout_ms
        }
        PolicyField::EvalToastTimeoutMs => {
            candidate.eval_toast_timeout_ms > anchor.eval_toast_timeout_ms
        }
        // Dropping ANY anchor entry re-enables that tool, whatever else the
        // candidate adds alongside.
        PolicyField::DisabledTools => anchor
            .disabled_tools
            .iter()
            .any(|t| !candidate.disabled_tools.contains(t)),
    }
}

/// Whether `field` sits at or beyond its restrictive pole in `candidate`
/// relative to `anchor` - written from the restrictive definition, not as a
/// negation, so the complement proptest has something real to check.
fn field_restricts_or_equal(
    field: PolicyField,
    candidate: &PolicyValues,
    anchor: &PolicyValues,
) -> bool {
    match field {
        PolicyField::CdpMode => candidate.cdp_mode <= anchor.cdp_mode,
        PolicyField::FileUploadEnabled => {
            candidate.file_upload_enabled <= anchor.file_upload_enabled
        }
        PolicyField::HandleDialogEnabled => {
            candidate.handle_dialog_enabled <= anchor.handle_dialog_enabled
        }
        PolicyField::PageEvalEnabled => candidate.page_eval_enabled <= anchor.page_eval_enabled,
        PolicyField::ConfirmHighRiskClick => {
            candidate.confirm_high_risk_click >= anchor.confirm_high_risk_click
        }
        PolicyField::ConfirmPageEval => candidate.confirm_page_eval >= anchor.confirm_page_eval,
        PolicyField::TouchIdConfirm => candidate.touch_id_confirm >= anchor.touch_id_confirm,
        PolicyField::ConfirmTabClose => candidate.confirm_tab_close >= anchor.confirm_tab_close,
        PolicyField::WarnPreciseSnapshot => {
            candidate.warn_precise_snapshot >= anchor.warn_precise_snapshot
        }
        PolicyField::EvalMask => candidate.eval_mask >= anchor.eval_mask,
        PolicyField::HostReverifyMs => {
            zero_top_rank(candidate.host_reverify_ms) <= zero_top_rank(anchor.host_reverify_ms)
        }
        PolicyField::ConfirmGraceMs => candidate.confirm_grace_ms <= anchor.confirm_grace_ms,
        PolicyField::ClickToastTimeoutMs => {
            candidate.click_toast_timeout_ms <= anchor.click_toast_timeout_ms
        }
        PolicyField::EvalToastTimeoutMs => {
            candidate.eval_toast_timeout_ms <= anchor.eval_toast_timeout_ms
        }
        PolicyField::DisabledTools => anchor
            .disabled_tools
            .iter()
            .all(|t| candidate.disabled_tools.contains(t)),
    }
}

/// Whether `candidate` moves ANY field toward its permissive pole relative
/// to `anchor` (the current effective policy, decision 3). A relaxation is
/// a capability grant: it needs a fresh presence signature naming the field
/// in its `touched` set, never the free restriction lane.
pub fn relaxes(candidate: &PolicyValues, anchor: &PolicyValues) -> bool {
    PolicyField::ALL
        .iter()
        .any(|f| field_relaxes(*f, candidate, anchor))
}

/// Whether `candidate` moves EVERY field toward its restrictive pole or
/// leaves it in place relative to `anchor` - the exact complement of
/// [`relaxes`] (pinned by proptest): a policy either grants somewhere or it
/// restricts-or-holds everywhere.
pub fn restricts_or_equal(candidate: &PolicyValues, anchor: &PolicyValues) -> bool {
    PolicyField::ALL
        .iter()
        .all(|f| field_restricts_or_equal(*f, candidate, anchor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Values differing from the deny baseline only in `hostReverifyMs`.
    fn with_reverify(ms: u64) -> PolicyValues {
        PolicyValues {
            host_reverify_ms: ms,
            ..PolicyValues::default()
        }
    }

    fn with_tools(tools: &[&str]) -> PolicyValues {
        PolicyValues {
            disabled_tools: tools.iter().map(|t| t.to_string()).collect(),
            ..PolicyValues::default()
        }
    }

    #[test]
    fn direction_is_total_over_the_pinned_field_catalogue() {
        // Pins the exact catalogue AND each field's declared direction: a
        // silently added, removed, or reclassified field fails right here.
        let table: Vec<(&str, Direction)> = PolicyField::ALL
            .iter()
            .map(|f| (f.wire_name(), direction(*f)))
            .collect();
        assert_eq!(
            table,
            [
                ("cdpMode", Direction::TruePermissive),
                ("fileUploadEnabled", Direction::TruePermissive),
                ("handleDialogEnabled", Direction::TruePermissive),
                ("pageEvalEnabled", Direction::TruePermissive),
                ("confirmHighRiskClick", Direction::FalsePermissive),
                ("confirmPageEval", Direction::FalsePermissive),
                ("touchIdConfirm", Direction::FalsePermissive),
                ("confirmTabClose", Direction::FalsePermissive),
                ("warnPreciseSnapshot", Direction::FalsePermissive),
                ("evalMask", Direction::FalsePermissive),
                ("hostReverifyMs", Direction::GrowsPermissiveZeroTop),
                ("confirmGraceMs", Direction::GrowsPermissive),
                ("clickToastTimeoutMs", Direction::GrowsPermissive),
                ("evalToastTimeoutMs", Direction::GrowsPermissive),
                ("disabledTools", Direction::ShrinksPermissiveSet),
            ]
        );
    }

    #[test]
    fn wire_names_match_serde_emission_and_round_trip() {
        // The macro derives both from one literal; this pins that serde
        // actually emits it, the same posture as protocol.rs's
        // every_control_variant_tag_is_derived_and_recognized.
        for f in PolicyField::ALL {
            let emitted = serde_json::to_value(f).unwrap();
            assert_eq!(emitted, json!(f.wire_name()));
            let back: PolicyField = serde_json::from_value(emitted).unwrap();
            assert_eq!(back, *f);
        }
    }

    #[test]
    fn document_keys_are_exactly_the_scoping_fields_plus_the_wire_names() {
        // PolicyDoc's keys come from rename_all = "camelCase" over the struct
        // fields, PolicyField's from the macro literals. Nothing ties the two
        // together at compile time, so pin their equality here: a struct
        // field rename (or a macro literal edit) that lets them drift makes a
        // touched entry stop naming a document key.
        let doc = serde_json::to_value(PolicyDoc::default()).unwrap();
        let doc_keys: std::collections::BTreeSet<&str> = doc
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let expected: std::collections::BTreeSet<&str> = ["v", "revision", "touched"]
            .into_iter()
            .chain(PolicyField::ALL.iter().map(|f| f.wire_name()))
            .collect();
        assert_eq!(doc_keys, expected);
        // The overlay carries exactly the wire-named fields (all optional).
        let full_overlay: PolicyOverlay =
            serde_json::from_value(doc_without_scoping_fields(&doc)).unwrap();
        assert_eq!(
            serde_json::to_value(&full_overlay)
                .unwrap()
                .as_object()
                .unwrap()
                .len(),
            PolicyField::ALL.len()
        );
    }

    /// The default document's JSON minus v/revision/touched: a full overlay
    /// in wire spelling, for the key-parity pin above.
    fn doc_without_scoping_fields(doc: &serde_json::Value) -> serde_json::Value {
        let mut obj = doc.as_object().unwrap().clone();
        obj.remove("v");
        obj.remove("revision");
        obj.remove("touched");
        serde_json::Value::Object(obj)
    }

    #[test]
    fn unknown_touched_field_names_fail_the_parse() {
        // requireEnrollment is retired and uiLanguage is deliberately not a
        // policy field; neither may ride into a touched set.
        for bad in ["requireEnrollment", "uiLanguage", "bogus", "cdpmode", ""] {
            assert!(
                serde_json::from_value::<PolicyField>(json!(bad)).is_err(),
                "field name {bad:?} must be refused"
            );
        }
        let mut doc = serde_json::to_value(PolicyDoc::default()).unwrap();
        doc["touched"] = json!(["pageEvalEnabled", "requireEnrollment"]);
        assert!(serde_json::from_value::<PolicyDoc>(doc).is_err());
    }

    #[test]
    fn host_reverify_zero_tops_the_permissiveness_scale() {
        // The order a naive numeric comparator gets backwards: 0 = never
        // re-verify = MOST permissive.
        assert!(relaxes(&with_reverify(0), &with_reverify(60_000)));
        assert!(!relaxes(&with_reverify(60_000), &with_reverify(0)));
        assert!(restricts_or_equal(
            &with_reverify(60_000),
            &with_reverify(0)
        ));
        assert!(!restricts_or_equal(
            &with_reverify(0),
            &with_reverify(60_000)
        ));
        // Among positive values permissiveness grows with the number.
        assert!(relaxes(&with_reverify(60_000), &with_reverify(1_000)));
        assert!(!relaxes(&with_reverify(1_000), &with_reverify(60_000)));
        assert!(restricts_or_equal(
            &with_reverify(1_000),
            &with_reverify(60_000)
        ));
        assert!(!restricts_or_equal(
            &with_reverify(60_000),
            &with_reverify(1_000)
        ));
    }

    #[test]
    fn revision_parses_only_inside_the_js_safe_bound() {
        let mut doc = serde_json::to_value(PolicyDoc::default()).unwrap();
        doc["revision"] = json!(9_007_199_254_740_991u64);
        let parsed: PolicyDoc = serde_json::from_value(doc.clone()).unwrap();
        assert_eq!(parsed.revision, JS_SAFE_INT_MAX);
        doc["revision"] = json!(9_007_199_254_740_992u64);
        assert!(serde_json::from_value::<PolicyDoc>(doc).is_err());
        // validate() covers the constructed-in-code path the parser never
        // sees (set_signed must refuse before any prompt).
        let over = PolicyDoc {
            revision: JS_SAFE_INT_MAX + 1,
            ..PolicyDoc::default()
        };
        assert!(over.validate().is_err());
        assert!(PolicyDoc::default().validate().is_ok());
    }

    #[test]
    fn validate_refuses_a_foreign_document_version() {
        let doc = PolicyDoc {
            v: POLICY_DOC_VERSION + 1,
            ..PolicyDoc::default()
        };
        assert!(doc.validate().is_err());
    }

    #[test]
    fn ms_fields_parse_only_inside_the_js_safe_bound() {
        // The parser differential F2 closes: without this bound a huge ms
        // value signs and stores host-side while the generated Zod (z.int()
        // rejects unsafe integers) refuses the push.
        for field in [
            "hostReverifyMs",
            "confirmGraceMs",
            "clickToastTimeoutMs",
            "evalToastTimeoutMs",
        ] {
            let mut doc = serde_json::to_value(PolicyDoc::default()).unwrap();
            doc[field] = json!(9_007_199_254_740_991u64);
            assert!(
                serde_json::from_value::<PolicyDoc>(doc.clone()).is_ok(),
                "{field} must accept 2^53 - 1"
            );
            doc[field] = json!(9_007_199_254_740_992u64);
            assert!(
                serde_json::from_value::<PolicyDoc>(doc).is_err(),
                "{field} must refuse 2^53"
            );
        }
    }

    #[test]
    fn overlay_ms_fields_parse_only_inside_the_js_safe_bound() {
        // The same differential as the document fields, overlay lane: a
        // huge-but-restricting overlay value is a legal restriction under
        // the zero-top order, so without this bound it would store
        // host-side and then fail the extension's JS-safe frame parse.
        for field in [
            "hostReverifyMs",
            "confirmGraceMs",
            "clickToastTimeoutMs",
            "evalToastTimeoutMs",
        ] {
            let ok = json!({ field: 9_007_199_254_740_991u64 });
            assert!(
                serde_json::from_value::<PolicyOverlay>(ok).is_ok(),
                "overlay {field} must accept 2^53 - 1"
            );
            let over = json!({ field: 9_007_199_254_740_992u64 });
            assert!(
                serde_json::from_value::<PolicyOverlay>(over).is_err(),
                "overlay {field} must refuse 2^53"
            );
        }
        // Absent fields stay None through the bounded deserializer.
        let empty: PolicyOverlay = serde_json::from_value(json!({})).unwrap();
        assert_eq!(empty, PolicyOverlay::default());
    }

    #[test]
    fn validate_bounds_ms_fields_for_constructed_docs() {
        // The parser never sees a constructed document; set_signed relies on
        // validate() to refuse it before any prompt.
        let over = JS_SAFE_INT_MAX + 1;
        for doc in [
            PolicyDoc {
                host_reverify_ms: over,
                ..PolicyDoc::default()
            },
            PolicyDoc {
                confirm_grace_ms: over,
                ..PolicyDoc::default()
            },
            PolicyDoc {
                click_toast_timeout_ms: over,
                ..PolicyDoc::default()
            },
            PolicyDoc {
                eval_toast_timeout_ms: over,
                ..PolicyDoc::default()
            },
        ] {
            assert!(doc.validate().is_err(), "{doc:?} must fail validate()");
        }
        let at_bound = PolicyDoc {
            host_reverify_ms: JS_SAFE_INT_MAX,
            confirm_grace_ms: JS_SAFE_INT_MAX,
            click_toast_timeout_ms: JS_SAFE_INT_MAX,
            eval_toast_timeout_ms: JS_SAFE_INT_MAX,
            ..PolicyDoc::default()
        };
        assert!(at_bound.validate().is_ok());
    }

    #[test]
    fn validate_bounds_disabled_tools_entries() {
        // An oversized list must never validate: the store's write cap
        // refuses to persist what load cannot read back, and these bounds
        // are what keep every valid document under it.
        let doc = |tools: Vec<String>| PolicyDoc {
            disabled_tools: tools,
            ..PolicyDoc::default()
        };
        assert!(doc(vec!["t".into(); DISABLED_TOOLS_MAX_ENTRIES])
            .validate()
            .is_ok());
        assert!(doc(vec!["t".into(); DISABLED_TOOLS_MAX_ENTRIES + 1])
            .validate()
            .is_err());
        assert!(doc(vec!["a".repeat(DISABLED_TOOL_NAME_MAX_BYTES)])
            .validate()
            .is_ok());
        assert!(doc(vec!["a".repeat(DISABLED_TOOL_NAME_MAX_BYTES + 1)])
            .validate()
            .is_err());
        assert!(doc(vec![String::new()]).validate().is_err());
    }

    #[test]
    fn host_reverify_default_zero_is_the_decided_deny_baseline_exception() {
        // hostReverifyMs's default 0 IS the field's most permissive value -
        // the one deliberate exception to "the deny baseline sits at every
        // field's restrictive pole" (user decision 2026-08-10: the deny
        // mechanism is grants-off + confirmations-on, and today's shipped
        // default of 0 is kept). Pinned together so no future review
        // rediscovers it as a bug.
        assert_eq!(PolicyValues::default().host_reverify_ms, 0);
        assert_eq!(
            direction(PolicyField::HostReverifyMs),
            Direction::GrowsPermissiveZeroTop
        );
    }

    #[test]
    fn touched_set_embeds_and_round_trips_byte_exact() {
        let doc = PolicyDoc {
            revision: 3,
            touched: vec![
                PolicyField::PageEvalEnabled,
                PolicyField::HostReverifyMs,
                PolicyField::DisabledTools,
            ],
            page_eval_enabled: true,
            ..PolicyDoc::default()
        };
        // The exact serialized bytes (what a signature would cover)
        // strict-parse back to the same document, touched set included.
        let bytes = serde_json::to_vec(&doc).unwrap();
        let back: PolicyDoc = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, doc);
        assert_eq!(back.touched, doc.touched);
        // And the embedded set is spelled in wire names inside those bytes.
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            value["touched"],
            json!(["pageEvalEnabled", "hostReverifyMs", "disabledTools"])
        );
    }

    #[test]
    fn unknown_fields_are_rejected_fail_closed() {
        let mut doc = serde_json::to_value(PolicyDoc::default()).unwrap();
        // Positive control: the exact shape parses.
        assert!(serde_json::from_value::<PolicyDoc>(doc.clone()).is_ok());
        doc["surprise"] = json!(true);
        assert!(serde_json::from_value::<PolicyDoc>(doc).is_err());

        assert!(serde_json::from_value::<PolicyOverlay>(json!({})).is_ok());
        assert!(serde_json::from_value::<PolicyOverlay>(json!({
            "disabledTools": ["page_eval"],
        }))
        .is_ok());
        assert!(serde_json::from_value::<PolicyOverlay>(json!({
            "disabledTools": ["page_eval"],
            "surprise": true,
        }))
        .is_err());
        // The retired / excluded settings.ts fields are unknown here too.
        assert!(serde_json::from_value::<PolicyOverlay>(json!({
            "requireEnrollment": false,
        }))
        .is_err());
        assert!(serde_json::from_value::<PolicyOverlay>(json!({
            "uiLanguage": "en",
        }))
        .is_err());
    }

    #[test]
    fn an_empty_overlay_serializes_to_an_empty_object() {
        assert_eq!(
            serde_json::to_value(PolicyOverlay::default()).unwrap(),
            json!({})
        );
    }

    #[test]
    fn the_default_is_the_deny_baseline() {
        let base = PolicyValues::default();
        assert!(!base.cdp_mode);
        assert!(!base.file_upload_enabled);
        assert!(!base.handle_dialog_enabled);
        assert!(!base.page_eval_enabled);
        assert!(base.confirm_high_risk_click);
        assert!(base.confirm_page_eval);
        assert!(base.touch_id_confirm);
        assert!(base.confirm_tab_close);
        assert!(base.warn_precise_snapshot);
        assert!(base.eval_mask);
        assert_eq!(base.host_reverify_ms, 0);
        assert_eq!(base.confirm_grace_ms, 60_000);
        assert_eq!(base.click_toast_timeout_ms, 30_000);
        assert_eq!(base.eval_toast_timeout_ms, 45_000);
        assert!(base.disabled_tools.is_empty());

        let doc = PolicyDoc::default();
        assert_eq!(doc.v, POLICY_DOC_VERSION);
        assert_eq!(doc.revision, 0);
        assert!(doc.touched.is_empty());
        assert_eq!(doc.values(), base);
    }

    #[test]
    fn fold_applies_exactly_the_present_overlay_entries() {
        let base = PolicyValues::default();
        let overlay = PolicyOverlay {
            page_eval_enabled: Some(false),
            confirm_grace_ms: Some(0),
            disabled_tools: Some(vec!["page_upload".into()]),
            ..PolicyOverlay::default()
        };
        let effective = fold(&base, &overlay);
        assert!(!effective.page_eval_enabled);
        assert_eq!(effective.confirm_grace_ms, 0);
        assert_eq!(effective.disabled_tools, vec!["page_upload".to_string()]);
        // Untouched fields pass through.
        assert_eq!(
            effective.click_toast_timeout_ms,
            base.click_toast_timeout_ms
        );
        assert_eq!(effective.eval_mask, base.eval_mask);
        // An empty overlay is the identity.
        assert_eq!(fold(&base, &PolicyOverlay::default()), base);
    }

    #[test]
    fn disabled_tools_relax_only_when_an_anchor_entry_is_dropped() {
        let anchor = with_tools(&["page_eval", "page_upload"]);
        // Growing the set (or holding it) never relaxes.
        assert!(!relaxes(&anchor.clone(), &anchor));
        assert!(!relaxes(
            &with_tools(&["page_eval", "page_upload", "tab_close"]),
            &anchor
        ));
        // Dropping any anchor entry relaxes, even while adding others.
        assert!(relaxes(&with_tools(&["page_eval"]), &anchor));
        assert!(relaxes(&with_tools(&["page_eval", "tab_close"]), &anchor));
        assert!(relaxes(&with_tools(&[]), &anchor));
    }
}

/// Property-based coverage of the comparison lattice and the fold, the
/// protocol.rs `mod proptests` pattern.
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// Millisecond values weighted toward 0 and small collisions, so the
    /// zero-top order and the equality edges are exercised constantly.
    fn arb_ms() -> impl Strategy<Value = u64> {
        prop_oneof![Just(0u64), 1u64..5, Just(60_000u64), any::<u64>(),]
    }

    /// Tool lists drawn from a tiny pool, so candidate/anchor pairs overlap,
    /// nest, and diverge in every combination.
    fn arb_tools() -> impl Strategy<Value = Vec<String>> {
        prop::collection::vec(
            prop::sample::select(vec!["page_eval", "page_upload", "tab_close", "click"]),
            0..4,
        )
        .prop_map(|ts| ts.into_iter().map(str::to_string).collect())
    }

    fn arb_values() -> impl Strategy<Value = PolicyValues> {
        (
            (any::<bool>(), any::<bool>(), any::<bool>(), any::<bool>()),
            (
                any::<bool>(),
                any::<bool>(),
                any::<bool>(),
                any::<bool>(),
                any::<bool>(),
                any::<bool>(),
            ),
            (arb_ms(), arb_ms(), arb_ms(), arb_ms()),
            arb_tools(),
        )
            .prop_map(
                |(
                    (cdp_mode, file_upload_enabled, handle_dialog_enabled, page_eval_enabled),
                    (
                        confirm_high_risk_click,
                        confirm_page_eval,
                        touch_id_confirm,
                        confirm_tab_close,
                        warn_precise_snapshot,
                        eval_mask,
                    ),
                    (
                        host_reverify_ms,
                        confirm_grace_ms,
                        click_toast_timeout_ms,
                        eval_toast_timeout_ms,
                    ),
                    disabled_tools,
                )| PolicyValues {
                    cdp_mode,
                    file_upload_enabled,
                    handle_dialog_enabled,
                    page_eval_enabled,
                    confirm_high_risk_click,
                    confirm_page_eval,
                    touch_id_confirm,
                    confirm_tab_close,
                    warn_precise_snapshot,
                    eval_mask,
                    host_reverify_ms,
                    confirm_grace_ms,
                    click_toast_timeout_ms,
                    eval_toast_timeout_ms,
                    disabled_tools,
                },
            )
    }

    /// An overlay built from arbitrary values with a per-field presence
    /// mask, so every subset of fields occurs.
    fn arb_overlay() -> impl Strategy<Value = PolicyOverlay> {
        (arb_values(), prop::collection::vec(any::<bool>(), 15)).prop_map(|(v, on)| PolicyOverlay {
            cdp_mode: on[0].then_some(v.cdp_mode),
            file_upload_enabled: on[1].then_some(v.file_upload_enabled),
            handle_dialog_enabled: on[2].then_some(v.handle_dialog_enabled),
            page_eval_enabled: on[3].then_some(v.page_eval_enabled),
            confirm_high_risk_click: on[4].then_some(v.confirm_high_risk_click),
            confirm_page_eval: on[5].then_some(v.confirm_page_eval),
            touch_id_confirm: on[6].then_some(v.touch_id_confirm),
            confirm_tab_close: on[7].then_some(v.confirm_tab_close),
            warn_precise_snapshot: on[8].then_some(v.warn_precise_snapshot),
            eval_mask: on[9].then_some(v.eval_mask),
            host_reverify_ms: on[10].then_some(v.host_reverify_ms),
            confirm_grace_ms: on[11].then_some(v.confirm_grace_ms),
            click_toast_timeout_ms: on[12].then_some(v.click_toast_timeout_ms),
            eval_toast_timeout_ms: on[13].then_some(v.eval_toast_timeout_ms),
            disabled_tools: on[14].then(|| v.disabled_tools.clone()),
        })
    }

    proptest! {
        /// The lattice partition: every candidate/anchor pair either relaxes
        /// somewhere or restricts-or-holds everywhere, never both, never
        /// neither. Real teeth because the two sides are implemented
        /// independently (grant reading vs restrictive reading, per field).
        #[test]
        fn relaxes_and_restricts_or_equal_partition_every_pair(
            candidate in arb_values(),
            anchor in arb_values(),
        ) {
            prop_assert!(relaxes(&candidate, &anchor) != restricts_or_equal(&candidate, &anchor));
        }

        /// Reflexive safety: a policy never relaxes itself (replaying the
        /// current effective policy is idempotent, never a grant).
        #[test]
        fn a_policy_never_relaxes_itself(v in arb_values()) {
            prop_assert!(!relaxes(&v, &v));
            prop_assert!(restricts_or_equal(&v, &v));
        }

        /// The verdict does not depend on the order fields are examined in.
        #[test]
        fn the_verdict_is_field_order_independent(
            candidate in arb_values(),
            anchor in arb_values(),
            order in Just(PolicyField::ALL.to_vec()).prop_shuffle(),
        ) {
            let any_relax = order.iter().any(|f| field_relaxes(*f, &candidate, &anchor));
            prop_assert_eq!(any_relax, relaxes(&candidate, &anchor));
            let all_hold = order
                .iter()
                .all(|f| field_restricts_or_equal(*f, &candidate, &anchor));
            prop_assert_eq!(all_hold, restricts_or_equal(&candidate, &anchor));
        }

        /// Folding the same overlay twice is folding it once.
        #[test]
        fn fold_is_idempotent(baseline in arb_values(), overlay in arb_overlay()) {
            let once = fold(&baseline, &overlay);
            prop_assert_eq!(fold(&once, &overlay), once.clone());
        }
    }
}
