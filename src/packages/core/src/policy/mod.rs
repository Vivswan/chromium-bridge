//! Host-owned policy: the field catalogue with each field's permissive
//! direction, the comparison primitives, and the signed policy document.
//!
//! Every verdict about a candidate policy is computed from the catalogue's
//! declared directions ([`relaxes`] / [`restricts_or_equal`]), never from
//! anyone's claim about which way a change points, and always against the
//! current EFFECTIVE policy (the signed baseline with its restriction overlay
//! applied, [`fold`]), never the baseline alone.
//!
//! The on-disk store and the two write seams live in [`store`]:
//! [`PolicyStore`] / [`PolicyHistory`] (fail-closed loads, atomic
//! runtime-locked writes), and [`set_signed`] / [`restrict`], the only
//! mutation paths every editing surface shares. The host-side dispatch gate
//! lives in [`gating`]. Owned elsewhere: the signing domain and the host key
//! ([`crate::enclave`]), the presence attestation a grant consumes
//! ([`crate::presence`]), and the control frames that carry the document
//! (`crate::protocol`).

mod cli;
mod store;

pub mod gating;

pub use cli::{
    gather_history_report, gather_policy_status, run_policy, PolicyErrorReport,
    PolicyHistoryEntryReport, PolicyHistoryReport, PolicyStatusReport, PolicyStoreState,
};
pub use store::{
    clear_baseline_locked, restrict, set_signed, PolicyHistory, PolicyHistoryEntry, PolicyStore,
    PolicyWriteError,
};

use serde::{Deserialize, Serialize};

/// The current policy document schema version. Bumped only on a
/// breaking-shape change; unknown-field parsing is fail-closed
/// (`deny_unknown_fields`) so a newer document is rejected rather than
/// misinterpreted by an older binary.
pub const POLICY_DOC_VERSION: u32 = 1;

/// The JS-safe integer bound, 2^53 - 1. [`PolicyDoc::revision`] and every [`Ms`] value are constrained to it
/// so the Rust parser and the generated Zod parser read the same number: a value Zod would refuse must never
/// sign or store, or the host signs a baseline the extension can only reject.
pub const JS_SAFE_INT_MAX: u64 = 9_007_199_254_740_991;

/// Bounds on `disabledTools`: at most this many entries...
pub const DISABLED_TOOLS_MAX_ENTRIES: usize = 256;

/// ...of 1 to this many bytes each. Together the two bounds keep any valid document or overlay far under the
/// store's read cap and bound an audit detail naming entries; the generated Zod validator mirrors both.
pub const DISABLED_TOOL_NAME_MAX_BYTES: usize = 128;

/// The shared `disabledTools` bound check: [`PolicyDoc::validate`] applies it to documents, [`restrict`] to
/// the merged overlay, so neither lane can persist a list the other side's parser or the store's read cap would refuse.
/// It also refuses what the comma-joined argv transport (`cli::parse_tool_list` re-splits and trims) cannot
/// round-trip, which the property test in `cli` pins.
///
/// ```text
/// name holding a comma    -> would silently become two names
/// surrounding whitespace  -> would silently become its trimmed self
/// ```
///
/// Running on the READ path too (`PolicyStore::baseline_doc` -> validate) is deliberate: a stored comma entry
/// could re-split in a push built from the store and silently DROP a tool from the deny list (the permissive
/// direction), so such a store reads present-but-UNREADABLE. No migration: nothing shipped could have stored one; re-sign to repair.
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
    if tools.iter().any(|t| t.contains(',')) {
        return Err(
            "a disabledTools entry contains a comma, which the comma-joined CLI \
             transport cannot round-trip",
        );
    }
    if tools.iter().any(|t| t.trim() != t.as_str()) {
        return Err(
            "a disabledTools entry carries surrounding whitespace, which the CLI \
             transport's trimming re-split cannot round-trip",
        );
    }
    Ok(())
}

/// A millisecond count inside the JS-safe integer bound ([`JS_SAFE_INT_MAX`]).
/// Every constructor is bounded (`TryFrom<u64>`, `From<u32>`, the parser), so
/// no document or overlay can carry a value the extension's Zod parser would
/// refuse; serializes as the bare integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[cfg_attr(
    feature = "envelope-schema",
    derive(schemars::JsonSchema),
    schemars(inline)
)]
#[serde(transparent)]
pub struct Ms(u64);

/// The one way an [`Ms`] construction fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("value exceeds the JS-safe integer bound (2^53 - 1)")]
pub struct MsOutOfBounds;

impl Ms {
    pub const ZERO: Ms = Ms(0);

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Every `u32` sits inside the bound, so small literals need no fallible path.
impl From<u32> for Ms {
    fn from(ms: u32) -> Ms {
        Ms(u64::from(ms))
    }
}

impl TryFrom<u64> for Ms {
    type Error = MsOutOfBounds;

    fn try_from(ms: u64) -> Result<Ms, MsOutOfBounds> {
        if ms > JS_SAFE_INT_MAX {
            return Err(MsOutOfBounds);
        }
        Ok(Ms(ms))
    }
}

impl<'de> Deserialize<'de> for Ms {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Ms, D::Error> {
        Ms::try_from(u64::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Display for Ms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Which value of a boolean field grants capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoolPole {
    /// The capability grants: permissive at `true`.
    TruePermissive,
    /// The confirm*/warn*/evalMask flags and `presenceConfirm`: permissive
    /// at `false` (a skipped confirmation is a grant).
    FalsePermissive,
}

/// How a millisecond window ranks on the permissiveness scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsOrder {
    /// Grants as it grows: a longer no-reprompt window, a longer-lived toast
    /// (declared conservative: the longer toast is the permissive reading).
    GrowsPermissive,
    /// Grows permissive among positive values (a longer interval means fewer
    /// checks), except that 0 means never re-verify and is the MOST
    /// permissive value: it tops the scale, so 0 ranks as infinity.
    GrowsPermissiveZeroTop,
}

/// A field's declared permissive direction, by value kind. Read it through
/// [`direction`]; the catalogue below is where each pole is declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Bool(BoolPole),
    Ms(MsOrder),
    /// The tool deny list: permissive as the set shrinks (dropping an entry
    /// re-enables a tool).
    ShrinksPermissiveSet,
}

/// A policy field refined by its value kind: the handle every typed accessor
/// takes, so a boolean comparison can only ever read a boolean field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    Bool(BoolField),
    Ms(MsField),
    ToolSet(ToolSetField),
}

/// Generates the catalogue types from one row per field: the `PolicyField` enum with its wire names, the kind-typed
/// handles with their poles, and the three value carriers (`PolicyValues`, `PolicyOverlay`, `PolicyDoc`) with their
/// typed accessors. One literal per field feeds every serde rename, so no carrier can spell a field differently from
/// the `touched` set that names it.
macro_rules! policy_fields {
    (
        bool { $($bv:ident: $bf:ident $bw:literal => $bp:ident),+ $(,)? }
        ms { $($mv:ident: $mf:ident $mw:literal => $mo:ident),+ $(,)? }
        tools { $($tv:ident: $tf:ident $tw:literal),+ $(,)? }
    ) => {
        /// One host-owned policy field. Serializes as its camelCase wire
        /// name; an unknown name fails the parse, so a `touched` set can
        /// never smuggle a field this catalogue does not own
        /// (`requireEnrollment` is retired, `uiLanguage` has its own lane and
        /// is deliberately not a policy field).
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        pub enum PolicyField {
            $(#[serde(rename = $bw)] $bv,)+
            $(#[serde(rename = $mw)] $mv,)+
            $(#[serde(rename = $tw)] $tv,)+
        }

        impl PolicyField {
            /// Every policy field, in declaration (wire) order.
            pub const ALL: &'static [PolicyField] = &[
                $(PolicyField::$bv,)+
                $(PolicyField::$mv,)+
                $(PolicyField::$tv,)+
            ];

            /// The camelCase wire name this field serializes under.
            pub const fn wire_name(self) -> &'static str {
                match self {
                    $(PolicyField::$bv => $bw,)+
                    $(PolicyField::$mv => $mw,)+
                    $(PolicyField::$tv => $tw,)+
                }
            }

            /// The field refined by its value kind.
            pub const fn kind(self) -> FieldKind {
                match self {
                    $(PolicyField::$bv => FieldKind::Bool(BoolField::$bv),)+
                    $(PolicyField::$mv => FieldKind::Ms(MsField::$mv),)+
                    $(PolicyField::$tv => FieldKind::ToolSet(ToolSetField::$tv),)+
                }
            }
        }

        /// A boolean policy field.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum BoolField {
            $($bv,)+
        }

        impl BoolField {
            /// Which value grants, as the catalogue declares it.
            pub const fn pole(self) -> BoolPole {
                match self {
                    $(BoolField::$bv => BoolPole::$bp,)+
                }
            }
        }

        /// A millisecond-window policy field.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum MsField {
            $($mv,)+
        }

        impl MsField {
            /// How the window ranks, as the catalogue declares it.
            pub const fn order(self) -> MsOrder {
                match self {
                    $(MsField::$mv => MsOrder::$mo,)+
                }
            }
        }

        /// A tool-set policy field.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum ToolSetField {
            $($tv,)+
        }

        /// Just the field values, detached from a document's version / revision / touched scoping: the shape the
        /// comparisons and the effective policy work in, and the `effective` payload of
        /// [`crate::policy::PolicyStatusReport`] that the CLI emits.
        ///
        /// Its own `deny_unknown_fields` is load-bearing: serde does NOT inherit a container attribute from an
        /// embedding type, so without it an unknown field inside a report's `effective` would parse silently.
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct PolicyValues {
            $(#[serde(rename = $bw)] pub $bf: bool,)+
            $(
                #[serde(rename = $mw)]
                pub $mf: Ms,
            )+
            $(#[serde(rename = $tw)] pub $tf: Vec<String>,)+
        }

        impl PolicyValues {
            pub fn get_bool(&self, field: BoolField) -> bool {
                match field {
                    $(BoolField::$bv => self.$bf,)+
                }
            }

            pub fn bool_mut(&mut self, field: BoolField) -> &mut bool {
                match field {
                    $(BoolField::$bv => &mut self.$bf,)+
                }
            }

            pub fn get_ms(&self, field: MsField) -> Ms {
                match field {
                    $(MsField::$mv => self.$mf,)+
                }
            }

            pub fn ms_mut(&mut self, field: MsField) -> &mut Ms {
                match field {
                    $(MsField::$mv => &mut self.$mf,)+
                }
            }

            pub fn get_tools(&self, field: ToolSetField) -> &[String] {
                match field {
                    $(ToolSetField::$tv => &self.$tf,)+
                }
            }

            pub fn tools_mut(&mut self, field: ToolSetField) -> &mut Vec<String> {
                match field {
                    $(ToolSetField::$tv => &mut self.$tf,)+
                }
            }
        }

        /// The unsigned restriction overlay: per-field overrides on top of
        /// the signed baseline, absent entries omitted from the wire. The
        /// overlay travels free precisely because it may only restrict; that
        /// direction check is the consumer's business ([`relaxes`] against
        /// the effective policy), not this shape's.
        #[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
        #[cfg_attr(feature = "envelope-schema", derive(schemars::JsonSchema))]
        #[serde(deny_unknown_fields)]
        pub struct PolicyOverlay {
            $(
                #[serde(rename = $bw, skip_serializing_if = "Option::is_none")]
                pub $bf: Option<bool>,
            )+
            $(
                #[serde(rename = $mw, skip_serializing_if = "Option::is_none")]
                pub $mf: Option<Ms>,
            )+
            $(
                #[serde(rename = $tw, skip_serializing_if = "Option::is_none")]
                pub $tf: Option<Vec<String>>,
            )+
        }

        impl PolicyOverlay {
            pub fn get_bool(&self, field: BoolField) -> Option<bool> {
                match field {
                    $(BoolField::$bv => self.$bf,)+
                }
            }

            pub fn bool_mut(&mut self, field: BoolField) -> &mut Option<bool> {
                match field {
                    $(BoolField::$bv => &mut self.$bf,)+
                }
            }

            pub fn get_ms(&self, field: MsField) -> Option<Ms> {
                match field {
                    $(MsField::$mv => self.$mf,)+
                }
            }

            pub fn ms_mut(&mut self, field: MsField) -> &mut Option<Ms> {
                match field {
                    $(MsField::$mv => &mut self.$mf,)+
                }
            }

            pub fn get_tools(&self, field: ToolSetField) -> Option<&[String]> {
                match field {
                    $(ToolSetField::$tv => self.$tf.as_deref(),)+
                }
            }

            pub fn tools_mut(&mut self, field: ToolSetField) -> &mut Option<Vec<String>> {
                match field {
                    $(ToolSetField::$tv => &mut self.$tf,)+
                }
            }
        }

        /// The signed policy document: the exact bytes the enclave signature covers. One flat struct on purpose:
        /// `#[serde(flatten)]` silently disables `deny_unknown_fields`, and this parser must stay fail-closed.
        ///
        /// ```text
        /// touched -> the fields the producing write explicitly edited, inside the signed bytes so the tap covers it: a
        ///            fresh signature warrants relaxation on exactly these fields, never on the document at large; Vec
        ///            on the wire, set semantics (order and duplication carry no meaning)
        /// ```
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct PolicyDoc {
            /// Schema version; see [`POLICY_DOC_VERSION`].
            pub v: u32,
            /// Monotonic write counter, bounded to [`JS_SAFE_INT_MAX`] in the
            /// parser itself so both sides read the same number.
            #[serde(deserialize_with = "de_js_safe_u64")]
            pub revision: u64,
            /// The fields the producing write explicitly edited (see the
            /// struct docs).
            pub touched: Vec<PolicyField>,
            $(#[serde(rename = $bw)] pub $bf: bool,)+
            $(#[serde(rename = $mw)] pub $mf: Ms,)+
            $(#[serde(rename = $tw)] pub $tf: Vec<String>,)+
        }

        impl PolicyDoc {
            /// The document's field values, detached from its scoping fields.
            pub fn values(&self) -> PolicyValues {
                PolicyValues {
                    $($bf: self.$bf,)+
                    $($mf: self.$mf,)+
                    $($tf: self.$tf.clone(),)+
                }
            }

            /// A document carrying `values` under the given scoping fields.
            /// Crate-private: surfaces pass [`PolicyValues`] and a touched
            /// set; revision arithmetic belongs to [`set_signed`] alone.
            pub(crate) fn from_values(
                values: &PolicyValues,
                revision: u64,
                touched: Vec<PolicyField>,
            ) -> PolicyDoc {
                PolicyDoc {
                    v: POLICY_DOC_VERSION,
                    revision,
                    touched,
                    $($bf: values.$bf,)+
                    $($mf: values.$mf,)+
                    $($tf: values.$tf.clone(),)+
                }
            }
        }
    };
}

// The one place a field's direction is declared; the comparisons read it through `kind()`, so no field can
// exist whose comparison ignores its direction. Declaration order is wire order, and the signed bytes depend
// on it.
policy_fields! {
    bool {
        CdpMode: cdp_mode "cdpMode" => TruePermissive,
        FileUploadEnabled: file_upload_enabled "fileUploadEnabled" => TruePermissive,
        HandleDialogEnabled: handle_dialog_enabled "handleDialogEnabled" => TruePermissive,
        PageEvalEnabled: page_eval_enabled "pageEvalEnabled" => TruePermissive,
        ConfirmHighRiskClick: confirm_high_risk_click "confirmHighRiskClick" => FalsePermissive,
        ConfirmPageEval: confirm_page_eval "confirmPageEval" => FalsePermissive,
        PresenceConfirm: presence_confirm "presenceConfirm" => FalsePermissive,
        ConfirmTabClose: confirm_tab_close "confirmTabClose" => FalsePermissive,
        WarnPreciseSnapshot: warn_precise_snapshot "warnPreciseSnapshot" => FalsePermissive,
        EvalMask: eval_mask "evalMask" => FalsePermissive,
    }
    ms {
        HostReverifyMs: host_reverify_ms "hostReverifyMs" => GrowsPermissiveZeroTop,
        ConfirmGraceMs: confirm_grace_ms "confirmGraceMs" => GrowsPermissive,
        ClickToastTimeoutMs: click_toast_timeout_ms "clickToastTimeoutMs" => GrowsPermissive,
        EvalToastTimeoutMs: eval_toast_timeout_ms "evalToastTimeoutMs" => GrowsPermissive,
    }
    tools {
        DisabledTools: disabled_tools "disabledTools",
    }
}

/// A field's declared permissive direction, read from the catalogue.
pub fn direction(field: PolicyField) -> Direction {
    match field.kind() {
        FieldKind::Bool(f) => Direction::Bool(f.pole()),
        FieldKind::Ms(f) => Direction::Ms(f.order()),
        FieldKind::ToolSet(_) => Direction::ShrinksPermissiveSet,
    }
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

impl Default for PolicyValues {
    /// The fail-closed deny baseline: what the extension enforces when no
    /// policy has ever applied. Every grant off, every confirmation on
    /// (`policy::tests` derives that from the catalogue); the three windows
    /// are usability defaults, and `hostReverifyMs` 0 (never re-verify) is
    /// the decided exception that keeps the shipped behavior.
    fn default() -> Self {
        PolicyValues {
            cdp_mode: false,
            file_upload_enabled: false,
            handle_dialog_enabled: false,
            page_eval_enabled: false,
            confirm_high_risk_click: true,
            confirm_page_eval: true,
            presence_confirm: true,
            confirm_tab_close: true,
            warn_precise_snapshot: true,
            eval_mask: true,
            host_reverify_ms: Ms::ZERO,
            confirm_grace_ms: Ms::from(60_000u32),
            click_toast_timeout_ms: Ms::from(30_000u32),
            eval_toast_timeout_ms: Ms::from(45_000u32),
            disabled_tools: Vec::new(),
        }
    }
}

impl PolicyValues {
    pub fn copy_field(&mut self, field: PolicyField, from: &PolicyValues) {
        match field.kind() {
            FieldKind::Bool(f) => *self.bool_mut(f) = from.get_bool(f),
            FieldKind::Ms(f) => *self.ms_mut(f) = from.get_ms(f),
            FieldKind::ToolSet(f) => *self.tools_mut(f) = from.get_tools(f).to_vec(),
        }
    }
}

impl PolicyOverlay {
    pub fn has(&self, field: PolicyField) -> bool {
        match field.kind() {
            FieldKind::Bool(f) => self.get_bool(f).is_some(),
            FieldKind::Ms(f) => self.get_ms(f).is_some(),
            FieldKind::ToolSet(f) => self.get_tools(f).is_some(),
        }
    }

    pub fn clear(&mut self, field: PolicyField) {
        match field.kind() {
            FieldKind::Bool(f) => *self.bool_mut(f) = None,
            FieldKind::Ms(f) => *self.ms_mut(f) = None,
            FieldKind::ToolSet(f) => *self.tools_mut(f) = None,
        }
    }

    pub fn set_from(&mut self, field: PolicyField, values: &PolicyValues) {
        match field.kind() {
            FieldKind::Bool(f) => *self.bool_mut(f) = Some(values.get_bool(f)),
            FieldKind::Ms(f) => *self.ms_mut(f) = Some(values.get_ms(f)),
            FieldKind::ToolSet(f) => *self.tools_mut(f) = Some(values.get_tools(f).to_vec()),
        }
    }

    pub fn copy_entry(&mut self, field: PolicyField, from: &PolicyOverlay) {
        match field.kind() {
            FieldKind::Bool(f) => *self.bool_mut(f) = from.get_bool(f),
            FieldKind::Ms(f) => *self.ms_mut(f) = from.get_ms(f),
            FieldKind::ToolSet(f) => {
                *self.tools_mut(f) = from.get_tools(f).map(<[String]>::to_vec);
            }
        }
    }
}

impl Default for PolicyDoc {
    fn default() -> Self {
        PolicyDoc::from_values(&PolicyValues::default(), 0, Vec::new())
    }
}

impl PolicyDoc {
    /// Structural validity of the bytes: the schema version is ours, the revision fits the JS-safe bound, and
    /// `disabledTools` fits its bounds. The parse enforces only the revision bound, so the read path
    /// ([`PolicyStore::baseline_doc`]) runs it, and `set_signed` runs it before any presence prompt. Whether the
    /// revision is acceptable for a write is the store's question, not the bytes'.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.v != POLICY_DOC_VERSION {
            return Err("unsupported policy document version");
        }
        if self.revision > JS_SAFE_INT_MAX {
            return Err("revision exceeds the JS-safe integer bound (2^53 - 1)");
        }
        validate_disabled_tools(&self.disabled_tools)?;
        Ok(())
    }
}

/// The effective policy: the baseline with the overlay's present entries
/// applied over it. Pure field-wise override - whether the overlay actually
/// restricts is checked by the consumer against the direction table, never
/// assumed here.
pub fn fold(baseline: &PolicyValues, overlay: &PolicyOverlay) -> PolicyValues {
    let mut effective = baseline.clone();
    for field in PolicyField::ALL {
        match field.kind() {
            FieldKind::Bool(f) => {
                if let Some(v) = overlay.get_bool(f) {
                    *effective.bool_mut(f) = v;
                }
            }
            FieldKind::Ms(f) => {
                if let Some(v) = overlay.get_ms(f) {
                    *effective.ms_mut(f) = v;
                }
            }
            FieldKind::ToolSet(f) => {
                if let Some(v) = overlay.get_tools(f) {
                    *effective.tools_mut(f) = v.to_vec();
                }
            }
        }
    }
    effective
}

/// `hostReverifyMs` on the permissiveness scale: 0 means never re-verify,
/// the MOST permissive value, so it maps to the top before comparing. No
/// real value collides with the top: every [`Ms`] sits under 2^53.
fn zero_top_rank(ms: Ms) -> u64 {
    if ms == Ms::ZERO {
        u64::MAX
    } else {
        ms.get()
    }
}

/// Whether `field` moves toward its permissive pole in `candidate` relative
/// to `anchor`: the one comparison every verdict reads from, one arm per
/// pole and none per field. The kind-typed handle makes a pole/value
/// mismatch unrepresentable.
fn field_relaxes(field: PolicyField, candidate: &PolicyValues, anchor: &PolicyValues) -> bool {
    match field.kind() {
        FieldKind::Bool(f) => match f.pole() {
            BoolPole::TruePermissive => candidate.get_bool(f) && !anchor.get_bool(f),
            BoolPole::FalsePermissive => !candidate.get_bool(f) && anchor.get_bool(f),
        },
        FieldKind::Ms(f) => match f.order() {
            MsOrder::GrowsPermissive => candidate.get_ms(f) > anchor.get_ms(f),
            MsOrder::GrowsPermissiveZeroTop => {
                zero_top_rank(candidate.get_ms(f)) > zero_top_rank(anchor.get_ms(f))
            }
        },
        // Dropping ANY anchor entry re-enables that tool, whatever else the
        // candidate adds alongside.
        FieldKind::ToolSet(f) => anchor
            .get_tools(f)
            .iter()
            .any(|t| !candidate.get_tools(f).contains(t)),
    }
}

/// Whether `a` and `b` differ on `field` under the lattice: one relaxes the
/// other. For the tool set that is set inequality (order and duplicates
/// carry no meaning), the reading every consumer of a difference wants.
pub(crate) fn field_differs(field: PolicyField, a: &PolicyValues, b: &PolicyValues) -> bool {
    field_relaxes(field, a, b) || field_relaxes(field, b, a)
}

/// Whether `candidate` moves ANY field toward its permissive pole relative
/// to `anchor` (the current effective policy). A relaxation is a capability
/// grant: it needs a fresh presence signature naming the field in its
/// `touched` set, never the free restriction lane.
pub fn relaxes(candidate: &PolicyValues, anchor: &PolicyValues) -> bool {
    PolicyField::ALL
        .iter()
        .any(|f| field_relaxes(*f, candidate, anchor))
}

/// Whether `candidate` moves EVERY field toward its restrictive pole or
/// leaves it in place relative to `anchor`: the exact complement of
/// [`relaxes`], since a policy either grants somewhere or restricts-or-holds
/// everywhere.
pub fn restricts_or_equal(candidate: &PolicyValues, anchor: &PolicyValues) -> bool {
    !relaxes(candidate, anchor)
}

#[cfg(test)]
mod tests;

/// Property-based coverage of the comparison lattice and the fold, the
/// protocol.rs `mod proptests` pattern.
#[cfg(test)]
mod proptests;
