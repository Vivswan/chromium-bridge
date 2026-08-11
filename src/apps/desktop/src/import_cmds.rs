//! The app's first-run legacy-import surface (ADR-0032 decision 8): read the
//! pending-import state from the bundled signed host and turn a recorded
//! legacy bag into a REVIEWABLE suggestion.
//!
//! The read shells out to `chromium-bridge policy pending-import --json` -
//! the `enclave-status` pattern - and parses the versioned
//! [`PendingImportReport`] fail-closed (version gate first, typed parse from
//! the original bytes). The bag is NEVER trusted as policy: it is untrusted
//! JSON a possibly-hostile extension once sent, so the mapping here is a
//! field-by-field salvage into the core's typed [`PolicyValues`] - a value
//! that is not exactly the right shape for its field is dropped (listed in
//! `ignored`), never coerced - and what it produces is only a SUGGESTION the
//! user reviews on the import screen and then signs (the enrolled Touch ID
//! lane or the unenrolled app floor, `crate::policy_cmds::set`). Consuming
//! the pending import is not this module's business at all: revision 1's
//! locked write does that in the core, whatever surface signs it.

use serde::Serialize;
use serde_json::Value;

use chromium_bridge_core::cli::argv;
use chromium_bridge_core::pending_import::PendingImportReport;
use chromium_bridge_core::policy::{
    PolicyField, PolicyOverlay, PolicyValues, DISABLED_TOOLS_MAX_ENTRIES,
    DISABLED_TOOL_NAME_MAX_BYTES, JS_SAFE_INT_MAX,
};

use crate::host;

/// What the first-run import screen renders: the pending-import state with a
/// `present` bag already mapped to a reviewable suggestion. The same tagged
/// sum discipline as the report it derives from - `consumed` cannot smuggle
/// a suggestion, `error` always carries its detail.
#[derive(Debug, PartialEq, Serialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum PendingImportSurvey {
    /// No pending import recorded (healthy; nothing to offer).
    None,
    /// A pending import is recorded: offer the mapped suggestion for review.
    Present { suggestion: ImportSuggestion },
    /// The one-time import already happened; the window is closed.
    Consumed,
    /// The pending-import store exists but is unreadable: fail closed (the
    /// screen shows the notice and offers nothing).
    Error { detail: String },
}

/// The reviewable mapping of a legacy bag (ADR-0032 decision 8): what Adopt
/// would sign, plus exactly which bag keys fed it and which were dropped.
#[derive(Debug, PartialEq, Serialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(rename_all = "camelCase")]
pub struct ImportSuggestion {
    /// The suggested initial policy: the core's deny defaults with every
    /// validly-mapped bag field applied. What revision 1 would carry.
    pub values: PolicyValues,
    /// The same values as a FULL overlay (all 15 fields present): the exact
    /// edit Adopt submits to `policy_set`, so the signed document's touched
    /// set names every field the user reviewed - a superset of whatever the
    /// write relaxes, which is what the grant seam's coverage check needs.
    pub overlay: PolicyOverlay,
    /// Wire names of the policy fields adopted from the bag, catalogue order.
    pub mapped: Vec<String>,
    /// Bag keys NOT adopted, sorted: browser-owned settings (the policy
    /// catalogue does not carry them), unknown keys, and known fields whose
    /// value failed its shape check (dropped whole, never coerced).
    pub ignored: Vec<String>,
}

/// Read the pending-import state from the bundled host
/// (`policy pending-import --json`, read-only) and map a present bag.
pub fn survey() -> Result<PendingImportSurvey, String> {
    Ok(match pending_import_report()? {
        PendingImportReport::None { .. } => PendingImportSurvey::None,
        // `consuming` (P4G-4) is a crash-recovery state: a first-baseline
        // write closed the import window but its baseline was not observed to
        // commit, and the bag was retained exactly so this screen can
        // re-offer it. For the app the two states offer the same action -
        // review and sign - so it maps to `present`; the difference (plants
        // are refused host-side) is the store's business, not this surface's,
        // and a baseline that DID land makes Adopt refuse at its own gate.
        PendingImportReport::Present { bag, .. } | PendingImportReport::Consuming { bag, .. } => {
            PendingImportSurvey::Present {
                suggestion: suggestion_from_bag(&bag),
            }
        }
        PendingImportReport::Consumed { .. } => PendingImportSurvey::Consumed,
        PendingImportReport::Error { detail, .. } => PendingImportSurvey::Error { detail },
    })
}

/// The machine-readable pending-import state, via
/// `policy pending-import --json` on the bundled host, parsed into the
/// core's typed [`PendingImportReport`] - the exact fail-closed discipline
/// of `host::enclave_status_report`.
fn pending_import_report() -> Result<PendingImportReport, String> {
    let run = host::run_host(&[argv::POLICY, argv::POLICY_PENDING_IMPORT, argv::JSON_FLAG])?;
    if !run.ok {
        return Err(format!(
            "policy pending-import failed: {}",
            run.transcript()
        ));
    }
    parse_pending_import_json(run.stdout.trim())
}

/// Parse and validate the subprocess's `--json` stdout: the version gate
/// peeks only `v` and refuses an unrecognized schema BEFORE any other field
/// is trusted, then the typed parse runs over the original bytes with the
/// report's `deny_unknown_fields` refusing an unexpected shape.
fn parse_pending_import_json(stdout: &str) -> Result<PendingImportReport, String> {
    let raw: Value = serde_json::from_str(stdout)
        .map_err(|e| format!("policy pending-import --json did not return JSON: {e}"))?;
    if raw.get("v").and_then(Value::as_u64) != Some(1) {
        return Err(
            "policy pending-import --json reported an unsupported schema version; \
             the bundled host is newer than this app"
                .to_string(),
        );
    }
    serde_json::from_str::<PendingImportReport>(stdout)
        .map_err(|e| format!("policy pending-import --json had an unexpected shape: {e}"))
}

/// Map an untrusted legacy bag onto the deny defaults, field by field. Only
/// keys that name a policy field AND carry exactly the right shape are
/// adopted; everything else lands in `ignored` (fail closed per field - a
/// wrong-typed value must not be coerced into a grant the user never had).
fn suggestion_from_bag(bag: &Value) -> ImportSuggestion {
    let mut values = PolicyValues::default();
    let mut mapped = Vec::new();
    let entries = bag.as_object();
    if let Some(entries) = entries {
        for field in PolicyField::ALL.iter().copied() {
            let Some(raw) = entries.get(field.wire_name()) else {
                continue;
            };
            if adopt_field(&mut values, field, raw) {
                mapped.push(field.wire_name().to_string());
            }
        }
    }
    let mut ignored: Vec<String> = entries
        .map(|entries| {
            entries
                .keys()
                .filter(|key| !mapped.iter().any(|m| m == *key))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    ignored.sort();
    ImportSuggestion {
        overlay: full_overlay(&values),
        values,
        mapped,
        ignored,
    }
}

/// Adopt one bag value into `values` if it has exactly the field's shape.
/// Exhaustive with no wildcard (the core's `diff_overlay` posture): a new
/// policy field fails to compile here until it says how a legacy value maps.
fn adopt_field(values: &mut PolicyValues, field: PolicyField, raw: &Value) -> bool {
    fn bool_of(raw: &Value) -> Option<bool> {
        raw.as_bool()
    }
    /// A millisecond value: a non-negative JSON integer inside the JS-safe
    /// bound (the same bound `PolicyDoc::validate` enforces, checked here so
    /// an over-bound bag value is dropped instead of failing the later sign).
    fn ms_of(raw: &Value) -> Option<u64> {
        raw.as_u64().filter(|v| *v <= JS_SAFE_INT_MAX)
    }
    /// A tool list: strings within the core's entry bounds that survive BOTH
    /// grant lanes byte-for-byte. The enrolled lane rides the CLI argv
    /// (comma-joined, re-split, trimmed), so an entry carrying a comma or
    /// surrounding whitespace would sign something other than what the user
    /// reviewed, and a "--" prefix would be eaten as a flag - all dropped
    /// here (the whole field, never a mangled entry), keeping the suggestion
    /// faithful to the floor lane (which passes the list verbatim) too.
    fn tools_of(raw: &Value) -> Option<Vec<String>> {
        let arr = raw.as_array()?;
        if arr.len() > DISABLED_TOOLS_MAX_ENTRIES {
            return None;
        }
        let mut out = Vec::with_capacity(arr.len());
        for entry in arr {
            let tool = entry.as_str()?;
            if tool.is_empty()
                || tool.len() > DISABLED_TOOL_NAME_MAX_BYTES
                || tool.starts_with("--")
                || tool.contains(',')
                || tool.trim() != tool
            {
                return None;
            }
            out.push(tool.to_string());
        }
        Some(out)
    }
    macro_rules! adopt {
        ($target:expr, $parse:expr) => {
            match $parse(raw) {
                Some(v) => {
                    $target = v;
                    true
                }
                None => false,
            }
        };
    }
    match field {
        PolicyField::CdpMode => adopt!(values.cdp_mode, bool_of),
        PolicyField::FileUploadEnabled => adopt!(values.file_upload_enabled, bool_of),
        PolicyField::HandleDialogEnabled => adopt!(values.handle_dialog_enabled, bool_of),
        PolicyField::PageEvalEnabled => adopt!(values.page_eval_enabled, bool_of),
        PolicyField::ConfirmHighRiskClick => adopt!(values.confirm_high_risk_click, bool_of),
        PolicyField::ConfirmPageEval => adopt!(values.confirm_page_eval, bool_of),
        PolicyField::TouchIdConfirm => adopt!(values.touch_id_confirm, bool_of),
        PolicyField::ConfirmTabClose => adopt!(values.confirm_tab_close, bool_of),
        PolicyField::WarnPreciseSnapshot => adopt!(values.warn_precise_snapshot, bool_of),
        PolicyField::EvalMask => adopt!(values.eval_mask, bool_of),
        PolicyField::HostReverifyMs => adopt!(values.host_reverify_ms, ms_of),
        PolicyField::ConfirmGraceMs => adopt!(values.confirm_grace_ms, ms_of),
        PolicyField::ClickToastTimeoutMs => adopt!(values.click_toast_timeout_ms, ms_of),
        PolicyField::EvalToastTimeoutMs => adopt!(values.eval_toast_timeout_ms, ms_of),
        PolicyField::DisabledTools => adopt!(values.disabled_tools, tools_of),
    }
}

/// Every field of `v` as a present overlay entry: the all-fields-touched
/// edit Adopt submits. Exhaustive, same reason as [`adopt_field`].
fn full_overlay(v: &PolicyValues) -> PolicyOverlay {
    PolicyOverlay {
        cdp_mode: Some(v.cdp_mode),
        file_upload_enabled: Some(v.file_upload_enabled),
        handle_dialog_enabled: Some(v.handle_dialog_enabled),
        page_eval_enabled: Some(v.page_eval_enabled),
        confirm_high_risk_click: Some(v.confirm_high_risk_click),
        confirm_page_eval: Some(v.confirm_page_eval),
        touch_id_confirm: Some(v.touch_id_confirm),
        confirm_tab_close: Some(v.confirm_tab_close),
        warn_precise_snapshot: Some(v.warn_precise_snapshot),
        eval_mask: Some(v.eval_mask),
        host_reverify_ms: Some(v.host_reverify_ms),
        confirm_grace_ms: Some(v.confirm_grace_ms),
        click_toast_timeout_ms: Some(v.click_toast_timeout_ms),
        eval_toast_timeout_ms: Some(v.eval_toast_timeout_ms),
        disabled_tools: Some(v.disabled_tools.clone()),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn parse_accepts_every_v1_report_arm() {
        let present =
            parse_pending_import_json(r#"{"state":"present","v":1,"bag":{"cdpMode":true}}"#)
                .expect("a v1 present report parses");
        assert!(matches!(present, PendingImportReport::Present { .. }));
        assert!(matches!(
            parse_pending_import_json(r#"{"state":"none","v":1}"#).unwrap(),
            PendingImportReport::None { .. }
        ));
        assert!(matches!(
            parse_pending_import_json(r#"{"state":"consuming","v":1,"bag":{"cdpMode":true}}"#)
                .unwrap(),
            PendingImportReport::Consuming { .. }
        ));
        assert!(matches!(
            parse_pending_import_json(r#"{"state":"consumed","v":1}"#).unwrap(),
            PendingImportReport::Consumed { .. }
        ));
        assert!(matches!(
            parse_pending_import_json(r#"{"state":"error","v":1,"detail":"boom"}"#).unwrap(),
            PendingImportReport::Error { .. }
        ));
    }

    #[test]
    fn parse_refuses_an_unsupported_schema_version_first() {
        let err =
            parse_pending_import_json(r#"{"state":"none","v":2}"#).expect_err("v2 must be refused");
        assert!(err.contains("unsupported schema version"), "got: {err}");
        let err = parse_pending_import_json(r#"{"state":"none"}"#)
            .expect_err("a missing v must be refused");
        assert!(err.contains("unsupported schema version"), "got: {err}");
    }

    #[test]
    fn parse_refuses_an_unrecognized_shape_and_non_json() {
        // deny_unknown_fields on the report enum: an unexpected field is a
        // loud refusal, and a consumed arm smuggling a bag cannot parse.
        let err = parse_pending_import_json(r#"{"state":"none","v":1,"surprise":1}"#)
            .expect_err("an unknown field must be refused");
        assert!(err.contains("unexpected shape"), "got: {err}");
        let err = parse_pending_import_json(r#"{"state":"consumed","v":1,"bag":{}}"#)
            .expect_err("a bag on the consumed arm must be refused");
        assert!(err.contains("unexpected shape"), "got: {err}");
        let err =
            parse_pending_import_json("not json at all").expect_err("garbage must be refused");
        assert!(err.contains("did not return JSON"), "got: {err}");
    }

    #[test]
    fn a_valid_bag_maps_onto_the_deny_defaults() {
        let suggestion = suggestion_from_bag(&json!({
            "pageEvalEnabled": true,
            "fileUploadEnabled": false, // valid, equal to the default
            "confirmGraceMs": 30000,
            "disabledTools": ["page_upload", "tab_close"],
        }));
        assert!(suggestion.values.page_eval_enabled);
        assert!(!suggestion.values.file_upload_enabled);
        assert_eq!(suggestion.values.confirm_grace_ms, 30_000);
        assert_eq!(
            suggestion.values.disabled_tools,
            vec!["page_upload".to_string(), "tab_close".to_string()]
        );
        // Unnamed fields keep the deny defaults.
        assert!(!suggestion.values.cdp_mode);
        // The mapped list names exactly the adopted fields, catalogue order.
        assert_eq!(
            suggestion.mapped,
            vec![
                "fileUploadEnabled",
                "pageEvalEnabled",
                "confirmGraceMs",
                "disabledTools"
            ]
        );
        assert!(suggestion.ignored.is_empty());
        // The overlay is FULL: every policy field present, carrying the
        // suggested value, so Adopt's touched set names all 15 fields.
        assert_eq!(suggestion.overlay.page_eval_enabled, Some(true));
        assert_eq!(suggestion.overlay.cdp_mode, Some(false));
        assert!(PolicyField::ALL.iter().all(|f| {
            // A quick presence probe through the serialized form: every wire
            // name appears in the overlay's JSON.
            serde_json::to_value(&suggestion.overlay)
                .unwrap()
                .get(f.wire_name())
                .is_some()
        }));
    }

    #[test]
    fn browser_owned_unknown_and_malformed_keys_are_ignored_never_coerced() {
        let suggestion = suggestion_from_bag(&json!({
            // Browser-owned settings the policy catalogue does not carry.
            "groupTabs": true,
            "allowAllSites": false,
            "uiLanguage": "zh_CN",
            // Known fields with the wrong shape: dropped whole.
            "pageEvalEnabled": "yes",
            "confirmGraceMs": -5,
            "hostReverifyMs": 1.5,
            "disabledTools": ["ok", 7],
            // Unknown junk.
            "zzUnknown": {},
        }));
        // Nothing was adopted: the suggestion is exactly the deny defaults.
        assert_eq!(suggestion.values, PolicyValues::default());
        assert!(suggestion.mapped.is_empty());
        assert_eq!(
            suggestion.ignored,
            vec![
                "allowAllSites",
                "confirmGraceMs",
                "disabledTools",
                "groupTabs",
                "hostReverifyMs",
                "pageEvalEnabled",
                "uiLanguage",
                "zzUnknown"
            ]
        );
    }

    #[test]
    fn out_of_bound_values_are_dropped_not_clamped() {
        // Over the JS-safe bound, an over-long tool list, a flag-shaped and
        // an over-long tool name: each drops its WHOLE field back to the
        // default (a truncated or clamped grant would misstate what the user
        // reviewed).
        let over_js = JS_SAFE_INT_MAX + 1;
        let many: Vec<String> = (0..=DISABLED_TOOLS_MAX_ENTRIES)
            .map(|i| format!("t{i}"))
            .collect();
        let suggestion = suggestion_from_bag(&json!({
            "confirmGraceMs": over_js,
            "disabledTools": many,
        }));
        assert_eq!(suggestion.values, PolicyValues::default());
        assert!(suggestion.mapped.is_empty());
        for tools in [
            json!(["--page-eval"]),
            json!([""]),
            json!(["x".repeat(DISABLED_TOOL_NAME_MAX_BYTES + 1)]),
        ] {
            let s = suggestion_from_bag(&json!({ "disabledTools": tools }));
            assert!(s.values.disabled_tools.is_empty(), "got: {s:?}");
            assert_eq!(s.ignored, vec!["disabledTools"]);
        }
    }

    #[test]
    fn tools_that_cannot_round_trip_the_cli_transport_are_dropped() {
        // The enrolled lane comma-joins the list into one argv value and the
        // CLI re-splits and trims it, so an entry carrying a comma or
        // surrounding whitespace would sign something OTHER than what the
        // user reviewed ("a,b" becomes two entries; " x" becomes "x"). The
        // whole field is dropped instead - never a silently mangled entry.
        for tools in [
            json!(["page_eval,page_upload"]),
            json!([",", ",,"]),
            json!([" page_eval"]),
            json!(["page_eval "]),
            json!(["\tpage_eval"]),
        ] {
            let s = suggestion_from_bag(&json!({ "disabledTools": tools }));
            assert!(s.values.disabled_tools.is_empty(), "got: {s:?}");
            assert_eq!(s.ignored, vec!["disabledTools"], "got: {tools:?}");
        }
        // Positive control: a clean list still maps.
        let s = suggestion_from_bag(&json!({ "disabledTools": ["page_eval", "tab_close"] }));
        assert_eq!(s.values.disabled_tools, vec!["page_eval", "tab_close"]);
    }

    #[test]
    fn a_non_object_bag_maps_to_the_bare_defaults() {
        // Nothing to salvage: the suggestion is the deny defaults, nothing
        // mapped, nothing to list - Adopt would simply sign the defaults and
        // close the window.
        for bag in [json!(null), json!("string"), json!([1, 2])] {
            let suggestion = suggestion_from_bag(&bag);
            assert_eq!(suggestion.values, PolicyValues::default());
            assert!(suggestion.mapped.is_empty());
            assert!(suggestion.ignored.is_empty());
        }
    }
}
