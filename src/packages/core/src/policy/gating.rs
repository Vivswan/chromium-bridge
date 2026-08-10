//! The host-side dispatch gate (ADR-0032 decision 4): before any bridge
//! traffic, refuse a tool whose gating capability grant is off in the
//! effective policy, or that the effective policy lists in `disabledTools`.
//!
//! This is defense in depth for the honest-host path, NOT a substitute for the
//! extension's own gate (decision 5): the extension keeps enforcing at its
//! trust boundary precisely because the host may not be ours. The two states
//! that must not be conflated are the crux (decisions 4 and 5):
//! - a store that is ABSENT means "no policy yet" (pre-cutover) and allows,
//!   matching the pre-ADR-0032 behavior - the gate bites only once a policy
//!   exists;
//! - a store that is present but UNREADABLE or corrupt denies ALL, failing
//!   closed, never a silent default that could mask a tamper.
//!
//! [`verdict`] is pure over the loaded policy so the fail-closed matrix is
//! unit-testable without the runtime directory, exactly as [`crate::kill`]
//! splits its pure `verdict` from the impure `check`; [`check`] is the impure
//! half [`crate::mcp::handler`] injects into the pure router.

use crate::error::{CallError, ToolDisabledReason};

use super::{PolicyField, PolicyStore, PolicyValues};

/// A capability grant (ADR-0032 decision 1): one of the four host-owned fields
/// whose permissive pole GRANTS the bridge a capability. Only a grant can gate
/// a tool at dispatch - the confirmation flags and the millisecond windows
/// only ever remove capability, and `disabledTools` is its own lane - so
/// `Grant` is a distinct type that keeps a confirmation field out of the
/// gating table by construction. [`grants_are_the_true_permissive_fields`]
/// pins the set against the direction catalogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Grant {
    CdpMode,
    FileUpload,
    HandleDialog,
    PageEval,
}

impl Grant {
    /// The policy field this grant is - the source of its wire name (for the
    /// refusal message and audit) and the tie that pins every grant to a
    /// `TruePermissive` field.
    const fn field(self) -> PolicyField {
        match self {
            Grant::CdpMode => PolicyField::CdpMode,
            Grant::FileUpload => PolicyField::FileUploadEnabled,
            Grant::HandleDialog => PolicyField::HandleDialogEnabled,
            Grant::PageEval => PolicyField::PageEvalEnabled,
        }
    }

    /// Whether this grant sits at its permissive (capability-granting) pole in
    /// the effective policy. Every grant is permissive at `true` (its
    /// `TruePermissive` direction), so "on" is simply the flag being set.
    fn is_on(self, p: &PolicyValues) -> bool {
        match self {
            Grant::CdpMode => p.cdp_mode,
            Grant::FileUpload => p.file_upload_enabled,
            Grant::HandleDialog => p.handle_dialog_enabled,
            Grant::PageEval => p.page_eval_enabled,
        }
    }
}

/// Every catalogue tool mapped to the capability grants that gate it, `&[]`
/// when none do (ADR-0032 decision 4). Exhaustive over the catalogue by
/// [`tool_grant_table_covers_every_catalogue_tool_exactly_once`] - the same
/// discipline the sibling `capabilities` table keeps, since tool names are
/// strings and the compiler cannot check string coverage - so a new tool
/// cannot ship without a deliberate answer to "does a grant gate this", and a
/// grant listed against a tool the catalogue dropped fails the same test.
///
/// `cdpMode` gates the whole debugger set (every `Permission::Debugger` tool),
/// because it is the master grant for using Chrome's debugger at all;
/// `page_upload` and `page_handle_dialog` carry their own additional grant on
/// top, so every one of a tool's grants must be on for it to run.
/// [`cdp_mode_gates_exactly_the_debugger_tools`] pins that set against the
/// catalogue's own permission column.
const TOOL_GRANTS: &[(&str, &[Grant])] = &[
    ("list_browsers", &[]),
    ("tab_list", &[]),
    ("tab_focus", &[]),
    ("tab_open", &[]),
    ("tab_close", &[]),
    ("page_snapshot", &[]),
    ("page_click", &[]),
    ("page_fill", &[]),
    ("page_text", &[]),
    ("page_screenshot", &[]),
    ("page_scroll", &[]),
    ("page_wait_for", &[]),
    ("page_eval", &[Grant::PageEval]),
    ("page_snapshot_precise", &[Grant::CdpMode]),
    ("cookie_get", &[]),
    ("storage_get", &[]),
    ("page_navigate", &[]),
    ("page_back", &[]),
    ("page_forward", &[]),
    ("page_reload", &[]),
    ("page_press", &[]),
    ("page_hover", &[]),
    ("page_select", &[]),
    ("console_get", &[Grant::CdpMode]),
    ("page_handle_dialog", &[Grant::CdpMode, Grant::HandleDialog]),
    ("page_upload", &[Grant::CdpMode, Grant::FileUpload]),
];

/// The grants that gate `name`, or `&[]` for an ungated (or unknown) tool. An
/// unknown name is ungated here on purpose: [`crate::tools::dispatch`] refuses
/// it as `UnknownTool`, so inventing a policy refusal for it would only
/// mislabel the same rejection.
fn grants_for(name: &str) -> &'static [Grant] {
    TOOL_GRANTS
        .iter()
        .find(|(tool, _)| *tool == name)
        .map_or(&[], |(_, grants)| *grants)
}

/// The host-side dispatch verdict for `name` against the loaded effective
/// policy (ADR-0032 decision 4). Pure over the load result so the fail-closed
/// matrix is unit-testable without the runtime directory, exactly as
/// [`crate::kill::verdict`] is over the revocation read.
///
/// The three load states carry the crux distinction of decision 5:
/// - `Ok(None)` - NO policy store yet (pre-cutover). Allow, matching the
///   pre-ADR-0032 behavior: the honest-host dispatch check bites only once a
///   policy exists, never before one is written.
/// - `Ok(Some(effective))` - a policy exists. Refuse when a gating grant is
///   off, or the tool is in `disabledTools`; allow otherwise.
/// - `Err(reason)` - the store is present but UNREADABLE or corrupt. Deny
///   ALL: fail closed (decision 5), refusing every tool as if all its grants
///   were off, never a silent default that could mask a tamper.
pub(crate) fn verdict(
    name: &str,
    effective: Result<Option<PolicyValues>, String>,
) -> Result<(), CallError> {
    let effective = match effective {
        Ok(None) => return Ok(()),
        Ok(Some(effective)) => effective,
        Err(reason) => {
            return Err(CallError::ToolDisabled {
                tool: name.to_string(),
                reason: ToolDisabledReason::StoreUnreadable(reason),
            })
        }
    };
    for grant in grants_for(name) {
        if !grant.is_on(&effective) {
            return Err(CallError::ToolDisabled {
                tool: name.to_string(),
                reason: ToolDisabledReason::GrantOff(grant.field().wire_name()),
            });
        }
    }
    if effective.disabled_tools.iter().any(|t| t == name) {
        return Err(CallError::ToolDisabled {
            tool: name.to_string(),
            reason: ToolDisabledReason::InDisabledList,
        });
    }
    Ok(())
}

/// Load the effective policy and compute the dispatch verdict for `name`. The
/// impure half (reads the runtime-directory store) that
/// [`crate::mcp::handler`] injects into the pure router, paired with
/// [`verdict`] the way [`crate::kill::check`] pairs with its own verdict.
pub fn check(name: &str) -> Result<(), CallError> {
    verdict(name, load_effective())
}

/// Collapse the two-step store read into the tri-state [`verdict`] consumes:
/// absent (`Ok(None)`) stays absent, a readable store folds to its effective
/// values, and either read error - the store envelope or the baseline bytes -
/// becomes the deny-all `Err`.
fn load_effective() -> Result<Option<PolicyValues>, String> {
    match PolicyStore::load() {
        Ok(None) => Ok(None),
        Ok(Some(store)) => store.effective().map(Some).map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{direction, Direction};
    use crate::tools::{all, Permission};
    use std::collections::BTreeSet;

    /// The effective policy with every capability grant on and no disabled
    /// tools: the baseline for asserting that a single off grant (or a single
    /// disabled entry) refuses exactly what it should and nothing else.
    fn all_grants_on() -> PolicyValues {
        PolicyValues {
            cdp_mode: true,
            file_upload_enabled: true,
            handle_dialog_enabled: true,
            page_eval_enabled: true,
            ..PolicyValues::default()
        }
    }

    fn catalogue_names() -> BTreeSet<&'static str> {
        all().iter().map(|t| t.name).collect()
    }

    #[test]
    fn tool_grant_table_covers_every_catalogue_tool_exactly_once() {
        let mut table: BTreeSet<&str> = BTreeSet::new();
        for (tool, _) in TOOL_GRANTS {
            assert!(
                table.insert(tool),
                "tool {tool} listed twice in TOOL_GRANTS"
            );
        }
        assert_eq!(
            table,
            catalogue_names(),
            "TOOL_GRANTS must list every catalogue tool exactly once (and no phantom)"
        );
    }

    #[test]
    fn cdp_mode_gates_exactly_the_debugger_tools() {
        let gated_by_cdp: BTreeSet<&str> = TOOL_GRANTS
            .iter()
            .filter(|(_, grants)| grants.contains(&Grant::CdpMode))
            .map(|(tool, _)| *tool)
            .collect();
        let debugger_tools: BTreeSet<&str> = all()
            .iter()
            .filter(|t| t.permission == Permission::Debugger)
            .map(|t| t.name)
            .collect();
        assert_eq!(
            gated_by_cdp, debugger_tools,
            "cdpMode must gate exactly the Permission::Debugger tools"
        );
    }

    #[test]
    fn grants_are_the_true_permissive_fields() {
        let grants = [
            Grant::CdpMode,
            Grant::FileUpload,
            Grant::HandleDialog,
            Grant::PageEval,
        ];
        // Each grant is a capability grant (permissive at true), never a
        // confirmation flag or a window.
        for g in grants {
            assert_eq!(
                direction(g.field()),
                Direction::TruePermissive,
                "grant {g:?} must map to a TruePermissive field"
            );
        }
        // The four grants are exactly the four TruePermissive fields: no
        // capability grant exists that a tool could never gate on.
        let grant_fields: BTreeSet<&str> = grants.iter().map(|g| g.field().wire_name()).collect();
        let true_permissive: BTreeSet<&str> = PolicyField::ALL
            .iter()
            .filter(|f| direction(**f) == Direction::TruePermissive)
            .map(|f| f.wire_name())
            .collect();
        assert_eq!(grant_fields, true_permissive);
    }

    #[test]
    fn absent_policy_allows_every_tool() {
        // Pre-cutover: no store, so the honest-host gate stays out of the way.
        for name in catalogue_names() {
            assert!(
                verdict(name, Ok(None)).is_ok(),
                "absent policy must allow {name}"
            );
        }
    }

    #[test]
    fn corrupt_store_denies_every_tool() {
        // An unreadable store fails closed as deny-all (decision 5), carrying
        // the stable TOOL_DISABLED code for every tool, gated or not.
        for name in catalogue_names() {
            let err = verdict(name, Err("policy store decode: bad".into())).unwrap_err();
            assert!(
                matches!(
                    err,
                    CallError::ToolDisabled {
                        reason: ToolDisabledReason::StoreUnreadable(_),
                        ..
                    }
                ),
                "corrupt store must deny {name}"
            );
            assert_eq!(err.code(), "TOOL_DISABLED");
        }
    }

    #[test]
    fn each_grant_off_refuses_exactly_its_gated_tools_and_allows_others() {
        // With every other grant on, turning one grant off refuses exactly the
        // tools that grant gates and no others.
        for grant in [
            Grant::CdpMode,
            Grant::FileUpload,
            Grant::HandleDialog,
            Grant::PageEval,
        ] {
            let mut eff = all_grants_on();
            match grant {
                Grant::CdpMode => eff.cdp_mode = false,
                Grant::FileUpload => eff.file_upload_enabled = false,
                Grant::HandleDialog => eff.handle_dialog_enabled = false,
                Grant::PageEval => eff.page_eval_enabled = false,
            }
            for name in catalogue_names() {
                let gated = grants_for(name).contains(&grant);
                let refused = verdict(name, Ok(Some(eff.clone()))).is_err();
                assert_eq!(
                    refused, gated,
                    "with {grant:?} off, {name} refused={refused} but gated={gated}"
                );
            }
        }
    }

    #[test]
    fn a_grant_off_refusal_names_the_grant() {
        let mut eff = all_grants_on();
        eff.page_eval_enabled = false;
        let err = verdict("page_eval", Ok(Some(eff))).unwrap_err();
        assert!(matches!(
            err,
            CallError::ToolDisabled {
                reason: ToolDisabledReason::GrantOff("pageEvalEnabled"),
                ..
            }
        ));
    }

    #[test]
    fn disabled_tools_membership_refuses_only_the_listed_tool() {
        let mut eff = all_grants_on();
        eff.disabled_tools = vec!["tab_list".to_string()];
        let err = verdict("tab_list", Ok(Some(eff.clone()))).unwrap_err();
        assert!(matches!(
            err,
            CallError::ToolDisabled {
                reason: ToolDisabledReason::InDisabledList,
                ..
            }
        ));
        assert_eq!(err.code(), "TOOL_DISABLED");
        // A tool absent from the list, and otherwise ungated, still runs.
        assert!(verdict("tab_focus", Ok(Some(eff))).is_ok());
    }

    #[test]
    fn a_disabled_tool_gates_even_a_debugger_tool_with_its_grants_on() {
        // disabledTools is independent of the grant gates: a tool with every
        // grant on is still refused when the policy disables it by name.
        let mut eff = all_grants_on();
        eff.disabled_tools = vec!["page_upload".to_string()];
        let err = verdict("page_upload", Ok(Some(eff))).unwrap_err();
        assert!(matches!(
            err,
            CallError::ToolDisabled {
                reason: ToolDisabledReason::InDisabledList,
                ..
            }
        ));
    }
}
