//! The host-side dispatch gate: before any bridge traffic, refuse a tool
//! whose gating capability grant is off in the effective policy, or that the
//! effective policy lists in `disabledTools`.
//!
//! This is defense in depth for the honest-host path, NOT a substitute for the
//! extension's own gate: the extension keeps enforcing at its trust boundary
//! precisely because the host may not be ours. The two states that must not
//! be conflated are the crux:
//! - a store that is ABSENT means "no policy yet" (pre-cutover) and allows,
//!   matching the pre-policy behavior - the gate bites only once a policy
//!   exists;
//! - a store that is present but UNREADABLE or corrupt denies ALL, failing
//!   closed, never a silent default that could mask a tamper.
//!
//! [`verdict`] is pure over the loaded policy so the fail-closed matrix is
//! unit-testable without the runtime directory, exactly as [`crate::kill`]
//! splits its pure `verdict` from the impure `check`; [`check`] is the impure
//! half [`crate::mcp::handler`] injects into the pure router.

use crate::error::{CallError, ToolDisabledReason};
use crate::tools::Tool;

use super::{PolicyField, PolicyStore, PolicyValues};
use crate::runtime_record::RuntimeRecord as _;

/// A capability grant: one of the four host-owned fields whose permissive
/// pole GRANTS the bridge a capability. Only a grant can gate a tool at
/// dispatch - the confirmation flags and the millisecond windows only ever
/// remove capability, and `disabledTools` is its own lane - so `Grant` is a
/// distinct type that keeps a confirmation field out of a tool's record by
/// construction. `grants_are_the_true_permissive_fields` pins the set against
/// the direction catalogue. Which tools each grant gates is the tool
/// catalogue's ([`Tool::grants`] and [`Tool::required_grants`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grant {
    CdpMode,
    FileUpload,
    HandleDialog,
    PageEval,
}

impl Grant {
    /// The policy field this grant is - the source of its wire name (for the
    /// refusal message, the audit, and the generated TypeScript) and the tie
    /// that pins every grant to a `TruePermissive` field.
    pub const fn field(self) -> PolicyField {
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

/// The host-side dispatch verdict for `tool` against the loaded effective policy. Pure over the load result so
/// the fail-closed matrix is unit-testable without the runtime directory, exactly as [`crate::kill::verdict`] is
/// over the revocation read. The three load states carry the crux:
///
/// ```text
/// `Ok(None)`             -> no policy store yet (pre-cutover): allow; the gate bites only once a policy exists
/// `Ok(Some(effective))`  -> refuse when a gating grant is off or the tool is in `disabledTools`, else allow
/// `Err(reason)`          -> store present but UNREADABLE or corrupt: deny ALL, never a silent default that
///                           could mask a tamper
/// ```
pub(crate) fn verdict(
    tool: &Tool,
    effective: Result<Option<PolicyValues>, String>,
) -> Result<(), CallError> {
    let effective = match effective {
        Ok(None) => return Ok(()),
        Ok(Some(effective)) => effective,
        Err(reason) => {
            return Err(CallError::ToolDisabled {
                tool: tool.name.to_string(),
                reason: ToolDisabledReason::StoreUnreadable(reason),
            })
        }
    };
    for grant in tool.required_grants() {
        if !grant.is_on(&effective) {
            return Err(CallError::ToolDisabled {
                tool: tool.name.to_string(),
                reason: ToolDisabledReason::GrantOff(grant.field().wire_name()),
            });
        }
    }
    if effective.disabled_tools.iter().any(|t| t == tool.name) {
        return Err(CallError::ToolDisabled {
            tool: tool.name.to_string(),
            reason: ToolDisabledReason::InDisabledList,
        });
    }
    Ok(())
}

/// Load the effective policy and compute the dispatch verdict for `tool`. The
/// impure half (reads the runtime-directory store) that
/// [`crate::mcp::handler`] injects into the pure router, paired with
/// [`verdict`] the way [`crate::kill::check`] pairs with its own verdict.
pub fn check(tool: &Tool) -> Result<(), CallError> {
    verdict(tool, load_effective())
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
    use crate::policy::{direction, BoolPole, Direction};
    use crate::tools::{all, ToolId};
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

    #[test]
    fn grants_are_the_true_permissive_fields() {
        let grants = [
            Grant::CdpMode,
            Grant::FileUpload,
            Grant::HandleDialog,
            Grant::PageEval,
        ];
        let true_permissive = Direction::Bool(BoolPole::TruePermissive);
        // Each grant is a capability grant (permissive at true), never a
        // confirmation flag or a window.
        for g in grants {
            assert_eq!(
                direction(g.field()),
                true_permissive,
                "grant {g:?} must map to a TruePermissive field"
            );
        }
        // The four grants are exactly the four TruePermissive fields: no
        // capability grant exists that a tool could never gate on.
        let grant_fields: BTreeSet<&str> = grants.iter().map(|g| g.field().wire_name()).collect();
        let true_permissive_fields: BTreeSet<&str> = PolicyField::ALL
            .iter()
            .filter(|f| direction(**f) == true_permissive)
            .map(|f| f.wire_name())
            .collect();
        assert_eq!(grant_fields, true_permissive_fields);
    }

    #[test]
    fn absent_policy_allows_every_tool() {
        // Pre-cutover: no store, so the honest-host gate stays out of the way.
        for tool in all() {
            assert!(
                verdict(&tool, Ok(None)).is_ok(),
                "absent policy must allow {}",
                tool.name
            );
        }
    }

    #[test]
    fn corrupt_store_denies_every_tool() {
        // An unreadable store fails closed as deny-all, carrying the stable
        // TOOL_DISABLED code for every tool, gated or not.
        for tool in all() {
            let err = verdict(&tool, Err("policy store decode: bad".into())).unwrap_err();
            assert!(
                matches!(
                    err,
                    CallError::ToolDisabled {
                        reason: ToolDisabledReason::StoreUnreadable(_),
                        ..
                    }
                ),
                "corrupt store must deny {}",
                tool.name
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
            for tool in all() {
                let gated = tool.required_grants().any(|g| g == grant);
                let refused = verdict(&tool, Ok(Some(eff.clone()))).is_err();
                assert_eq!(
                    refused, gated,
                    "with {grant:?} off, {} refused={refused} but gated={gated}",
                    tool.name
                );
            }
        }
    }

    #[test]
    fn a_grant_off_refusal_names_the_grant() {
        let mut eff = all_grants_on();
        eff.page_eval_enabled = false;
        let err = verdict(&ToolId::PageEval.tool(), Ok(Some(eff))).unwrap_err();
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
        let err = verdict(&ToolId::TabList.tool(), Ok(Some(eff.clone()))).unwrap_err();
        assert!(matches!(
            err,
            CallError::ToolDisabled {
                reason: ToolDisabledReason::InDisabledList,
                ..
            }
        ));
        assert_eq!(err.code(), "TOOL_DISABLED");
        // A tool absent from the list, and otherwise ungated, still runs.
        assert!(verdict(&ToolId::TabFocus.tool(), Ok(Some(eff))).is_ok());
    }

    #[test]
    fn a_disabled_tool_gates_even_a_debugger_tool_with_its_grants_on() {
        // disabledTools is independent of the grant gates: a tool with every
        // grant on is still refused when the policy disables it by name.
        let mut eff = all_grants_on();
        eff.disabled_tools = vec!["page_upload".to_string()];
        let err = verdict(&ToolId::PageUpload.tool(), Ok(Some(eff))).unwrap_err();
        assert!(matches!(
            err,
            CallError::ToolDisabled {
                reason: ToolDisabledReason::InDisabledList,
                ..
            }
        ));
    }
}
