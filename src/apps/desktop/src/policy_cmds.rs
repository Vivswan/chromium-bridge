//! The app's policy-editor surface (ADR-0032 decision 5): reads, the two
//! write lanes, and rollback.
//!
//! Reads (`policy_status` / `policy_history` / `policy_plan`) and the FREE
//! restriction lane run in-process through `chromium_bridge_core::policy` -
//! plain user-file I/O, no keychain. The signed GRANT lane (`policy_set`)
//! and `policy_rollback` shell out to the bundled signed host binary under
//! `--json`, the `enclave_pair` pattern: the app carries no keychain
//! entitlements (ADR-0026), so the Touch ID sheet a signed write raises
//! must attribute to the host (in-process signing would always degrade to
//! an unsigned floor, even on an enrolled machine). The set argv passes
//! individual field flags, never a whole document, so the CLI folds the
//! edits over the current BASELINE values itself (decision 3: a signed
//! document carries baseline values on fields it does not touch;
//! `set_signed` refuses untouched-field drift).
//!
//! The one exception to the subprocess rule is the GENUINELY UNENROLLED Mac
//! (the bundled host's `enclave-status` reports `supported && key == none`):
//! there is no key to sign with anywhere, the CLI's signature-only lane
//! refuses by design (decision 5), and the app is the one surface entitled
//! to carry its interactive floor for the write - `set` then calls
//! `set_signed` in-process with [`crate::presence_seam::APP_POLICY_FLOOR`],
//! storing an UNSIGNED baseline after the webview's modal confirmation. Any
//! other keyless state (invalid, unreadable, unsupported platform) refuses
//! outright and points at enrollment/repair (fail closed, never a silent
//! degrade).
//!
//! Direction classification (which edits tighten, which relax) is decided
//! HERE, from the core's direction table - the webview only displays the
//! verdict, it never computes which way a change points.

use serde::Serialize;

use chromium_bridge_core::cli::argv;
use chromium_bridge_core::enclave::{EnclaveKeyState, EnclaveStatusReport};
use chromium_bridge_core::policy::{
    fold, gather_policy_status, relaxes, set_signed, PolicyErrorReport, PolicyField, PolicyOverlay,
    PolicyStatusReport, PolicyStore, PolicyStoreState, PolicyValues,
};

use crate::{host, presence_seam};

/// One subprocess policy write, mirroring `EnclaveOutcome`: on success the
/// post-write [`PolicyStatusReport`] the host printed under `--json`; on a
/// refusal the host's own words verbatim (the versioned error object where
/// it parses, the raw transcript where it does not - never smoothed over).
#[derive(Serialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(rename_all = "camelCase")]
pub struct PolicyOutcome {
    pub ok: bool,
    /// The refusal or diagnostics, verbatim; empty on a quiet success.
    pub transcript: String,
    /// The post-write status, parsed from the subprocess's `--json` stdout
    /// (version-gated). `None` on a refusal.
    pub status: Option<PolicyStatusReport>,
}

/// How a draft overlay moves each edited field relative to the currently
/// enforced policy, in catalogue order, by wire name. Computed in Rust from
/// the core's direction table; the webview uses it only to pick the lane
/// and to show the user exactly which fields relax before any prompt.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(rename_all = "camelCase")]
pub struct PolicyPlan {
    /// Edited fields that move toward their permissive pole: applying them
    /// is a grant and takes the signed lane.
    pub relaxes: Vec<String>,
    /// Edited fields that move toward their restrictive pole.
    pub tightens: Vec<String>,
}

/// One present overlay entry, rendered every way a caller needs it: the CLI
/// flag + value spelling `policy_args` parses back, and the entry isolated
/// as a single-field overlay (for per-field direction classification).
struct FieldEdit {
    flag: &'static str,
    value: String,
    single: PolicyOverlay,
}

fn on_off(v: bool) -> String {
    if v { "on" } else { "off" }.to_string()
}

/// The overlay's entry for `field`, or `None` when the field is not edited.
/// Exhaustive with no wildcard, the core's `diff_overlay` posture: a new
/// policy field fails to compile here until it says how the app sends it.
fn field_edit(overlay: &PolicyOverlay, field: PolicyField) -> Option<FieldEdit> {
    let single = |single: PolicyOverlay, flag: &'static str, value: String| FieldEdit {
        flag,
        value,
        single,
    };
    match field {
        PolicyField::CdpMode => overlay.cdp_mode.map(|v| {
            single(
                PolicyOverlay {
                    cdp_mode: Some(v),
                    ..PolicyOverlay::default()
                },
                argv::POLICY_F_CDP_MODE,
                on_off(v),
            )
        }),
        PolicyField::FileUploadEnabled => overlay.file_upload_enabled.map(|v| {
            single(
                PolicyOverlay {
                    file_upload_enabled: Some(v),
                    ..PolicyOverlay::default()
                },
                argv::POLICY_F_FILE_UPLOAD,
                on_off(v),
            )
        }),
        PolicyField::HandleDialogEnabled => overlay.handle_dialog_enabled.map(|v| {
            single(
                PolicyOverlay {
                    handle_dialog_enabled: Some(v),
                    ..PolicyOverlay::default()
                },
                argv::POLICY_F_HANDLE_DIALOG,
                on_off(v),
            )
        }),
        PolicyField::PageEvalEnabled => overlay.page_eval_enabled.map(|v| {
            single(
                PolicyOverlay {
                    page_eval_enabled: Some(v),
                    ..PolicyOverlay::default()
                },
                argv::POLICY_F_PAGE_EVAL,
                on_off(v),
            )
        }),
        PolicyField::ConfirmHighRiskClick => overlay.confirm_high_risk_click.map(|v| {
            single(
                PolicyOverlay {
                    confirm_high_risk_click: Some(v),
                    ..PolicyOverlay::default()
                },
                argv::POLICY_F_CONFIRM_HIGH_RISK_CLICK,
                on_off(v),
            )
        }),
        PolicyField::ConfirmPageEval => overlay.confirm_page_eval.map(|v| {
            single(
                PolicyOverlay {
                    confirm_page_eval: Some(v),
                    ..PolicyOverlay::default()
                },
                argv::POLICY_F_CONFIRM_PAGE_EVAL,
                on_off(v),
            )
        }),
        PolicyField::TouchIdConfirm => overlay.touch_id_confirm.map(|v| {
            single(
                PolicyOverlay {
                    touch_id_confirm: Some(v),
                    ..PolicyOverlay::default()
                },
                argv::POLICY_F_TOUCH_ID_CONFIRM,
                on_off(v),
            )
        }),
        PolicyField::ConfirmTabClose => overlay.confirm_tab_close.map(|v| {
            single(
                PolicyOverlay {
                    confirm_tab_close: Some(v),
                    ..PolicyOverlay::default()
                },
                argv::POLICY_F_CONFIRM_TAB_CLOSE,
                on_off(v),
            )
        }),
        PolicyField::WarnPreciseSnapshot => overlay.warn_precise_snapshot.map(|v| {
            single(
                PolicyOverlay {
                    warn_precise_snapshot: Some(v),
                    ..PolicyOverlay::default()
                },
                argv::POLICY_F_WARN_PRECISE_SNAPSHOT,
                on_off(v),
            )
        }),
        PolicyField::EvalMask => overlay.eval_mask.map(|v| {
            single(
                PolicyOverlay {
                    eval_mask: Some(v),
                    ..PolicyOverlay::default()
                },
                argv::POLICY_F_EVAL_MASK,
                on_off(v),
            )
        }),
        PolicyField::HostReverifyMs => overlay.host_reverify_ms.map(|v| {
            single(
                PolicyOverlay {
                    host_reverify_ms: Some(v),
                    ..PolicyOverlay::default()
                },
                argv::POLICY_F_HOST_REVERIFY_MS,
                v.to_string(),
            )
        }),
        PolicyField::ConfirmGraceMs => overlay.confirm_grace_ms.map(|v| {
            single(
                PolicyOverlay {
                    confirm_grace_ms: Some(v),
                    ..PolicyOverlay::default()
                },
                argv::POLICY_F_CONFIRM_GRACE_MS,
                v.to_string(),
            )
        }),
        PolicyField::ClickToastTimeoutMs => overlay.click_toast_timeout_ms.map(|v| {
            single(
                PolicyOverlay {
                    click_toast_timeout_ms: Some(v),
                    ..PolicyOverlay::default()
                },
                argv::POLICY_F_CLICK_TOAST_TIMEOUT_MS,
                v.to_string(),
            )
        }),
        PolicyField::EvalToastTimeoutMs => overlay.eval_toast_timeout_ms.map(|v| {
            single(
                PolicyOverlay {
                    eval_toast_timeout_ms: Some(v),
                    ..PolicyOverlay::default()
                },
                argv::POLICY_F_EVAL_TOAST_TIMEOUT_MS,
                v.to_string(),
            )
        }),
        PolicyField::DisabledTools => overlay.disabled_tools.as_ref().map(|v| {
            single(
                PolicyOverlay {
                    disabled_tools: Some(v.clone()),
                    ..PolicyOverlay::default()
                },
                argv::POLICY_F_DISABLED_TOOLS,
                v.join(","),
            )
        }),
    }
}

/// The `chromium-bridge policy set` argv for an overlay: individual field
/// flags in catalogue order (never a whole document - the CLI builds the
/// signed document over the current baseline itself). `Err` on an empty
/// overlay, so an edit-less invoke never reaches the subprocess, and on a
/// disabledTools entry the comma-joined argv transport cannot round-trip
/// (a comma splits a name into two, surrounding whitespace trims away, an
/// empty entry drops) - the join below must never sign something other than
/// what the caller stated, so it refuses instead of mangling (the CLI's
/// validate_disabled_tools refuses the same shapes on its side, but a
/// mangled entry would arrive there already split, looking valid).
fn set_args(overlay: &PolicyOverlay) -> Result<Vec<String>, String> {
    if let Some(tools) = &overlay.disabled_tools {
        if let Some(bad) = tools
            .iter()
            .find(|t| t.is_empty() || t.contains(',') || t.trim() != t.as_str())
        {
            return Err(format!(
                "policy set: disabledTools entry {bad:?} cannot round-trip the CLI \
                 transport (empty entries, commas, and surrounding whitespace are \
                 refused, never mangled)"
            ));
        }
    }
    let mut args = vec![argv::POLICY.to_string(), argv::POLICY_SET.to_string()];
    for field in PolicyField::ALL.iter().copied() {
        if let Some(edit) = field_edit(overlay, field) {
            args.push(edit.flag.to_string());
            args.push(edit.value);
        }
    }
    if args.len() == 2 {
        return Err("policy set: the edit names no fields".to_string());
    }
    Ok(args)
}

/// Classify an overlay's edits against `anchor` (the currently enforced
/// policy), per field, from the core's direction primitives. A field whose
/// edit leaves the anchor value in place is dropped: it is neither lane's
/// business.
fn classify(overlay: &PolicyOverlay, anchor: &PolicyValues) -> PolicyPlan {
    let mut plan = PolicyPlan {
        relaxes: Vec::new(),
        tightens: Vec::new(),
    };
    for field in PolicyField::ALL.iter().copied() {
        let Some(edit) = field_edit(overlay, field) else {
            continue;
        };
        let folded = fold(anchor, &edit.single);
        if folded == *anchor {
            continue;
        }
        if relaxes(&folded, anchor) {
            plan.relaxes.push(field.wire_name().to_string());
        } else {
            plan.tightens.push(field.wire_name().to_string());
        }
    }
    plan
}

/// Parse and validate a policy write's `--json` stdout, the exact
/// fail-closed discipline of `host::parse_status_json`: the version gate
/// peeks only `v` and refuses an unrecognized schema BEFORE any other field
/// is trusted, then the typed parse runs over the original bytes (a `Value`
/// re-serialization would have collapsed duplicate keys last-write-wins)
/// with `deny_unknown_fields` refusing an unexpected shape.
fn parse_policy_status_json(stdout: &str) -> Result<PolicyStatusReport, String> {
    let raw: serde_json::Value = serde_json::from_str(stdout)
        .map_err(|e| format!("policy --json did not return JSON: {e}"))?;
    if raw.get("v").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err("policy --json reported an unsupported schema version; \
             the bundled host is newer than this app"
            .to_string());
    }
    serde_json::from_str::<PolicyStatusReport>(stdout)
        .map_err(|e| format!("policy --json had an unexpected shape: {e}"))
}

/// The refusal side of the same contract: the versioned error object,
/// version-gated first, typed-parsed from the original bytes.
fn parse_policy_error_json(stdout: &str) -> Result<PolicyErrorReport, String> {
    let raw: serde_json::Value = serde_json::from_str(stdout)
        .map_err(|e| format!("policy --json did not return JSON: {e}"))?;
    if raw.get("v").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err(
            "policy --json reported an unsupported error-report version; \
             the bundled host is newer than this app"
                .to_string(),
        );
    }
    serde_json::from_str::<PolicyErrorReport>(stdout)
        .map_err(|e| format!("policy --json had an unexpected error shape: {e}"))
}

/// Run one policy write on the bundled host under `--json` and fold its two
/// wire shapes into a [`PolicyOutcome`]. A refusal whose stdout does not
/// parse as the versioned error object (an argv parse error prints only to
/// stderr, for instance) surfaces the raw transcript instead - more
/// verbatim text, never less.
fn run_policy_op(mut args: Vec<String>) -> Result<PolicyOutcome, String> {
    args.push(argv::JSON_FLAG.to_string());
    let run = host::run_host(&args)?;
    if run.ok {
        return Ok(match parse_policy_status_json(run.stdout.trim()) {
            Ok(status) => PolicyOutcome {
                ok: true,
                transcript: run.stderr.trim_end().to_string(),
                status: Some(status),
            },
            // Exit 0 means the write already landed; an unreadable status
            // report must not repaint that success as a failure (the user
            // would retry a write that took). ok stands, the status stays
            // untrusted (None - the UI re-reads the store), and the
            // transcript says exactly what happened, keeping whatever the
            // subprocess said on stderr.
            Err(e) => {
                let stderr = run.stderr.trim_end();
                let mut transcript =
                    format!("the write was applied, but its status report could not be read: {e}");
                if !stderr.is_empty() {
                    transcript.push('\n');
                    transcript.push_str(stderr);
                }
                PolicyOutcome {
                    ok: true,
                    transcript,
                    status: None,
                }
            }
        });
    }
    let transcript = match parse_policy_error_json(run.stdout.trim()) {
        Ok(report) => {
            let stderr = run.stderr.trim_end();
            if stderr.is_empty() {
                report.error
            } else {
                format!("{}\n{stderr}", report.error)
            }
        }
        Err(_) => run.transcript(),
    };
    Ok(PolicyOutcome {
        ok: false,
        transcript,
        status: None,
    })
}

/// The signed GRANT lane's dispatcher: decide the lane from the bundled
/// host's own `enclave-status` report, then either run
/// `chromium-bridge policy set <field flags> --json` as a subprocess (a key
/// exists; the Touch ID sheet and the keyless signature-only refusal,
/// decision 5, are the subprocess's) or - on a GENUINELY unenrolled,
/// Enclave-capable Mac - carry the app's interactive floor for the write
/// ([`set_unenrolled_floor`]). Dialog-first obligation either way: only the
/// webview's explicit confirm handler may reach this (see
/// [`crate::presence_seam::APP_POLICY_FLOOR`]).
pub fn set(overlay: PolicyOverlay) -> Result<PolicyOutcome, String> {
    // Build (and thereby validate) the argv first: an edit-less write never
    // spawns the status subprocess either.
    let args = set_args(&overlay)?;
    let status = host::enclave_status_report()
        .map_err(|e| format!("cannot decide the policy grant lane: {e}; refusing"))?;
    match grant_lane(&status)? {
        GrantLane::SignedSubprocess => run_policy_op(args),
        GrantLane::UnenrolledAppFloor => Ok(set_unenrolled_floor(overlay)),
    }
}

/// Which lane a policy grant takes on this machine (ADR-0032 decision 5).
#[derive(Debug, PartialEq, Eq)]
enum GrantLane {
    /// A usable enrollment key exists: the signed subprocess lane. A Touch
    /// ID refusal there is terminal - never downgraded to the floor.
    SignedSubprocess,
    /// Genuine unenrollment (`supported && key == none`): the hardware rung
    /// is UNAVAILABLE, so the app's documented interactive floor
    /// ([`crate::presence_seam::APP_POLICY_FLOOR`]) may carry the write.
    UnenrolledAppFloor,
}

/// The lane decision, pure over the host's report so it is unit-testable
/// without a subprocess. The authority is the bundled SIGNED host's
/// `enclave-status` - never an in-process keychain lookup, which (from this
/// unentitled app) could misread an enrolled machine as keyless and degrade
/// a signable write to the unsigned floor. Anything that is not provably
/// "key present" or provably "supported and keyless" refuses (fail closed)
/// and says what to do instead of degrading silently.
fn grant_lane(report: &EnclaveStatusReport) -> Result<GrantLane, String> {
    match report.key {
        EnclaveKeyState::Present => Ok(GrantLane::SignedSubprocess),
        EnclaveKeyState::None if report.supported => Ok(GrantLane::UnenrolledAppFloor),
        // key == none on an unsupported platform should not occur (the host
        // reports Unsupported for the key too); refuse rather than guess.
        EnclaveKeyState::None => Err(
            "the host reports no enclave key on a platform without a Secure Enclave; \
             refusing to store a policy baseline (non-macOS ships no grant surface, \
             ADR-0032 decision 8)"
                .to_string(),
        ),
        EnclaveKeyState::Invalid => Err(format!(
            "the enrollment key is REJECTED as untrusted ({}); refusing to write policy. \
             Replace it with `chromium-bridge pair --reset`.",
            report.detail.as_deref().unwrap_or("no detail")
        )),
        EnclaveKeyState::Unsupported => Err(
            "this platform has no Secure Enclave, so a policy grant cannot be signed and \
             the app refuses (non-macOS ships no grant surface, ADR-0032 decision 8)"
                .to_string(),
        ),
        EnclaveKeyState::Error => Err(format!(
            "the enclave key state is unreadable ({}); refusing to write policy (fail closed)",
            report.detail.as_deref().unwrap_or("no detail")
        )),
    }
}

/// The unenrolled-Mac write (ADR-0032 decision 5): the app is the one
/// surface entitled to store an UNSIGNED baseline where hardware presence is
/// genuinely unavailable, and only after its own modal confirmation - the
/// [`crate::presence_seam::APP_POLICY_FLOOR`] obligations. Runs in-process
/// (`set_signed` needs no keychain on this path), folding the edits over the
/// current BASELINE (decision 3) exactly like the CLI's set lane, and
/// returns the same [`PolicyOutcome`] shape the subprocess lane produces so
/// the webview renders both identically.
///
/// Residual, named: a key enrolled between the lane decision and this write
/// is NOT reliably detected. `set_signed` retries the hardware rung first,
/// but from this unentitled app process a real enrolled key can be
/// indistinguishable from absence (the keychain answers not-found without
/// the access-group entitlement), which maps to `Unavailable` and takes the
/// floor. What bounds the window: the lane decision is host-authored (the
/// signed host's own `enclave-status`, never this process's keychain view),
/// it runs back-to-back with this write inside one [`set`] call with no
/// user interaction between, and a pinned extension rejects an unsigned
/// baseline outright - so an unsigned baseline written around a real key is
/// refused at the boundary that matters. This residual belongs in the Phase
/// 5 SECURITY.md threat model alongside the other same-user concessions.
fn set_unenrolled_floor(overlay: PolicyOverlay) -> PolicyOutcome {
    match floor_write(overlay) {
        Ok(()) => PolicyOutcome {
            ok: true,
            transcript: "unsigned baseline stored via the app's confirmation floor (this \
                         Mac has no enclave key). Enroll with `chromium-bridge pair` (or \
                         the Browsers screen) to sign future baselines."
                .to_string(),
            status: Some(gather_policy_status()),
        },
        Err(e) => PolicyOutcome {
            ok: false,
            transcript: e,
            status: None,
        },
    }
}

/// The floor write's work, output-free (the `do_set` shape from the core's
/// CLI): fold over the baseline, name the touched fields, write through the
/// one shared grant seam.
fn floor_write(overlay: PolicyOverlay) -> Result<(), String> {
    let touched: Vec<PolicyField> = PolicyField::ALL
        .iter()
        .copied()
        .filter(|f| field_edit(&overlay, *f).is_some())
        .collect();
    if touched.is_empty() {
        return Err("policy set: the edit names no fields".to_string());
    }
    let base = match PolicyStore::load() {
        Ok(Some(store)) => store
            .baseline_doc()
            .map_err(|e| format!("the current baseline is unreadable ({e}); refusing"))?
            .values(),
        Ok(None) => PolicyValues::default(),
        Err(e) => return Err(format!("the policy store is unreadable ({e}); refusing")),
    };
    let values = fold(&base, &overlay);
    set_signed(
        values,
        touched,
        chromium_bridge_core::audit::Surface::Core,
        presence_seam::APP_POLICY_FLOOR,
    )
    .map(|_rung| ())
    .map_err(|e| e.to_string())
}

/// `chromium-bridge policy rollback --revision <n> --json` as a subprocess:
/// the CLI re-derives that revision's effective policy and re-applies it as
/// a fresh write (free when it only tightens, one signed tap when it
/// relaxes). Refusals - an ambiguous revision included - come back verbatim.
pub fn rollback(revision: u64) -> Result<PolicyOutcome, String> {
    run_policy_op(vec![
        argv::POLICY.to_string(),
        argv::POLICY_ROLLBACK.to_string(),
        argv::POLICY_REVISION_FLAG.to_string(),
        revision.to_string(),
    ])
}

/// The import screen's Adopt lane (ADR-0032 decision 8): [`set`] behind a
/// first-baseline gate. The user confirmed "sign the imported settings as
/// REVISION 1", so a baseline that appeared since the screen surveyed (this
/// app's editor, the CLI, another window) refuses instead of silently
/// re-signing the reviewed values as revision 2 over a write the user never
/// saw. The gate re-reads immediately before the write, shrinking the
/// exposed window from the dialog's dwell time to the write's own start;
/// from `set_signed`'s pre-prompt observation onward the core's Conflict
/// re-check covers the rest. The sliver between this gate and that
/// observation stays open - both racers are the user's own approved writes
/// (each behind its own dialog and prompt), so a collision there re-signs
/// user-reviewed values, never anything unattended.
pub fn adopt(overlay: PolicyOverlay) -> Result<PolicyOutcome, String> {
    if let Err(refusal) = adopt_gate(gather_policy_status().store()) {
        return Ok(PolicyOutcome {
            ok: false,
            transcript: refusal,
            status: None,
        });
    }
    set(overlay)
}

/// The first-baseline gate, pure over the store state: only the
/// no-baseline-yet state may adopt (revision 1 is what consumes the pending
/// import); an existing baseline means the window already closed, and an
/// unreadable store refuses (fail closed).
fn adopt_gate(store: PolicyStoreState) -> Result<(), String> {
    match store {
        PolicyStoreState::None => Ok(()),
        PolicyStoreState::Present => Err(
            "a policy baseline already exists, so the one-time import window is closed; \
             nothing was signed. Manage policy in Security."
                .to_string(),
        ),
        PolicyStoreState::Error => Err(
            "the policy store is unreadable; refusing to sign the imported settings \
             (fail closed)"
                .to_string(),
        ),
    }
}

/// The FREE lane, in-process: `policy::restrict` needs no attestation and
/// no keychain. `Surface::Core` is the surface every in-process app call
/// audits under (there is no dedicated app variant; the same one
/// `kill::release` and `pair_client_with_presence` use here). Returns the
/// fresh status so the editor re-renders from what actually landed.
pub fn restrict(overlay: PolicyOverlay) -> Result<PolicyStatusReport, String> {
    if !PolicyField::ALL
        .iter()
        .any(|f| field_edit(&overlay, *f).is_some())
    {
        return Err("policy restrict: the edit names no fields".to_string());
    }
    chromium_bridge_core::policy::restrict(overlay, chromium_bridge_core::audit::Surface::Core)
        .map_err(|e| e.to_string())?;
    Ok(gather_policy_status())
}

/// Classify a draft's edits for the apply flow (read-only, in-process). The
/// anchor is the current effective policy; with no baseline yet it is the
/// deny defaults (what the extension enforces pre-cutover); an unreadable
/// store refuses - a plan over garbage would be a lane decision over
/// garbage.
pub fn plan(overlay: PolicyOverlay) -> Result<PolicyPlan, String> {
    let anchor = match gather_policy_status() {
        PolicyStatusReport::Error { detail, .. } => {
            return Err(format!(
                "the policy store is unreadable ({detail}); failing closed"
            ));
        }
        PolicyStatusReport::None { .. } => PolicyValues::default(),
        PolicyStatusReport::Present { effective, .. } => effective,
    };
    Ok(classify(&overlay, &anchor))
}

/// The deny baseline (the core's canonical defaults): what the editor seeds
/// its draft from while no baseline exists, so the webview never hardcodes
/// a policy value.
pub fn defaults() -> PolicyValues {
    PolicyValues::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chromium_bridge_core::cli::{policy_args, PolicyCommand};

    fn full_overlay() -> PolicyOverlay {
        PolicyOverlay {
            cdp_mode: Some(true),
            file_upload_enabled: Some(false),
            handle_dialog_enabled: Some(true),
            page_eval_enabled: Some(false),
            confirm_high_risk_click: Some(true),
            confirm_page_eval: Some(false),
            touch_id_confirm: Some(true),
            confirm_tab_close: Some(false),
            warn_precise_snapshot: Some(true),
            eval_mask: Some(false),
            host_reverify_ms: Some(0),
            confirm_grace_ms: Some(45_000),
            click_toast_timeout_ms: Some(30_000),
            eval_toast_timeout_ms: Some(1),
            disabled_tools: Some(vec!["page_eval".into(), "page_upload".into()]),
        }
    }

    #[test]
    fn set_args_round_trip_through_the_cli_parser() {
        // The argv this app builds must parse back through the CLI's own
        // policy_args into the SAME overlay with every edited field touched:
        // the two sides share the argv:: consts at compile time, and this
        // pins the value spellings (on/off, decimal ms, comma-joined tools).
        let overlay = full_overlay();
        let mut argv = vec!["chromium-bridge".to_string()];
        argv.extend(set_args(&overlay).unwrap());
        // run_policy_op appends --json; mirror the exact invocation.
        argv.push(argv::JSON_FLAG.to_string());
        match policy_args(&argv).unwrap() {
            PolicyCommand::Set {
                overlay: parsed,
                touched,
                json,
            } => {
                assert_eq!(parsed, overlay);
                assert_eq!(touched, PolicyField::ALL.to_vec());
                assert!(json, "the app always asks for the typed report");
            }
            other => panic!("expected Set, got {other:?}"),
        }
    }

    #[test]
    fn set_args_carries_only_the_edited_fields() {
        let overlay = PolicyOverlay {
            page_eval_enabled: Some(true),
            confirm_grace_ms: Some(30_000),
            ..PolicyOverlay::default()
        };
        assert_eq!(
            set_args(&overlay).unwrap(),
            vec![
                "policy",
                "set",
                "--page-eval",
                "on",
                "--confirm-grace-ms",
                "30000"
            ]
        );
    }

    #[test]
    fn set_args_refuses_an_empty_edit() {
        // An edit-less write must never spawn the subprocess (the CLI would
        // refuse it too; this is the earlier, cheaper refusal).
        assert!(set_args(&PolicyOverlay::default()).is_err());
    }

    #[test]
    fn set_args_refuses_tools_the_argv_transport_cannot_round_trip() {
        // The set lane comma-joins the list into one argv value; an entry a
        // re-split would mangle (comma inside a name, surrounding whitespace,
        // an empty entry) must be refused BEFORE the join, or the signed
        // document states something other than what the caller passed.
        for bad in ["a,b", " page_eval", "page_eval ", ""] {
            let overlay = PolicyOverlay {
                disabled_tools: Some(vec![bad.into()]),
                ..PolicyOverlay::default()
            };
            let err = set_args(&overlay).unwrap_err();
            assert!(err.contains("round-trip"), "{bad:?} -> {err}");
        }
        // Positive control: ordinary names pass through untouched.
        let overlay = PolicyOverlay {
            disabled_tools: Some(vec!["page_eval".into()]),
            ..PolicyOverlay::default()
        };
        assert!(set_args(&overlay).is_ok());
    }

    #[test]
    fn empty_tools_clear_spells_an_empty_value() {
        // Some(vec![]) is a full clear on the set lane; the CLI parses
        // --disabled-tools "" as the empty set.
        let overlay = PolicyOverlay {
            disabled_tools: Some(Vec::new()),
            ..PolicyOverlay::default()
        };
        assert_eq!(
            set_args(&overlay).unwrap(),
            vec!["policy", "set", "--disabled-tools", ""]
        );
        let mut argv = vec!["chromium-bridge".to_string()];
        argv.extend(set_args(&overlay).unwrap());
        match policy_args(&argv).unwrap() {
            PolicyCommand::Set {
                overlay: parsed, ..
            } => assert_eq!(parsed.disabled_tools, Some(Vec::new())),
            other => panic!("expected Set, got {other:?}"),
        }
    }

    #[test]
    fn classify_splits_relaxing_and_tightening_edits() {
        // Anchor: deny baseline (grants off, confirmations on).
        let anchor = PolicyValues::default();
        let overlay = PolicyOverlay {
            page_eval_enabled: Some(true),          // grant: relaxes
            confirm_page_eval: Some(false),         // skipped confirmation: relaxes
            confirm_grace_ms: Some(30_000),         // below the 60000 default: tightens
            disabled_tools: Some(vec!["x".into()]), // grows the set: tightens
            eval_mask: Some(true),                  // equals the anchor: dropped
            ..PolicyOverlay::default()
        };
        let plan = classify(&overlay, &anchor);
        assert_eq!(plan.relaxes, vec!["pageEvalEnabled", "confirmPageEval"]);
        assert_eq!(plan.tightens, vec!["confirmGraceMs", "disabledTools"]);
    }

    #[test]
    fn classify_gets_the_zero_top_reverify_order_right() {
        // 0 means never re-verify and is the MOST permissive value: moving
        // 0 -> 60000 tightens, 60000 -> 0 relaxes. The one order a naive
        // numeric comparator gets backwards.
        let at_zero = PolicyValues::default();
        assert_eq!(at_zero.host_reverify_ms, 0);
        let overlay = PolicyOverlay {
            host_reverify_ms: Some(60_000),
            ..PolicyOverlay::default()
        };
        let plan = classify(&overlay, &at_zero);
        assert_eq!(plan.tightens, vec!["hostReverifyMs"]);
        assert!(plan.relaxes.is_empty());

        let at_minute = PolicyValues {
            host_reverify_ms: 60_000,
            ..PolicyValues::default()
        };
        let overlay = PolicyOverlay {
            host_reverify_ms: Some(0),
            ..PolicyOverlay::default()
        };
        let plan = classify(&overlay, &at_minute);
        assert_eq!(plan.relaxes, vec!["hostReverifyMs"]);
        assert!(plan.tightens.is_empty());
    }

    #[test]
    fn classify_reads_disabled_tools_as_a_set() {
        let anchor = PolicyValues {
            disabled_tools: vec!["a".into(), "b".into()],
            ..PolicyValues::default()
        };
        // Dropping an entry re-enables a tool: relaxes.
        let plan = classify(
            &PolicyOverlay {
                disabled_tools: Some(vec!["a".into()]),
                ..PolicyOverlay::default()
            },
            &anchor,
        );
        assert_eq!(plan.relaxes, vec!["disabledTools"]);
    }

    #[test]
    fn parse_accepts_a_well_formed_v1_report() {
        let report =
            parse_policy_status_json(r#"{"store":"none","v":1}"#).expect("a v1 report parses");
        assert!(matches!(report, PolicyStatusReport::None { v: 1 }));
        assert_eq!(report.store(), PolicyStoreState::None);
    }

    #[test]
    fn parse_refuses_an_unsupported_schema_version_first() {
        let err =
            parse_policy_status_json(r#"{"store":"none","v":2}"#).expect_err("v2 must be refused");
        assert!(err.contains("unsupported schema version"), "got: {err}");
        let err = parse_policy_status_json(r#"{"store":"none"}"#)
            .expect_err("a missing v must be refused");
        assert!(err.contains("unsupported schema version"), "got: {err}");
    }

    #[test]
    fn parse_refuses_an_unrecognized_shape_and_non_json() {
        let err = parse_policy_status_json(r#"{"store":"none","v":1,"surprise":1}"#)
            .expect_err("an unknown field must be refused");
        assert!(err.contains("unexpected shape"), "got: {err}");
        let err = parse_policy_status_json("not json at all").expect_err("garbage must be refused");
        assert!(err.contains("did not return JSON"), "got: {err}");
    }

    #[test]
    fn parse_refuses_duplicate_keys() {
        // The Value peek collapses duplicates last-write-wins, so this slips
        // the version gate; the typed parse from the original bytes must
        // still refuse the smuggled duplicate.
        let err = parse_policy_status_json(r#"{"v":2,"v":1,"store":"none"}"#)
            .expect_err("a duplicate key must be refused");
        assert!(err.contains("unexpected shape"), "got: {err}");
    }

    #[test]
    fn error_report_parses_under_the_same_gates() {
        let report = parse_policy_error_json(r#"{"v":1,"error":"policy signing refused"}"#)
            .expect("a v1 error report parses");
        assert_eq!(report.error, "policy signing refused");
        let err = parse_policy_error_json(r#"{"v":2,"error":"x"}"#)
            .expect_err("a newer error schema must be refused");
        assert!(err.contains("unsupported"), "got: {err}");
        let err = parse_policy_error_json(r#"{"v":1,"error":"x","surprise":1}"#)
            .expect_err("an unknown field must be refused");
        assert!(err.contains("unexpected error shape"), "got: {err}");
    }

    /// A minimal `enclave-status` report with the given key state and
    /// platform support, for driving [`grant_lane`] purely.
    fn enclave_report(key: EnclaveKeyState, supported: bool) -> EnclaveStatusReport {
        EnclaveStatusReport {
            v: 1,
            supported,
            key_label: "label".into(),
            key,
            public_key_b64: None,
            fingerprint: None,
            detail: Some("detail words".into()),
            policy: None,
            policy_error: None,
        }
    }

    #[test]
    fn grant_lane_takes_the_signed_subprocess_where_a_key_exists() {
        assert_eq!(
            grant_lane(&enclave_report(EnclaveKeyState::Present, true)).unwrap(),
            GrantLane::SignedSubprocess
        );
    }

    #[test]
    fn grant_lane_floors_only_genuine_unenrollment() {
        // supported && key == none is the ONE state entitled to the app's
        // interactive floor (ADR-0032 decision 5).
        assert_eq!(
            grant_lane(&enclave_report(EnclaveKeyState::None, true)).unwrap(),
            GrantLane::UnenrolledAppFloor
        );
    }

    #[test]
    fn grant_lane_refuses_every_ambiguous_or_unsupported_state() {
        // Fail closed with a pointer at the fix, never a silent degrade to
        // the unsigned floor.
        let err = grant_lane(&enclave_report(EnclaveKeyState::Invalid, true)).unwrap_err();
        assert!(err.contains("pair --reset"), "got: {err}");
        assert!(err.contains("detail words"), "got: {err}");
        let err = grant_lane(&enclave_report(EnclaveKeyState::Error, true)).unwrap_err();
        assert!(err.contains("fail closed"), "got: {err}");
        let err = grant_lane(&enclave_report(EnclaveKeyState::Unsupported, false)).unwrap_err();
        assert!(err.contains("no Secure Enclave"), "got: {err}");
        // key == none but unsupported: contradictory, refused, never floored.
        assert!(grant_lane(&enclave_report(EnclaveKeyState::None, false)).is_err());
    }

    #[test]
    fn adopt_gate_admits_only_the_no_baseline_state() {
        // Revision 1 is what consumes the pending import: an existing
        // baseline means the window closed and Adopt must refuse rather than
        // re-sign the reviewed values as revision 2; an unreadable store
        // fails closed.
        assert!(adopt_gate(PolicyStoreState::None).is_ok());
        let err = adopt_gate(PolicyStoreState::Present).unwrap_err();
        assert!(err.contains("already exists"), "got: {err}");
        assert!(err.contains("nothing was signed"), "got: {err}");
        let err = adopt_gate(PolicyStoreState::Error).unwrap_err();
        assert!(err.contains("fail closed"), "got: {err}");
    }
}
