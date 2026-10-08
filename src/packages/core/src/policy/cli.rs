//! CLI runners for `genkan policy`, and the versioned status/history reports
//! `--json` prints. The reports follow the enclave-status precedent: a versioned, typed struct serialized
//! through `serde_json::Value` (sorted keys, a frozen wire contract) with `deny_unknown_fields`.
//!
//! ```text
//! set       -> the signed GRANT lane (set_signed), refused and audited where no host key exists
//! restrict  -> the free lane (restrict)
//! rollback  -> neither a new lane nor a replay: re-derives a past revision's EFFECTIVE policy and re-applies it as a
//!              FRESH write (free when it only tightens, one signed tap when it relaxes anything), so the lower revision
//!              keeps failing the extension's ratchet and the old signed artifact never goes back on the wire
//! --json    -> set and rollback print the post-write PolicyStatusReport on success, PolicyErrorReport on refusal
//! ```

use serde::{Deserialize, Serialize};

use super::plan::{
    entry_state, plan_grant, refused_grant, rollback_inputs, summarize, touched_fields, wire_names,
    HeldPolicy,
};
use super::{
    confirm_unmoved, prepare_grant, restrict, restrict_planned, set_signed, FieldKind, Grant,
    HistoryEntryRef, PolicyField, PolicyHistory, PolicyOverlay, PolicyStore, PolicyValues,
    RollbackPlan,
};
use crate::audit::Surface;
use crate::cli::PolicyCommand;
use crate::presence::{self, TerminalStdin};
use crate::runtime_record::RuntimeRecord as _;

/// The store line for a machine with no baseline, printed by `policy show` and by the doctor row: the deny
/// baseline holds until either grant surface signs the first one.
pub const PRE_CUTOVER_STORE_NOTE: &str =
    "none yet (pre-cutover; the extension keeps enforcing its deny \
                                          baseline until `genkan policy set` or the options page's \
                                          Security policy section signs a baseline)";

// ---- The reports (typed, versioned) ------------------------------------------

/// The store state a status report distinguishes. `none` is the pre-cutover
/// state and is HEALTHY - it is not an error (the extension enforces the deny
/// baseline until a first policy signs). `error` is a present-but-unreadable
/// store, which fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyStoreState {
    /// No policy baseline on this machine yet (pre-cutover; the extension
    /// keeps enforcing its deny baseline).
    None,
    /// A baseline exists and parsed.
    Present,
    /// The store is present but unreadable (corrupt, oversized, wrong
    /// version, or an undecodable baseline): fail closed.
    Error,
}

/// The versioned, machine-readable policy status: the exact object `genkan policy show --json` prints,
/// which the doctor row renders from. A sum tagged on `store` rather than
/// a flat struct, so a `none` report smuggling an effective policy, or a `present` one missing its revision, cannot
/// even deserialize.
///
/// ```text
/// same `store` tag field and field spellings as the flat v1 shape -> wire form VALUE-identical to v1, no `v` bump
/// serialized directly, not through this CLI's sorted-keys Value   -> key order may differ; no consumer reads key order
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "store", rename_all = "lowercase", deny_unknown_fields)]
pub enum PolicyStatusReport {
    /// No policy baseline on this machine yet (pre-cutover, healthy; the
    /// extension keeps enforcing its deny baseline).
    None {
        /// Schema version. `1` today; a newer value must be refused before
        /// any field below is read (fail closed).
        v: u32,
    },
    /// A baseline exists and parsed.
    Present {
        /// Schema version; see the `none` arm.
        v: u32,
        /// The signed baseline's monotonic revision.
        revision: u64,
        /// Whether a signature is stored; the host never self-certifies, the extension verifies against its
        /// pinned key.
        signed: bool,
        /// Whether an unsigned restriction overlay is active on top of the
        /// baseline.
        overlay_active: bool,
        /// The effective policy: the baseline with the overlay folded over
        /// it - what the bridge actually enforces.
        effective: PolicyValues,
    },
    /// The store is present but unreadable (corrupt, oversized, wrong
    /// version, or an undecodable baseline): fail closed.
    Error {
        /// Schema version; see the `none` arm.
        v: u32,
        /// Human detail of the read failure.
        detail: String,
    },
}

impl PolicyStatusReport {
    /// The pre-cutover no-baseline report (healthy).
    fn none() -> Self {
        PolicyStatusReport::None { v: 1 }
    }

    /// The fail-closed unreadable-store report.
    fn error(detail: String) -> Self {
        PolicyStatusReport::Error { v: 1, detail }
    }

    /// The store state this report describes: the tag, as the shared
    /// [`PolicyStoreState`] the doctor verdict branches on without caring
    /// about the arm's payload.
    pub fn store(&self) -> PolicyStoreState {
        match self {
            PolicyStatusReport::None { .. } => PolicyStoreState::None,
            PolicyStatusReport::Present { .. } => PolicyStoreState::Present,
            PolicyStatusReport::Error { .. } => PolicyStoreState::Error,
        }
    }
}

/// The versioned policy-history report: the superseded-revision ring, oldest
/// first, as `genkan policy history --json` prints it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyHistoryReport {
    /// Schema version.
    pub v: u32,
    pub entries: Vec<PolicyHistoryEntryReport>,
}

/// One superseded record, reduced to what a rollback surface needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyHistoryEntryReport {
    /// The record's content identity ([`crate::policy::PolicyHistoryEntry::id`]), what `rollback --entry` names.
    pub id: String,
    /// Whether the superseded baseline carried a signature.
    pub signed: bool,
    /// Whether it carried a restriction overlay.
    pub overlay_active: bool,
    /// Unix seconds when the record stopped being the current store.
    pub superseded_unix: u64,
    /// The record's baseline revision with the policy it held (its baseline under its overlay), what a rollback
    /// to it re-derives; `null` when that historical baseline is unreadable (a damaged ring entry never blocks
    /// the report).
    pub held: Option<HeldPolicy>,
}

/// The failure object the WRITE subcommands print on stdout under `--json`, with the same frozen-wire posture as
/// [`PolicyStatusReport`]; success prints the post-write status report instead, and the exit code stays 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyErrorReport {
    /// Schema version. `1` today; refused first, like the status report's.
    pub v: u32,
    /// The refusal or failure, verbatim - the same words the prose path
    /// prints to stderr.
    pub error: String,
}

// ---- Gathering (I/O) and pure builders --------------------------------------

/// The current policy status, read fail-closed from the store. Infallible: an
/// unreadable store becomes the `error` state, never a panic or a silent
/// default. Public so the doctor row shares exactly this read (the CLI
/// and doctor report the same state).
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
        (Ok(doc), Ok(effective)) => PolicyStatusReport::Present {
            v: 1,
            revision: doc.revision,
            signed: store.sig_b64.is_some(),
            overlay_active: store.overlay.is_some(),
            effective,
        },
    }
}

/// The history report, read fail-closed. `Err` only when the ring itself is
/// unreadable; an absent ring is the empty report.
pub fn gather_history_report() -> Result<PolicyHistoryReport, String> {
    match PolicyHistory::load().map_err(|e| e.to_string())? {
        None => Ok(PolicyHistoryReport {
            v: 1,
            entries: Vec::new(),
        }),
        Some(history) => Ok(history_report(&history)),
    }
}

/// Build a history report from a loaded ring (pure: no disk). A ring entry
/// whose baseline is unreadable keeps its slot with nothing held.
fn history_report(history: &PolicyHistory) -> PolicyHistoryReport {
    PolicyHistoryReport {
        v: 1,
        entries: history
            .entries
            .iter()
            .map(|e| PolicyHistoryEntryReport {
                id: e.id(),
                signed: e.sig_b64.is_some(),
                overlay_active: e.overlay.is_some(),
                superseded_unix: e.superseded_unix,
                held: entry_state(e),
            })
            .collect(),
    }
}

// ---- Rendering (pure) -------------------------------------------------------

/// The human `policy show` text.
fn render_status(r: &PolicyStatusReport) -> String {
    let mut out = String::from("genkan policy\n");
    match r {
        PolicyStatusReport::None { .. } => {
            out.push_str(&format!("store:      {PRE_CUTOVER_STORE_NOTE}\n"));
        }
        PolicyStatusReport::Error { detail, .. } => {
            out.push_str(&format!(
                "store:      present but UNREADABLE ({detail}) - failing closed\n"
            ));
        }
        PolicyStatusReport::Present {
            revision,
            signed,
            overlay_active,
            effective,
            ..
        } => {
            out.push_str(&format!("store:      present (revision {revision})\n"));
            out.push_str(&format!("baseline:   {}\n", signed_line(*signed)));
            out.push_str(&format!(
                "overlay:    {}\n",
                if *overlay_active {
                    "restriction overlay active"
                } else {
                    "none"
                }
            ));
            out.push_str("effective policy:\n");
            out.push_str(&render_values(effective));
        }
    }
    out
}

/// The signed/unsigned line, never claiming host-side verification (the
/// extension verifies against its pinned key; this binary cannot).
fn signed_line(signed: bool) -> &'static str {
    if signed {
        "signed (the extension verifies it against its pinned key; not verifiable here)"
    } else {
        "unsigned"
    }
}

/// The effective values, one field per line in catalogue order.
fn render_values(v: &PolicyValues) -> String {
    let mut out = String::new();
    for field in PolicyField::ALL {
        let value = match field.kind() {
            FieldKind::Bool(f) => if v.get_bool(f) { "on" } else { "off" }.to_string(),
            FieldKind::Ms(f) => v.get_ms(f).to_string(),
            FieldKind::ToolSet(f) => {
                let tools = v.get_tools(f);
                if tools.is_empty() {
                    "(none)".to_string()
                } else {
                    tools.join(",")
                }
            }
        };
        out.push_str(&format!("  {:<22} {value}\n", field.wire_name()));
    }
    out
}

/// The human `policy history` text.
fn render_history(r: &PolicyHistoryReport) -> String {
    if r.entries.is_empty() {
        return "genkan policy history\n  (empty)\n".to_string();
    }
    let mut out = String::from("genkan policy history (oldest first)\n");
    for e in &r.entries {
        let (revision, effective) = match &e.held {
            Some(held) => (
                held.revision.to_string(),
                summarize(&held.effective, PolicyField::ALL),
            ),
            None => ("?".to_string(), "?".to_string()),
        };
        out.push_str(&format!(
            "  revision {revision:<6} {} {} superseded_unix={} entry={} effective={effective}\n",
            if e.signed { "signed  " } else { "unsigned" },
            if e.overlay_active {
                "overlay"
            } else {
                "no-overlay"
            },
            e.superseded_unix,
            e.id,
        ));
    }
    out
}

// ---- The signature-only grant gate -------------------------------------------

/// The CLI's presence prompt for a grant: the typed phrase on the terminal the witness proved. The witness is
/// taken by the lane before `set_signed` runs, so a piped stdin is refused before the host key is looked up
/// (a credential store may raise its unlock dialog on the lookup); `set_signed` runs the prompt after
/// validation, so a malformed request never reaches it.
fn cli_attest(
    reason: &'static str,
    terminal: TerminalStdin,
) -> impl FnOnce() -> Result<presence::PresenceAttestation, presence::PresenceError> {
    move || presence::tty_confirm(reason, terminal)
}

// ---- The subcommand runners -------------------------------------------------

/// Dispatch `genkan policy <sub>` to its lane. Returns the process
/// exit code.
pub fn run_policy(command: PolicyCommand) -> i32 {
    match command {
        PolicyCommand::Show { json } => run_show(json),
        PolicyCommand::History { json } => run_history(json),
        PolicyCommand::Set { overlay, json } => run_set(overlay, json, TerminalStdin::require()),
        PolicyCommand::Restrict { overlay } => run_restrict(overlay),
        PolicyCommand::Rollback {
            revision,
            entry,
            json,
        } => run_rollback(revision, entry, json, TerminalStdin::require()),
    }
}

/// Success tail of a `--json` write: the post-write status report on stdout
/// (exit 0), the exact object `policy show --json` prints.
fn emit_status_json(sub: &str) -> i32 {
    match serde_json::to_value(gather_policy_status()) {
        Ok(value) => {
            println!("{value}");
            0
        }
        Err(e) => {
            eprintln!("{sub} --json failed to serialize the report: {e}");
            1
        }
    }
}

/// Failure tail of a write: the versioned error object on stdout under
/// `--json`, the prose on stderr otherwise; exit 1 either way (the same
/// code the prose path always used).
fn refuse_write(sub: &str, json: bool, error: String) -> i32 {
    if json {
        match serde_json::to_value(&PolicyErrorReport { v: 1, error }) {
            Ok(value) => println!("{value}"),
            Err(e) => eprintln!("{sub} --json failed to serialize the error report: {e}"),
        }
    } else {
        eprintln!("{sub}: {error}");
    }
    1
}

/// `policy show [--json]`: read-only.
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

/// `policy set <field flags> [--json]`: the GRANT lane; the terminal witness comes first, then `set_signed`
/// refuses a keyless machine before any prompt and audits the refusal. Untouched fields carry the current
/// BASELINE values, so the edits fold over the baseline, never the effective policy. Under `--json`, success
/// prints the post-write status report and any refusal the versioned error object.
///
/// `terminal` is the witness, or the precondition failure that kept the dispatcher from constructing one (a
/// piped stdin arrives as the `Err`), taken before anything else runs.
fn run_set(
    overlay: PolicyOverlay,
    json: bool,
    terminal: Result<TerminalStdin, presence::PresenceError>,
) -> i32 {
    match do_set(overlay, terminal) {
        Ok(rung) => {
            if json {
                emit_status_json("policy set")
            } else {
                println!(
                    "policy updated: a fresh signed baseline (authorized by {}).",
                    rung.wire_name()
                );
                0
            }
        }
        Err(error) => refuse_write("policy set", json, error),
    }
}

/// The set lane's work, output-free so the prose and `--json` renderings
/// share one path: witness, fold over the baseline, sign. The touched set is the
/// fields the overlay names, in catalogue order (order carries no meaning in
/// the signed document).
fn do_set(
    overlay: PolicyOverlay,
    terminal: Result<TerminalStdin, presence::PresenceError>,
) -> Result<crate::presence::PresencePath, String> {
    let terminal =
        terminal.map_err(|e| refused_grant(Surface::Cli, &touched_fields(&overlay), &e))?;
    let Grant { values, touched } = plan_grant(&overlay)?;
    set_signed(
        values,
        touched,
        Surface::Cli,
        cli_attest(
            "This policy grant relaxes what the extension lets the bridge do.",
            terminal,
        ),
    )
    .map_err(|e| e.to_string())
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

/// `policy rollback --revision <n> [--json]`: the plan is [`RollbackPlan`]'s (`policy/plan.rs`), and every arm
/// holds to the store the plan was read over, refusing one that moved since as a conflict. Under `--json`
/// stdout is the report alone: success, a no-op included, prints the post-write status report, a refusal the
/// error object. `terminal` is the witness, or the precondition failure that stands for it, consumed only by a
/// relaxing plan.
fn run_rollback(
    revision: u64,
    entry: Option<String>,
    json: bool,
    terminal: Result<TerminalStdin, presence::PresenceError>,
) -> i32 {
    let inputs = match rollback_inputs(revision, entry.map(|id| HistoryEntryRef { id })) {
        Ok(inputs) => inputs,
        Err(error) => return refuse_write("policy rollback", json, error),
    };
    match inputs.plan() {
        RollbackPlan::NoChange => match confirm_unmoved(&inputs.over) {
            Ok(()) if json => emit_status_json("policy rollback"),
            Ok(()) => {
                println!(
                    "policy already matches revision {revision}'s effective policy; nothing to do."
                );
                0
            }
            Err(e) => refuse_write("policy rollback", json, e.to_string()),
        },
        RollbackPlan::Tighten { overlay, fields } => {
            if !json {
                println!(
                    "rolling back to revision {revision}: tighten-only (free) - restricting {}",
                    wire_names(&fields)
                );
            }
            match restrict_planned(overlay, &inputs.over, Surface::Cli) {
                Ok(()) => {
                    if json {
                        emit_status_json("policy rollback")
                    } else {
                        println!(
                            "done: a fresh restriction overlay (the old artifact is never replayed)."
                        );
                        0
                    }
                }
                Err(e) => refuse_write("policy rollback", json, e.to_string()),
            }
        }
        RollbackPlan::Relax(Grant { values, touched }) => {
            let terminal = match terminal {
                Ok(terminal) => terminal,
                Err(e) => {
                    return refuse_write(
                        "policy rollback",
                        json,
                        refused_grant(Surface::Cli, &touched, &e),
                    )
                }
            };
            if !json {
                println!(
                    "rolling back to revision {revision}: this relaxes the effective policy \
                     ({}), so it mints a fresh signed revision (never a replay of the old \
                     artifact) and requires your confirmation.",
                    wire_names(&touched)
                );
            }
            match prepare_grant(values, touched, Surface::Cli)
                .and_then(|prepared| prepared.planned_over(&inputs.over))
                .and_then(|prepared| {
                    prepared.attest_and_commit(cli_attest(
                        "This rollback relaxes the effective policy.",
                        terminal,
                    ))
                }) {
                Ok(rung) => {
                    if json {
                        emit_status_json("policy rollback")
                    } else {
                        println!(
                            "done: a fresh signed revision (authorized by {}).",
                            rung.wire_name()
                        );
                        0
                    }
                }
                Err(e) => refuse_write("policy rollback", json, e.to_string()),
            }
        }
    }
}

#[cfg(test)]
mod tests;
