//! CLI runners for `chromium-bridge policy`, and the versioned status/history reports
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

use super::{
    field_differs, fold, restrict, restricts_or_equal, set_signed, FieldKind, PolicyDoc,
    PolicyField, PolicyHistory, PolicyOverlay, PolicyStore, PolicyValues,
};
use crate::audit::Surface;
use crate::cli::PolicyCommand;
use crate::enclave::base64_decode;
use crate::presence::{self, TerminalStdin};
use crate::runtime_record::RuntimeRecord as _;

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

/// The versioned, machine-readable policy status: the exact object `chromium-bridge policy show --json` prints,
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
        /// Whether the stored baseline carries an enclave signature (`true`)
        /// or not (`false`). Host-side this is
        /// only "a signature is stored" - the host never self-certifies; the
        /// extension verifies it against its pinned key.
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
/// first, as `chromium-bridge policy history --json` prints it.
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

/// The versioned failure object the WRITE subcommands print on stdout under
/// `--json` (`policy set --json` / `policy rollback --json`): the same
/// frozen-wire posture as [`PolicyStatusReport`] - a consumer refuses an
/// unrecognized `v` before trusting `error`, and `deny_unknown_fields` makes
/// an unexpected shape a loud refusal. Success prints the post-write
/// [`PolicyStatusReport`] instead; the exit code (1) is unchanged from the
/// prose path.
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
    match r {
        PolicyStatusReport::None { .. } => {
            out.push_str(
                "store:      none yet (pre-cutover; the extension keeps enforcing its deny\n            \
                 baseline until a baseline is signed via\n            \
                 `chromium-bridge policy set`)\n",
            );
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

// ---- The signature-only grant gate -------------------------------------------

/// The CLI's presence prompt for a grant: the terminal witness, then the typed phrase. `set_signed` runs it
/// after validation, so a piped stdin is refused at the prompt and a malformed request never reaches it.
fn cli_attest(
    reason: &'static str,
) -> impl FnOnce() -> Result<presence::PresenceAttestation, presence::PresenceError> {
    move || TerminalStdin::require().and_then(|terminal| presence::tty_confirm(reason, terminal))
}

// ---- Rollback planning (pure) -----------------------------------------------

/// What a rollback will do, decided by diffing a past revision's effective
/// policy against the current effective policy.
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
    /// (the signed document carries baseline values on fields it
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
            values.copy_field(field, target);
        }
        RollbackPlan::Relax {
            values,
            touched: fields.clone(),
            fields,
        }
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

/// Comma-joined wire names, for the plan description.
fn wire_names(fields: &[PolicyField]) -> String {
    fields
        .iter()
        .map(|f| f.wire_name())
        .collect::<Vec<_>>()
        .join(",")
}

// ---- The subcommand runners -------------------------------------------------

/// Dispatch `chromium-bridge policy <sub>` to its lane. Returns the process
/// exit code.
pub fn run_policy(command: PolicyCommand) -> i32 {
    match command {
        PolicyCommand::Show { json } => run_show(json),
        PolicyCommand::History { json } => run_history(json),
        PolicyCommand::Set { overlay, json } => run_set(overlay, json),
        PolicyCommand::Restrict { overlay } => run_restrict(overlay),
        PolicyCommand::Rollback { revision, json } => run_rollback(revision, json),
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

/// `policy set <field flags> [--json]`: the GRANT lane; `set_signed` refuses a keyless machine before any
/// prompt and audits the refusal. Untouched fields carry the current BASELINE values, so the edits fold over
/// the baseline, never the effective policy. Under `--json`, success prints the post-write status report and
/// any refusal the versioned error object.
fn run_set(overlay: PolicyOverlay, json: bool) -> i32 {
    match do_set(overlay) {
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
/// share one path: gate, fold over the baseline, sign. The touched set is the
/// fields the overlay names, in catalogue order (order carries no meaning in
/// the signed document).
fn do_set(overlay: PolicyOverlay) -> Result<crate::presence::PresencePath, String> {
    let touched: Vec<PolicyField> = PolicyField::ALL
        .iter()
        .copied()
        .filter(|field| overlay.has(*field))
        .collect();
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
        Surface::Cli,
        cli_attest("This policy grant relaxes what the extension lets the bridge do."),
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

/// `policy rollback --revision <n> [--json]`: re-derive revision `n`'s
/// effective policy and re-apply it as a FRESH write - tighten-only rides
/// `restrict` free, any relaxation is one `set_signed` tap. The old signed
/// artifact is never written back: a lower revision must keep failing the
/// extension's ratchet. Under `--json` the planning prose is suppressed
/// (stdout is the report, nothing else): success - a no-op included -
/// prints the post-write status report, any refusal the versioned error
/// object.
fn run_rollback(revision: u64, json: bool) -> i32 {
    let inputs = match rollback_inputs(revision) {
        Ok(inputs) => inputs,
        Err(error) => return refuse_write("policy rollback", json, error),
    };
    match plan_rollback(&inputs.target, &inputs.current, &inputs.baseline) {
        RollbackPlan::NoChange => {
            if json {
                emit_status_json("policy rollback")
            } else {
                println!(
                    "policy already matches revision {revision}'s effective policy; nothing to do."
                );
                0
            }
        }
        RollbackPlan::Tighten { overlay, fields } => {
            if !json {
                println!(
                    "rolling back to revision {revision}: tighten-only (free) - restricting {}",
                    wire_names(&fields)
                );
            }
            match restrict(overlay, Surface::Cli) {
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
        RollbackPlan::Relax {
            values,
            touched,
            fields,
        } => {
            if !json {
                println!(
                    "rolling back to revision {revision}: this relaxes the effective policy \
                     ({}), so it mints a fresh signed revision (never a replay of the old \
                     artifact) and requires your confirmation.",
                    wire_names(&fields)
                );
            }
            match set_signed(
                values,
                touched,
                Surface::Cli,
                cli_attest("This rollback relaxes the effective policy."),
            ) {
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

/// The three effective/baseline states a rollback is planned over.
struct RollbackInputs {
    /// The target revision's effective policy, re-derived from the history.
    target: PolicyValues,
    /// The current effective policy.
    current: PolicyValues,
    /// The current baseline's values (what a relaxing plan folds over).
    baseline: PolicyValues,
}

/// The disk reads behind a rollback, output-free so the prose and `--json`
/// renderings share one path.
fn rollback_inputs(revision: u64) -> Result<RollbackInputs, String> {
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

#[cfg(test)]
mod tests;
