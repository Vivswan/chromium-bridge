//! Command-line entry helpers: argv-based mode selection and the `--help`
//! text. Kept in the library so they are unit-testable and reusable.

/// The subcommand and flag spellings that co-equal surfaces re-issue: the
/// desktop app drives this binary as a subprocess (ADR-0029) and builds argv
/// from these consts, so [`parse`] and the app's Enclave buttons cannot
/// drift apart silently.
pub mod argv {
    /// `pair`: the enrollment ceremony (ADR-0021).
    pub const PAIR: &str = "pair";
    /// `pair --reset`: replace the enrollment key with a fresh one.
    pub const RESET_FLAG: &str = "--reset";
    /// `revoke`: delete the enrollment key (fails closed).
    pub const REVOKE: &str = "revoke";
    /// `enclave-status`: read-only enrollment state report.
    pub const ENCLAVE_STATUS: &str = "enclave-status";
    /// `enclave-status --json`: the machine-readable form the app parses.
    /// Shared by `policy show --json` / `policy history --json`.
    pub const JSON_FLAG: &str = "--json";

    // ---- policy (ADR-0032 decision 5) ----------------------------------------
    // The host-owned policy read/edit surface. The desktop app is a co-equal
    // write surface that drives this binary as a subprocess, so it builds argv
    // from these same literals; keeping them here is what stops the two
    // surfaces from drifting apart.

    /// `policy <sub>`: the host-owned policy read/edit surface.
    pub const POLICY: &str = "policy";
    /// `policy show [--json]`: the current effective policy + store state.
    pub const POLICY_SHOW: &str = "show";
    /// `policy set <field flags>`: the GRANT lane - mint a fresh signed
    /// baseline (Touch ID), signature-only (refuses where no key exists).
    pub const POLICY_SET: &str = "set";
    /// `policy restrict <field flags>`: the FREE lane - apply an unsigned
    /// restriction overlay (no Touch ID; only ever removes capability).
    pub const POLICY_RESTRICT: &str = "restrict";
    /// `policy history [--json]`: the superseded-revision ring.
    pub const POLICY_HISTORY: &str = "history";
    /// `policy rollback --revision <n>`: re-derive a past revision's effective
    /// policy as a FRESH write (never a replay of the old signed artifact).
    pub const POLICY_ROLLBACK: &str = "rollback";
    /// `policy rollback --revision <n>`.
    pub const POLICY_REVISION_FLAG: &str = "--revision";

    // The per-field edit flags shared by `policy set` and `policy restrict`.
    // Boolean flags take `on|off`; the four `*-ms` flags take a non-negative
    // integer; `--disabled-tools` takes a comma-separated list. One flag per
    // policy field, spelled in kebab-case of its camelCase wire name.
    pub const POLICY_F_CDP_MODE: &str = "--cdp-mode";
    pub const POLICY_F_FILE_UPLOAD: &str = "--file-upload";
    pub const POLICY_F_HANDLE_DIALOG: &str = "--handle-dialog";
    pub const POLICY_F_PAGE_EVAL: &str = "--page-eval";
    pub const POLICY_F_CONFIRM_HIGH_RISK_CLICK: &str = "--confirm-high-risk-click";
    pub const POLICY_F_CONFIRM_PAGE_EVAL: &str = "--confirm-page-eval";
    pub const POLICY_F_TOUCH_ID_CONFIRM: &str = "--touch-id-confirm";
    pub const POLICY_F_CONFIRM_TAB_CLOSE: &str = "--confirm-tab-close";
    pub const POLICY_F_WARN_PRECISE_SNAPSHOT: &str = "--warn-precise-snapshot";
    pub const POLICY_F_EVAL_MASK: &str = "--eval-mask";
    pub const POLICY_F_HOST_REVERIFY_MS: &str = "--host-reverify-ms";
    pub const POLICY_F_CONFIRM_GRACE_MS: &str = "--confirm-grace-ms";
    pub const POLICY_F_CLICK_TOAST_TIMEOUT_MS: &str = "--click-toast-timeout-ms";
    pub const POLICY_F_EVAL_TOAST_TIMEOUT_MS: &str = "--eval-toast-timeout-ms";
    pub const POLICY_F_DISABLED_TOOLS: &str = "--disabled-tools";
}

use crate::policy::{PolicyField, PolicyOverlay};

use crate::browsers::Browser;

/// Which mode/subcommand argv selects. Parsed once in `main` and dispatched.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    /// Default (no args): run as the MCP server.
    McpServer,
    /// `--native-host` (or a Chrome-appended extension origin on Windows).
    NativeHost,
    /// `doctor` / `status`: health report, plus `--fix` (repair/register
    /// the native-messaging manifests) and `--list`. Flags are parsed by
    /// [`doctor_args`] in the handler.
    Doctor,
    /// `pair [--reset]`: the enrollment ceremony (ADR-0021).
    Pair { reset: bool },
    /// `revoke`: delete the enrollment key, fail the pinned extension closed.
    Revoke,
    /// `enclave-status [--json]`: read-only enrollment state report. `--json`
    /// emits one machine-readable object for co-equal surfaces (the desktop
    /// app drives this binary as a subprocess and parses it).
    EnclaveStatus { json: bool },
    /// `presence-selftest`: raise one per-action user-presence prompt
    /// (ADR-0031) and report the outcome. A diagnostic that exercises exactly
    /// the Enclave signing the `page_eval`/`page_upload` gate uses, so the
    /// hardware prompt can be seen without a browser. Read-only.
    PresenceSelftest,
    /// `pair-client ...`: add or replace a trusted MCP-client harness in the
    /// allowlist (ADR-0024). Flags are parsed by [`pair_client_args`] in the
    /// handler, so a rich error can be reported instead of a bare help dump.
    PairClient,
    /// `revoke-client --name <label>`: remove a trusted client.
    RevokeClient,
    /// `list-clients`: print the trusted-client allowlist.
    ListClients,
    /// `uninstall ...`: reverse exactly the registrations this project
    /// wrote. Flags are parsed by [`uninstall_args`] in the handler.
    Uninstall,
    /// `kill`: engage the global kill switch (ADR-0030).
    Kill,
    /// `unkill`: explicitly release the global kill switch.
    Unkill,
    /// `audit [--limit <n>]`: print the on-disk audit trail (read-only).
    /// Flags are parsed by the handler for a rich error message.
    Audit,
    /// `policy <sub> ...`: the host-owned policy read/edit surface (ADR-0032).
    /// The subcommand and its flags are parsed by [`policy_args`] in the
    /// handler, so a bad combination reports a clear error rather than a bare
    /// help dump - the `pair-client` / `doctor` pattern.
    Policy,
    /// `-h` / `--help`.
    Help,
    /// Anything unrecognized: print help, exit non-zero.
    Unknown,
}

/// The parsed arguments of `pair-client`. The anchor is exactly one of an
/// explicit hash, an explicit Team ID, or a measurement of this invocation's
/// parent process (`--this-parent`).
#[derive(Debug, PartialEq, Eq)]
pub struct PairClientArgs {
    pub name: String,
    pub anchor: AnchorSpec,
}

/// How `pair-client` was told to identify the client to trust.
#[derive(Debug, PartialEq, Eq)]
pub enum AnchorSpec {
    /// Pin an explicit attested image hash (lowercase hex).
    Hash(String),
    /// Pin an explicit macOS signing Team ID.
    TeamId(String),
    /// Measure this invocation's parent process and pin its hash. Lets a user
    /// enroll the client they launched `pair-client` from.
    ThisParent,
}

/// Chrome launches a Windows native-messaging host directly and appends the
/// calling extension origin (plus a parent-window handle) to its command
/// line. Native-host manifests have no `args` field, so on Windows the
/// registration points straight at chromium-bridge.exe and this origin
/// selects host mode. Unix registrations keep using the explicit
/// `--native-host` wrapper argument.
pub fn is_native_host_mode(args: &[String]) -> bool {
    if args.get(1).map(String::as_str) == Some("--native-host") {
        return true;
    }
    cfg!(windows)
        && args
            .get(1)
            .is_some_and(|arg| arg.starts_with("chrome-extension://"))
}

/// Parse argv into a [`Command`]. Strict: a recognized subcommand followed by
/// an argument it does not take is [`Command::Unknown`], so a typo fails loud
/// instead of silently doing the un-flagged thing.
pub fn parse(args: &[String]) -> Command {
    if is_native_host_mode(args) {
        return Command::NativeHost;
    }
    let rest = args.get(1..).unwrap_or(&[]);
    match rest.first().map(String::as_str) {
        None => Command::McpServer,
        Some("-h" | "--help") => Command::Help,
        // doctor takes flags (--fix/--list/...), parsed by doctor_args in
        // the handler.
        Some("doctor" | "status") => Command::Doctor,
        Some(argv::PAIR) if rest.len() == 1 => Command::Pair { reset: false },
        Some(argv::PAIR)
            if rest.len() == 2 && rest.get(1).is_some_and(|a| a == argv::RESET_FLAG) =>
        {
            Command::Pair { reset: true }
        }
        Some(argv::REVOKE) if rest.len() == 1 => Command::Revoke,
        Some(argv::ENCLAVE_STATUS) if rest.len() == 1 => Command::EnclaveStatus { json: false },
        Some(argv::ENCLAVE_STATUS)
            if rest.len() == 2 && rest.get(1).is_some_and(|a| a == argv::JSON_FLAG) =>
        {
            Command::EnclaveStatus { json: true }
        }
        Some("presence-selftest") if rest.len() == 1 => Command::PresenceSelftest,
        // The client-allowlist subcommands take their own flags, parsed by the
        // handler (pair_client_args) so a bad combination reports a clear error
        // rather than a bare help dump.
        Some("pair-client") => Command::PairClient,
        Some("revoke-client") => Command::RevokeClient,
        Some("list-clients") if rest.len() == 1 => Command::ListClients,
        Some("uninstall") => Command::Uninstall,
        Some("kill") if rest.len() == 1 => Command::Kill,
        Some("unkill") if rest.len() == 1 => Command::Unkill,
        // `audit` takes --limit, parsed by the handler (audit_args) so a bad
        // flag reports a clear error rather than a bare help dump.
        Some("audit") => Command::Audit,
        // `policy` takes a subcommand + flags, parsed by the handler
        // (policy_args) for a rich error - the pair-client pattern.
        Some(argv::POLICY) => Command::Policy,
        Some(_) => Command::Unknown,
    }
}

/// Parse the flags of `pair-client`: a required `--name <label>` and exactly one
/// anchor source (`--hash <hex>`, `--team-id <id>`, or `--this-parent`).
/// Returns a clear error string on any missing, repeated, or conflicting flag
/// (the handler prints it and exits non-zero -- fail loud, never guess).
pub fn pair_client_args(args: &[String]) -> Result<PairClientArgs, String> {
    let mut name: Option<String> = None;
    let mut hash: Option<String> = None;
    let mut team_id: Option<String> = None;
    let mut this_parent = false;

    // Skip argv[0] (binary) and argv[1] ("pair-client").
    let mut it = args.iter().skip(2);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--name" => {
                if name.is_some() {
                    return Err("--name given more than once".into());
                }
                name = Some(take_value(&mut it, "--name")?);
            }
            "--hash" => {
                if hash.is_some() {
                    return Err("--hash given more than once".into());
                }
                hash = Some(take_value(&mut it, "--hash")?);
            }
            "--team-id" => {
                if team_id.is_some() {
                    return Err("--team-id given more than once".into());
                }
                team_id = Some(take_value(&mut it, "--team-id")?);
            }
            "--this-parent" => this_parent = true,
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }

    let name = name.ok_or("pair-client requires --name <label>")?;
    let anchor = match (hash, team_id, this_parent) {
        (Some(h), None, false) => AnchorSpec::Hash(h),
        (None, Some(t), false) => AnchorSpec::TeamId(t),
        (None, None, true) => AnchorSpec::ThisParent,
        (None, None, false) => {
            return Err(
                "pair-client needs one of --hash <hex>, --team-id <id>, or --this-parent".into(),
            )
        }
        _ => return Err("pair-client accepts only ONE of --hash, --team-id, --this-parent".into()),
    };
    Ok(PairClientArgs { name, anchor })
}

/// The `--name <label>` of `revoke-client`. Same strictness as
/// [`pair_client_args`].
pub fn revoke_client_name(args: &[String]) -> Result<String, String> {
    let mut name: Option<String> = None;
    let mut it = args.iter().skip(2);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--name" => {
                if name.is_some() {
                    return Err("--name given more than once".into());
                }
                name = Some(take_value(&mut it, "--name")?);
            }
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }
    name.ok_or_else(|| "revoke-client requires --name <label>".into())
}

/// The parsed form of `doctor` / `status`: exactly one of the read-only
/// report (the default), the resolver-only `--list`, or a `--fix` repair with
/// one targeting mode. An enum rather than flat flags so a contradictory
/// invocation cannot be represented past this boundary.
#[derive(Debug, PartialEq, Eq)]
pub enum DoctorCommand {
    /// Plain `doctor`: the read-only health report.
    Report,
    /// `--list`: print detection/registration state, change nothing.
    List,
    /// `--fix`: (re-)register the targeted browsers. Idempotent, so this is
    /// also the fresh-machine registration path.
    Fix(FixTargets),
}

/// Which registrations `doctor --fix` repairs. Exactly one mode - the
/// exclusivity that used to be a post-hoc check over flat flags is the shape
/// of the type, and `--browser` keys are resolved to [`Browser`]s here at
/// the CLI boundary, so an unknown key fails loud before anything runs.
#[derive(Debug, PartialEq, Eq)]
pub enum FixTargets {
    /// No targeting flag: every browser detected for this user.
    Detected,
    /// `--all`: every known browser, present or not.
    All,
    /// `--browser chrome,brave`: exactly these known browsers.
    Browsers(Vec<Browser>),
    /// `--manifest-dir PATH` (repeatable): exact NativeMessagingHosts dirs,
    /// for Chromium browsers we do not know by name. Absolute paths only.
    ManifestDirs(Vec<String>),
}

/// Parse the flags of `doctor` / `status`. Same strictness as
/// [`pair_client_args`]: conflicting or malformed selections are an error,
/// never a guess.
pub fn doctor_args(args: &[String]) -> Result<DoctorCommand, String> {
    let mut fix = false;
    let mut list = false;
    let mut browsers: Option<Vec<Browser>> = None;
    let mut all = false;
    let mut manifest_dirs: Vec<String> = Vec::new();
    let mut it = args.iter().skip(2);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--fix" => fix = true,
            "--list" => list = true,
            "--browser" => {
                if browsers.is_some() {
                    return Err("--browser given more than once".into());
                }
                let value = take_value(&mut it, "--browser")?;
                let mut keys: Vec<Browser> = Vec::new();
                for key in value.split(',').map(str::trim).filter(|k| !k.is_empty()) {
                    let Some(browser) = Browser::from_key(key) else {
                        return Err(format!(
                            "unknown --browser key {key:?}; known: {}",
                            crate::registration::known_keys()
                        ));
                    };
                    if keys.contains(&browser) {
                        return Err(format!("--browser lists {key:?} twice"));
                    }
                    keys.push(browser);
                }
                if keys.is_empty() {
                    return Err(format!("--browser selected no browser: {value:?}"));
                }
                browsers = Some(keys);
            }
            "--all" => all = true,
            "--manifest-dir" => {
                manifest_dirs.push(manifest_dir_value(&mut it)?);
            }
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }

    let selections = [all, browsers.is_some(), !manifest_dirs.is_empty()]
        .into_iter()
        .filter(|&picked| picked)
        .count();
    if selections > 1 {
        return Err("--all, --browser, and --manifest-dir are mutually exclusive".into());
    }
    if selections > 0 && !fix {
        return Err("--browser/--all/--manifest-dir only target a repair; add --fix".into());
    }
    if list && (fix || selections > 0) {
        return Err("--list is a read-only report and takes no other flags".into());
    }
    if list {
        return Ok(DoctorCommand::List);
    }
    if !fix {
        return Ok(DoctorCommand::Report);
    }
    Ok(DoctorCommand::Fix(if all {
        FixTargets::All
    } else if let Some(browsers) = browsers {
        FixTargets::Browsers(browsers)
    } else if !manifest_dirs.is_empty() {
        FixTargets::ManifestDirs(manifest_dirs)
    } else {
        FixTargets::Detected
    }))
}

/// The parsed form of `policy <sub>` (ADR-0032 decision 5): exactly one of
/// the read surfaces (`show`, `history`), the two write lanes (`set` = the
/// signed GRANT lane, `restrict` = the free lane), or `rollback`. An enum
/// rather than flat flags so a contradictory invocation cannot be represented
/// past this boundary, and each variant carries exactly the data its lane
/// needs.
#[derive(Debug, PartialEq, Eq)]
pub enum PolicyCommand {
    /// `policy show [--json]`: the current effective policy and store state.
    Show { json: bool },
    /// `policy history [--json]`: the superseded-revision ring.
    History { json: bool },
    /// `policy set <field flags>`: the GRANT lane. `overlay` carries the
    /// user's per-field edits and `touched` names exactly the fields they
    /// set; the handler folds `overlay` over the current baseline and signs.
    /// The parser guarantees `touched` is non-empty (an empty write is
    /// refused at the CLI boundary, never handed to the seam).
    Set {
        overlay: PolicyOverlay,
        touched: Vec<PolicyField>,
    },
    /// `policy restrict <field flags>`: the FREE lane - the edits as an
    /// unsigned restriction overlay. Whether they actually restrict is the
    /// seam's direction check, not this parser's.
    Restrict { overlay: PolicyOverlay },
    /// `policy rollback --revision <n>`: re-derive revision `n`'s effective
    /// policy and re-apply it as a FRESH write.
    Rollback { revision: u64 },
}

/// Parse `policy <sub> [flags]`. Same strictness as [`doctor_args`]: an
/// unknown subcommand, a stray argument, a repeated flag, or a malformed
/// value is an error the handler prints, never a guess. `set` / `restrict`
/// demand at least one field flag; `rollback` demands `--revision`.
pub fn policy_args(args: &[String]) -> Result<PolicyCommand, String> {
    // Skip argv[0] (binary) and argv[1] ("policy").
    let mut it = args.iter().skip(2);
    match it.next().map(String::as_str) {
        Some(argv::POLICY_SHOW) => Ok(PolicyCommand::Show {
            json: policy_json_flag(&mut it, argv::POLICY_SHOW)?,
        }),
        Some(argv::POLICY_HISTORY) => Ok(PolicyCommand::History {
            json: policy_json_flag(&mut it, argv::POLICY_HISTORY)?,
        }),
        Some(argv::POLICY_SET) => {
            let (overlay, touched) = policy_field_edits(&mut it, argv::POLICY_SET)?;
            Ok(PolicyCommand::Set { overlay, touched })
        }
        Some(argv::POLICY_RESTRICT) => {
            let (overlay, _touched) = policy_field_edits(&mut it, argv::POLICY_RESTRICT)?;
            Ok(PolicyCommand::Restrict { overlay })
        }
        Some(argv::POLICY_ROLLBACK) => Ok(PolicyCommand::Rollback {
            revision: policy_rollback_revision(&mut it)?,
        }),
        Some(other) => Err(format!(
            "unknown policy subcommand {other:?}; expected: show, set, restrict, history, rollback"
        )),
        None => {
            Err("policy needs a subcommand: show, set, restrict, history, or rollback".to_string())
        }
    }
}

/// The `[--json]` tail of `policy show` / `policy history`: nothing else is
/// accepted, and `--json` at most once.
fn policy_json_flag<'a, I: Iterator<Item = &'a String>>(
    it: &mut I,
    sub: &str,
) -> Result<bool, String> {
    let mut json = false;
    for arg in it {
        match arg.as_str() {
            argv::JSON_FLAG if !json => json = true,
            argv::JSON_FLAG => return Err(format!("policy {sub}: --json given more than once")),
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }
    Ok(json)
}

/// The `--revision <n>` of `policy rollback`: required, exactly once, a
/// non-negative integer.
fn policy_rollback_revision<'a, I: Iterator<Item = &'a String>>(it: &mut I) -> Result<u64, String> {
    let mut revision: Option<u64> = None;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            argv::POLICY_REVISION_FLAG => {
                if revision.is_some() {
                    return Err("--revision given more than once".into());
                }
                let value = take_value(it, argv::POLICY_REVISION_FLAG)?;
                revision = Some(value.parse::<u64>().map_err(|_| {
                    format!("--revision takes a non-negative revision number, got {value:?}")
                })?);
            }
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }
    revision.ok_or_else(|| "policy rollback requires --revision <n>".into())
}

/// Parse the per-field edit flags shared by `set` and `restrict` into an
/// overlay plus the ordered set of fields the user named (the `touched` set a
/// signed write embeds). A repeated field, an unknown flag, a missing value,
/// or a malformed value is an error; an empty edit is refused here so the
/// seam never sees a write that names no field.
fn policy_field_edits<'a, I: Iterator<Item = &'a String>>(
    it: &mut I,
    sub: &str,
) -> Result<(PolicyOverlay, Vec<PolicyField>), String> {
    let mut overlay = PolicyOverlay::default();
    let mut touched: Vec<PolicyField> = Vec::new();
    while let Some(arg) = it.next() {
        let flag = arg.as_str();
        let field =
            policy_field_of_flag(flag).ok_or_else(|| format!("unexpected argument {flag:?}"))?;
        if touched.contains(&field) {
            return Err(format!("{flag} given more than once"));
        }
        let value = take_value(it, flag)?;
        set_overlay_field(&mut overlay, field, flag, &value)?;
        touched.push(field);
    }
    if touched.is_empty() {
        return Err(format!(
            "policy {sub} needs at least one field flag (for example: --page-eval on)"
        ));
    }
    Ok((overlay, touched))
}

/// Map an edit flag to its policy field. `None` for anything that is not a
/// field flag (the caller reports it as unexpected).
fn policy_field_of_flag(flag: &str) -> Option<PolicyField> {
    Some(match flag {
        argv::POLICY_F_CDP_MODE => PolicyField::CdpMode,
        argv::POLICY_F_FILE_UPLOAD => PolicyField::FileUploadEnabled,
        argv::POLICY_F_HANDLE_DIALOG => PolicyField::HandleDialogEnabled,
        argv::POLICY_F_PAGE_EVAL => PolicyField::PageEvalEnabled,
        argv::POLICY_F_CONFIRM_HIGH_RISK_CLICK => PolicyField::ConfirmHighRiskClick,
        argv::POLICY_F_CONFIRM_PAGE_EVAL => PolicyField::ConfirmPageEval,
        argv::POLICY_F_TOUCH_ID_CONFIRM => PolicyField::TouchIdConfirm,
        argv::POLICY_F_CONFIRM_TAB_CLOSE => PolicyField::ConfirmTabClose,
        argv::POLICY_F_WARN_PRECISE_SNAPSHOT => PolicyField::WarnPreciseSnapshot,
        argv::POLICY_F_EVAL_MASK => PolicyField::EvalMask,
        argv::POLICY_F_HOST_REVERIFY_MS => PolicyField::HostReverifyMs,
        argv::POLICY_F_CONFIRM_GRACE_MS => PolicyField::ConfirmGraceMs,
        argv::POLICY_F_CLICK_TOAST_TIMEOUT_MS => PolicyField::ClickToastTimeoutMs,
        argv::POLICY_F_EVAL_TOAST_TIMEOUT_MS => PolicyField::EvalToastTimeoutMs,
        argv::POLICY_F_DISABLED_TOOLS => PolicyField::DisabledTools,
        _ => return None,
    })
}

/// Set the overlay entry for `field` from a flag value, parsing per the
/// field's type. Exhaustive with no wildcard, like the direction table: a new
/// policy field fails to compile here until it says how its CLI value parses.
fn set_overlay_field(
    overlay: &mut PolicyOverlay,
    field: PolicyField,
    flag: &str,
    value: &str,
) -> Result<(), String> {
    match field {
        PolicyField::CdpMode => overlay.cdp_mode = Some(parse_on_off(flag, value)?),
        PolicyField::FileUploadEnabled => {
            overlay.file_upload_enabled = Some(parse_on_off(flag, value)?)
        }
        PolicyField::HandleDialogEnabled => {
            overlay.handle_dialog_enabled = Some(parse_on_off(flag, value)?)
        }
        PolicyField::PageEvalEnabled => {
            overlay.page_eval_enabled = Some(parse_on_off(flag, value)?)
        }
        PolicyField::ConfirmHighRiskClick => {
            overlay.confirm_high_risk_click = Some(parse_on_off(flag, value)?)
        }
        PolicyField::ConfirmPageEval => {
            overlay.confirm_page_eval = Some(parse_on_off(flag, value)?)
        }
        PolicyField::TouchIdConfirm => overlay.touch_id_confirm = Some(parse_on_off(flag, value)?),
        PolicyField::ConfirmTabClose => {
            overlay.confirm_tab_close = Some(parse_on_off(flag, value)?)
        }
        PolicyField::WarnPreciseSnapshot => {
            overlay.warn_precise_snapshot = Some(parse_on_off(flag, value)?)
        }
        PolicyField::EvalMask => overlay.eval_mask = Some(parse_on_off(flag, value)?),
        PolicyField::HostReverifyMs => overlay.host_reverify_ms = Some(parse_ms(flag, value)?),
        PolicyField::ConfirmGraceMs => overlay.confirm_grace_ms = Some(parse_ms(flag, value)?),
        PolicyField::ClickToastTimeoutMs => {
            overlay.click_toast_timeout_ms = Some(parse_ms(flag, value)?)
        }
        PolicyField::EvalToastTimeoutMs => {
            overlay.eval_toast_timeout_ms = Some(parse_ms(flag, value)?)
        }
        PolicyField::DisabledTools => overlay.disabled_tools = Some(parse_tool_list(value)),
    }
    Ok(())
}

/// A boolean policy flag: exactly `on` or `off`, never a guess at `y`/`1`.
fn parse_on_off(flag: &str, value: &str) -> Result<bool, String> {
    match value {
        "on" => Ok(true),
        "off" => Ok(false),
        other => Err(format!("{flag} takes on|off, got {other:?}")),
    }
}

/// A millisecond policy flag: a non-negative integer. The JS-safe bound is
/// enforced by the write seam (`PolicyDoc::validate`), so a friendly parse
/// error here covers only the non-numeric case.
fn parse_ms(flag: &str, value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| format!("{flag} takes a non-negative integer (milliseconds), got {value:?}"))
}

/// The `--disabled-tools` value: a comma-separated list. Empty entries are
/// dropped, so `--disabled-tools ""` is the empty set (a full clear on the
/// `set` lane). The seam bounds the entry count and size.
fn parse_tool_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// The parsed arguments of `uninstall`: only the `--manifest-dir` targets to
/// clear beyond the known-browser table (re-pass what you passed to
/// `doctor --fix`).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct UninstallArgs {
    pub manifest_dirs: Vec<String>,
}

/// Parse the flags of `uninstall`.
pub fn uninstall_args(args: &[String]) -> Result<UninstallArgs, String> {
    let mut parsed = UninstallArgs::default();
    let mut it = args.iter().skip(2);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--manifest-dir" => {
                parsed.manifest_dirs.push(manifest_dir_value(&mut it)?);
            }
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }
    Ok(parsed)
}

/// Take and validate a `--manifest-dir` value: non-empty and absolute, so a
/// registration can never land relative to whatever the current directory
/// happens to be.
fn manifest_dir_value<'a, I: Iterator<Item = &'a String>>(it: &mut I) -> Result<String, String> {
    let value = take_value(it, "--manifest-dir")?;
    if !std::path::Path::new(&value).is_absolute() {
        return Err(format!(
            "--manifest-dir must be an absolute path, got {value:?}"
        ));
    }
    Ok(value)
}

/// Pull the value following a flag, rejecting a missing value or a following
/// flag (`--x --y`) as an error rather than swallowing the next flag.
fn take_value<'a, I: Iterator<Item = &'a String>>(
    it: &mut I,
    flag: &str,
) -> Result<String, String> {
    it.next()
        .filter(|v| !v.starts_with("--"))
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

/// Extract the `--label <name>` argument of `--native-host` mode: the browser
/// name this host announces in its bridge handshake, so one MCP server can
/// tell several browsers apart. Returns `Ok(None)` when no label was given
/// (the server files the connection under its default slot). A missing or
/// flag-shaped value, a repeated `--label`, or a label that
/// [`crate::ipc::BrowserLabel::parse`] rejects is an error - the caller must
/// refuse to start rather than run under a mangled identity. The returned
/// [`crate::ipc::BrowserLabel`] carries that validation to the handshake.
pub fn native_host_label(args: &[String]) -> Result<Option<crate::ipc::BrowserLabel>, String> {
    let mut found: Option<crate::ipc::BrowserLabel> = None;
    let mut it = args.iter().skip(1);
    while let Some(arg) = it.next() {
        if arg == "--label" {
            if found.is_some() {
                return Err("--label given more than once".to_string());
            }
            let value = it
                .next()
                // A following flag (e.g. a bare `--label --native-host`) is a
                // missing value, not a label; valid labels start alphanumeric.
                .filter(|v| !v.starts_with('-'))
                .ok_or_else(|| "--label requires a value".to_string())?;
            let Some(label) = crate::ipc::BrowserLabel::parse(value) else {
                return Err(format!(
                    "invalid --label {value:?}: want 1-32 chars of [A-Za-z0-9._-], starting alphanumeric"
                ));
            };
            found = Some(label);
        }
    }
    Ok(found)
}

pub fn print_help() {
    eprintln!(
        "chromium-bridge {version}\n\
         Bridge an MCP client to a real Chrome via an extension + native host.\n\n\
         USAGE:\n    \
         chromium-bridge                Run as MCP server (for your MCP client)\n    \
         chromium-bridge doctor         Print a read-only health report (alias: status)\n    \
         chromium-bridge doctor --list  List known browsers + registration state (read-only)\n    \
         chromium-bridge doctor --fix [--browser <keys> | --all | --manifest-dir <dir>]\n                                Repair (or first-register) the native-messaging\n                                manifests for your Chromium browsers. Default:\n                                every browser detected for this user; keys:\n                                {browser_keys}\n    \
         chromium-bridge pair           Enroll: mint the Secure Enclave key (macOS)\n    \
         chromium-bridge pair --reset   Replace the enrollment key with a fresh one\n    \
         chromium-bridge revoke         Delete the enrollment key (fails closed)\n    \
         chromium-bridge enclave-status [--json]\n                                Print the enrollment state (--json: machine-readable)\n    \
         chromium-bridge presence-selftest  Raise one Touch ID prompt and report (ADR-0031)\n    \
         chromium-bridge pair-client --name <label> (--this-parent | --hash <hex> | --team-id <id>)\n                                Trust an MCP-client harness (ADR-0024)\n    \
         chromium-bridge revoke-client --name <label>   Untrust a client\n    \
         chromium-bridge list-clients   Print the trusted-client allowlist\n    \
         chromium-bridge uninstall [--manifest-dir <dir>]\n                                Remove exactly the registrations this project wrote\n                                (re-pass any --manifest-dir you registered)\n    \
         chromium-bridge kill           ENGAGE the global kill switch: refuse all bridge\n                                activity, sever browser connections, survive restarts\n    \
         chromium-bridge unkill         Explicitly release the kill switch\n                                (interactive confirmation on the terminal)\n    \
         chromium-bridge audit [--limit <n>]\n                                Print the audit trail (default: last {audit_limit} records)\n    \
         chromium-bridge policy show [--json]\n                                Print the host-owned policy: store state, revision,\n                                signed?, overlay, and the effective values\n    \
         chromium-bridge policy set <field flags>\n                                GRANT lane: mint a fresh SIGNED baseline (Touch ID).\n                                Signature-only: refuses where no enrollment key exists.\n                                Flags: --page-eval on|off, --file-upload on|off,\n                                --confirm-page-eval on|off, --host-reverify-ms <n>,\n                                --disabled-tools a,b, ... (one per policy field)\n    \
         chromium-bridge policy restrict <field flags>\n                                FREE lane: apply an unsigned restriction overlay\n                                (no Touch ID; only ever removes capability)\n    \
         chromium-bridge policy history [--json]\n                                Print the superseded-revision ring\n    \
         chromium-bridge policy rollback --revision <n>\n                                Re-apply revision <n>'s effective policy as a FRESH\n                                write (tighten-only rides restrict free; any\n                                relaxation is one signed tap; never a replay)\n    \
         chromium-bridge --native-host [--label <browser>]\n                                Run as the Chrome native messaging host;\n                                --label names this browser (e.g. chrome, brave)\n                                so one MCP server can address several browsers\n\n\
         Configure your MCP client (Claude Code, Codex, ...) to launch this \
         binary with no arguments as an MCP server; Chrome launches it with \
         --native-host via the host manifest. You normally never invoke either \
         mode by hand.",
        version = env!("CARGO_PKG_VERSION"),
        browser_keys = crate::registration::known_keys(),
        audit_limit = crate::audit::DEFAULT_AUDIT_LIMIT,
    );
}

#[cfg(test)]
mod tests {
    use super::{is_native_host_mode, native_host_label, parse, Command};

    fn args(list: &[&str]) -> Vec<String> {
        std::iter::once("chromium-bridge")
            .chain(list.iter().copied())
            .map(String::from)
            .collect()
    }

    // --manifest-dir demands an absolute path, and "/a" is not absolute on
    // Windows; build one per platform.
    fn abs(tail: &str) -> String {
        if cfg!(windows) {
            format!("C:\\{tail}")
        } else {
            format!("/{tail}")
        }
    }

    #[test]
    fn explicit_native_host_flag_is_recognized() {
        assert!(is_native_host_mode(&args(&["--native-host"])));
        assert_eq!(parse(&args(&["--native-host"])), Command::NativeHost);
    }

    #[test]
    fn label_argument_is_parsed_and_validated() {
        let argv = |rest: &[&str]| -> Vec<String> {
            std::iter::once("chromium-bridge")
                .chain(rest.iter().copied())
                .map(String::from)
                .collect()
        };
        // No --label: None (server files the connection under its default).
        assert_eq!(native_host_label(&argv(&["--native-host"])), Ok(None));
        // A well-formed label is returned, already validated (the
        // BrowserLabel is the proof).
        assert_eq!(
            native_host_label(&argv(&["--native-host", "--label", "brave"])),
            Ok(crate::ipc::BrowserLabel::parse("brave"))
        );
        // Missing value and malformed labels refuse to start (fail closed).
        assert!(native_host_label(&argv(&["--native-host", "--label"])).is_err());
        assert!(native_host_label(&argv(&["--native-host", "--label", "bad label"])).is_err());
        // A following flag is a missing value, not a label.
        assert!(native_host_label(&argv(&["--label", "--native-host"])).is_err());
        // A repeated --label is ambiguous and refused.
        assert!(
            native_host_label(&argv(&["--native-host", "--label", "a", "--label", "b"])).is_err()
        );
    }

    #[cfg(windows)]
    #[test]
    fn chrome_windows_origin_is_recognized() {
        assert!(is_native_host_mode(&[
            "chromium-bridge.exe".into(),
            "chrome-extension://mkjjlmjbcljpcfkfadfmhblmmddkdihf/".into(),
            "--parent-window=123".into(),
        ]));
    }

    #[test]
    fn parse_selects_modes_and_subcommands() {
        assert_eq!(parse(&args(&[])), Command::McpServer);
        assert_eq!(parse(&args(&["-h"])), Command::Help);
        assert_eq!(parse(&args(&["--help"])), Command::Help);
        assert_eq!(parse(&args(&["doctor"])), Command::Doctor);
        assert_eq!(parse(&args(&["status"])), Command::Doctor);
        assert_eq!(parse(&args(&["pair"])), Command::Pair { reset: false });
        assert_eq!(
            parse(&args(&["pair", "--reset"])),
            Command::Pair { reset: true }
        );
        assert_eq!(parse(&args(&["revoke"])), Command::Revoke);
        assert_eq!(
            parse(&args(&["enclave-status"])),
            Command::EnclaveStatus { json: false }
        );
        assert_eq!(
            parse(&args(&["enclave-status", "--json"])),
            Command::EnclaveStatus { json: true }
        );
        assert_eq!(
            parse(&args(&["presence-selftest"])),
            Command::PresenceSelftest
        );
        assert_eq!(parse(&args(&["presence-selftest", "x"])), Command::Unknown);
        assert_eq!(parse(&args(&["kill"])), Command::Kill);
        assert_eq!(parse(&args(&["unkill"])), Command::Unkill);
        assert_eq!(parse(&args(&["audit"])), Command::Audit);
        assert_eq!(parse(&args(&["audit", "--limit", "5"])), Command::Audit);
    }

    #[test]
    fn parse_rejects_typos_and_stray_arguments() {
        assert_eq!(parse(&args(&["pare"])), Command::Unknown);
        assert_eq!(parse(&args(&["pair", "--rest"])), Command::Unknown);
        assert_eq!(parse(&args(&["pair", "--reset", "x"])), Command::Unknown);
        assert_eq!(parse(&args(&["revoke", "--force"])), Command::Unknown);
        assert_eq!(parse(&args(&["enclave-status", "--jso"])), Command::Unknown);
        assert_eq!(
            parse(&args(&["enclave-status", "--json", "x"])),
            Command::Unknown
        );
        // doctor now takes flags; stray arguments are rejected by doctor_args
        // (see doctor_args_fail_loud_on_conflicts_and_bad_values).
        assert!(super::doctor_args(&args(&["doctor", "extra"])).is_err());
    }

    #[test]
    fn doctor_and_uninstall_are_dispatched_with_flags() {
        assert_eq!(parse(&args(&["doctor"])), Command::Doctor);
        assert_eq!(parse(&args(&["status", "--fix"])), Command::Doctor);
        assert_eq!(parse(&args(&["doctor", "--list"])), Command::Doctor);
        assert_eq!(parse(&args(&["uninstall"])), Command::Uninstall);
        // The install verb does not exist; the app (or doctor --fix) registers.
        assert_eq!(parse(&args(&["install"])), Command::Unknown);
    }

    #[test]
    fn doctor_args_parse_fix_and_targeting() {
        use super::{doctor_args, DoctorCommand, FixTargets};
        use crate::browsers::Browser;
        let ok = |list: &[&str]| doctor_args(&args(list)).unwrap();
        assert_eq!(ok(&["doctor"]), DoctorCommand::Report);
        assert_eq!(
            ok(&["doctor", "--fix"]),
            DoctorCommand::Fix(FixTargets::Detected)
        );
        assert_eq!(ok(&["doctor", "--list"]), DoctorCommand::List);
        assert_eq!(
            ok(&["doctor", "--fix", "--all"]),
            DoctorCommand::Fix(FixTargets::All)
        );
        // Keys resolve to typed browsers at this boundary, never later.
        assert_eq!(
            ok(&["doctor", "--fix", "--browser", "chrome, brave"]),
            DoctorCommand::Fix(FixTargets::Browsers(vec![Browser::Chrome, Browser::Brave]))
        );
        assert_eq!(
            ok(&[
                "doctor",
                "--fix",
                "--manifest-dir",
                &abs("a"),
                "--manifest-dir",
                &abs("b")
            ]),
            DoctorCommand::Fix(FixTargets::ManifestDirs(vec![abs("a"), abs("b")]))
        );
    }

    #[test]
    fn doctor_args_fail_loud_on_conflicts_and_bad_values() {
        use super::doctor_args;
        let err = |list: &[&str]| doctor_args(&args(list)).unwrap_err();
        // Targeting flags without --fix never guess.
        assert!(err(&["doctor", "--browser", "chrome"]).contains("add --fix"));
        assert!(err(&["doctor", "--all"]).contains("add --fix"));
        // Conflicting selections never guess.
        assert!(err(&["doctor", "--fix", "--all", "--browser", "chrome"])
            .contains("mutually exclusive"));
        assert!(err(&["doctor", "--list", "--fix"]).contains("read-only"));
        // Malformed values.
        assert!(err(&["doctor", "--fix", "--browser"]).contains("requires a value"));
        assert!(err(&["doctor", "--fix", "--browser", ","]).contains("no browser"));
        assert!(err(&["doctor", "--fix", "--browser", "chrome,chrome"]).contains("twice"));
        // Unknown keys fail loud at the CLI boundary and name the known set.
        assert!(err(&["doctor", "--fix", "--browser", "netscape"]).contains("unknown --browser"));
        assert!(err(&["doctor", "--fix", "--browser", "netscape"]).contains("chrome,chromium"));
        assert!(err(&["doctor", "--fix", "--manifest-dir", "relative/dir"]).contains("absolute"));
        assert!(err(&["doctor", "--fix", "--manifest-dir", ""]).contains("absolute"));
        assert!(err(&["doctor", "--bogus"]).contains("unexpected argument"));
    }

    #[test]
    fn uninstall_args_take_only_manifest_dirs() {
        use super::uninstall_args;
        assert_eq!(
            uninstall_args(&args(&["uninstall", "--manifest-dir", &abs("a")]))
                .unwrap()
                .manifest_dirs,
            vec![abs("a")]
        );
        assert!(uninstall_args(&args(&["uninstall", "--browser", "chrome"])).is_err());
    }

    #[test]
    fn kill_switch_verbs_are_strict() {
        // The kill switch verbs are deliberately strict: no flags, no
        // arguments, so a typo can never half-engage or half-release it.
        assert_eq!(parse(&args(&["kill", "--force"])), Command::Unknown);
        assert_eq!(parse(&args(&["unkill", "now"])), Command::Unknown);
    }

    #[test]
    fn policy_is_dispatched_to_the_handler_parser() {
        // Like pair-client / doctor, `policy` parses to a bare Command and the
        // handler (policy_args) reports rich errors; parse never guesses here.
        assert_eq!(parse(&args(&["policy"])), Command::Policy);
        assert_eq!(parse(&args(&["policy", "show"])), Command::Policy);
        assert_eq!(parse(&args(&["policy", "bogus", "--x"])), Command::Policy);
    }

    #[test]
    fn policy_args_parse_reads_and_writes() {
        use super::{policy_args, PolicyCommand};
        use crate::policy::{PolicyField, PolicyOverlay};
        let ok = |list: &[&str]| policy_args(&args(list)).unwrap();

        assert_eq!(ok(&["policy", "show"]), PolicyCommand::Show { json: false });
        assert_eq!(
            ok(&["policy", "show", "--json"]),
            PolicyCommand::Show { json: true }
        );
        assert_eq!(
            ok(&["policy", "history", "--json"]),
            PolicyCommand::History { json: true }
        );
        assert_eq!(
            ok(&["policy", "rollback", "--revision", "7"]),
            PolicyCommand::Rollback { revision: 7 }
        );

        // set: the edits become an overlay AND a touched set, in flag order.
        assert_eq!(
            ok(&[
                "policy",
                "set",
                "--page-eval",
                "on",
                "--host-reverify-ms",
                "60000",
                "--disabled-tools",
                "page_upload, tab_close",
            ]),
            PolicyCommand::Set {
                overlay: PolicyOverlay {
                    page_eval_enabled: Some(true),
                    host_reverify_ms: Some(60_000),
                    disabled_tools: Some(vec!["page_upload".into(), "tab_close".into()]),
                    ..PolicyOverlay::default()
                },
                touched: vec![
                    PolicyField::PageEvalEnabled,
                    PolicyField::HostReverifyMs,
                    PolicyField::DisabledTools,
                ],
            }
        );

        // restrict: the same parser, overlay only.
        assert_eq!(
            ok(&["policy", "restrict", "--confirm-page-eval", "on"]),
            PolicyCommand::Restrict {
                overlay: PolicyOverlay {
                    confirm_page_eval: Some(true),
                    ..PolicyOverlay::default()
                },
            }
        );
    }

    #[test]
    fn policy_args_fail_loud() {
        use super::policy_args;
        let err = |list: &[&str]| policy_args(&args(list)).unwrap_err();
        // A missing subcommand and an unknown one both name the choices.
        assert!(err(&["policy"]).contains("needs a subcommand"));
        assert!(err(&["policy", "grant"]).contains("unknown policy subcommand"));
        // set / restrict demand at least one field flag.
        assert!(err(&["policy", "set"]).contains("at least one field flag"));
        assert!(err(&["policy", "restrict"]).contains("at least one field flag"));
        // Repeated field, unknown flag, malformed values.
        assert!(
            err(&["policy", "set", "--page-eval", "on", "--page-eval", "off"])
                .contains("given more than once")
        );
        assert!(err(&["policy", "set", "--bogus", "on"]).contains("unexpected argument"));
        assert!(err(&["policy", "set", "--page-eval", "maybe"]).contains("on|off"));
        assert!(err(&["policy", "set", "--host-reverify-ms", "soon"]).contains("integer"));
        // A following flag is a missing value, never a swallowed flag.
        assert!(err(&["policy", "set", "--page-eval", "--host-reverify-ms"])
            .contains("requires a value"));
        // Stray args on the read subcommands, and a missing rollback revision.
        assert!(err(&["policy", "show", "extra"]).contains("unexpected argument"));
        assert!(err(&["policy", "show", "--json", "--json"]).contains("more than once"));
        assert!(err(&["policy", "rollback"]).contains("requires --revision"));
        assert!(err(&["policy", "rollback", "--revision", "x"]).contains("revision number"));
    }
}
