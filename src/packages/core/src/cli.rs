//! The argv boundary. [`parse`] reads argv exactly once into a typed
//! [`Command`], and no handler sees argv again. The newtypes a subcommand
//! carries (`BrowserLabel`, `HashDigest`, `SignerId`, `ClientName`, `Ms`,
//! `Browser`) are parsed here; values with their own trust boundary (a tool
//! list) are validated at the seam that stores them.

use std::path::PathBuf;

use clap::builder::ArgGroup;
use clap::{Arg, ArgAction, ArgMatches, Args, FromArgMatches, Parser, Subcommand};
use itertools::Itertools as _;

use crate::allowlist::ClientName;
use crate::audit::DEFAULT_AUDIT_LIMIT;
use crate::browsers::{Browser, Scope};
use crate::ipc::{BrowserLabel, HashDigest, SignerId};
use crate::lang::{UiLang, UI_LANGUAGES};
use crate::policy::{FieldKind, Ms, PolicyField, PolicyOverlay};
use crate::registration::known_keys;

/// Which mode or subcommand argv selected, with its arguments fully typed.
#[derive(Debug, PartialEq, Eq, Subcommand)]
pub enum Command {
    /// No arguments: the MCP server, as an MCP client's server config launches it.
    #[command(skip)]
    McpServer,
    /// `--native-host [--label <browser>]`: the Chrome-spawned native messaging host.
    #[command(skip)]
    NativeHost { label: Option<BrowserLabel> },
    /// Read-only health report; --fix repairs the native-messaging registrations
    #[command(visible_alias = "status")]
    Doctor(DoctorCommand),
    /// Enroll: mint the host identity key the extension pins
    Pair {
        /// Replace the host key with a fresh one
        #[arg(long)]
        reset: bool,
        /// Keep the key in a 0600 file in the runtime directory instead of the OS credential store
        #[arg(long)]
        file_store: bool,
    },
    /// Forget one browser's enrolled authenticators, or start over with --all
    Revoke(RevokeTarget),
    /// Print the host key state
    EnclaveStatus {
        /// One machine-readable object instead of prose
        #[arg(long)]
        json: bool,
    },
    /// Trust an MCP-client harness
    PairClient(PairClientArgs),
    /// Untrust a client; a live broker drops it at once
    RevokeClient {
        /// The client's label in the allowlist
        #[arg(long, value_name = "LABEL")]
        name: String,
    },
    /// Print the trusted-client allowlist
    ListClients,
    /// Remove exactly the registrations this project wrote
    Uninstall(UninstallArgs),
    /// ENGAGE the global kill switch: refuse all bridge activity, sever browser connections, survive restarts
    Kill,
    /// Release the kill switch (interactive confirmation on the terminal)
    Unkill,
    /// Print the audit trail, oldest first
    Audit {
        /// How many of the newest records to print
        #[arg(long, default_value_t = DEFAULT_AUDIT_LIMIT, value_name = "N")]
        limit: usize,
    },
    /// Read or edit the host-owned policy
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// Read or set the display language the options page shows (`show` when no subcommand is given)
    Lang(LangCommand),
}

#[derive(Debug, PartialEq, Eq)]
pub enum LangCommand {
    Show,
    Set { value: UiLang },
}

#[derive(Args)]
struct LangFlags {
    #[command(subcommand)]
    action: Option<LangAction>,
}

#[derive(Subcommand)]
enum LangAction {
    /// Print the current display language
    Show,
    /// Apply a display language; a connected browser swaps on the host's next push
    Set {
        #[arg(value_parser = ui_lang, value_name = "LANG", help = format!("One of: {}", UI_LANGUAGES.join(", ")))]
        value: UiLang,
    },
}

impl From<LangFlags> for LangCommand {
    fn from(flags: LangFlags) -> Self {
        match flags.action {
            None | Some(LangAction::Show) => LangCommand::Show,
            Some(LangAction::Set { value }) => LangCommand::Set { value },
        }
    }
}

/// `doctor` / `status` as exactly one of its four forms, so a contradictory
/// invocation cannot be represented past this boundary.
#[derive(Debug, PartialEq, Eq)]
pub enum DoctorCommand {
    /// The read-only health report; `json` prints it as one object.
    Report { json: bool },
    /// `--list`: detection and registration state, nothing changed.
    List,
    /// `--paths`: the runtime dir and lock path this environment resolves
    /// to, with neither created nor probed.
    Paths,
    /// `--fix`: (re-)register the targeted browsers in one scope. Idempotent,
    /// so this is also the fresh-machine registration path.
    Fix { targets: FixTargets, scope: Scope },
}

/// Which registrations `doctor --fix` repairs. Exactly one mode.
#[derive(Debug, PartialEq, Eq)]
pub enum FixTargets {
    /// No targeting flag: every browser detected for this user.
    Detected,
    /// `--all`: every known browser, present or not.
    All,
    /// `--browser chrome,brave`: exactly these known browsers, each once.
    Browsers(Vec<Browser>),
    /// `--manifest-dir DIR` (repeatable): exact NativeMessagingHosts dirs,
    /// for Chromium browsers we do not know by name. Absolute paths only.
    ManifestDirs(Vec<PathBuf>),
}

/// The flag surface clap parses `doctor` from; [`DoctorCommand`] is the
/// typed result.
#[derive(Args)]
#[command(group(ArgGroup::new("target").multiple(false).requires("fix")))]
struct DoctorFlags {
    /// Repair (or first-register) the native-messaging manifests
    #[arg(long, conflicts_with_all = ["list", "paths", "json"])]
    fix: bool,
    /// List known browsers and their registration state; changes nothing
    #[arg(long, conflicts_with_all = ["paths", "json"])]
    list: bool,
    /// Print the runtime dir and lock path this environment resolves to; creates neither
    #[arg(long, conflicts_with = "json")]
    paths: bool,
    /// Print the report as one JSON object
    #[arg(long)]
    json: bool,
    #[arg(
        long,
        group = "target",
        action = ArgAction::Set,
        value_delimiter = ',',
        value_parser = browser_key,
        value_name = "KEYS",
        help = format!("Register exactly these browsers; keys: {}", known_keys()),
    )]
    browser: Vec<Browser>,
    /// Register every known browser, present or not
    #[arg(long, group = "target")]
    all: bool,
    /// Register into this NativeMessagingHosts dir (absolute; repeatable)
    #[arg(long, group = "target", value_parser = absolute_dir, value_name = "DIR")]
    manifest_dir: Vec<PathBuf>,
    /// Register machine-wide, where every account's browser looks (root only; the .deb's post-install)
    #[arg(long, requires = "fix", conflicts_with_all = ["list", "paths", "json", "manifest_dir"])]
    system: bool,
}

impl From<DoctorFlags> for DoctorCommand {
    fn from(flags: DoctorFlags) -> Self {
        if flags.list {
            return DoctorCommand::List;
        }
        if flags.paths {
            return DoctorCommand::Paths;
        }
        if !flags.fix {
            return DoctorCommand::Report { json: flags.json };
        }
        let targets = if flags.all {
            FixTargets::All
        } else if !flags.browser.is_empty() {
            FixTargets::Browsers(flags.browser.into_iter().unique().collect())
        } else if !flags.manifest_dir.is_empty() {
            FixTargets::ManifestDirs(flags.manifest_dir)
        } else {
            FixTargets::Detected
        };
        DoctorCommand::Fix {
            targets,
            scope: scope_flag(flags.system),
        }
    }
}

/// The one place `--system` becomes a [`Scope`].
fn scope_flag(system: bool) -> Scope {
    if system {
        Scope::System
    } else {
        Scope::User
    }
}

/// `revoke` as exactly one of its two forms; a bare `revoke` is refused with the usage.
#[derive(Debug, PartialEq, Eq)]
pub enum RevokeTarget {
    /// `revoke <browser>`: forget every authenticator enrolled under that label, the host manifest's `--label`
    /// (`default` for every browser sharing an unlabelled manifest). Not presence-gated.
    Browser(BrowserLabel),
    /// `revoke --all`: the host key, the signed policy baseline, every enrollment, every client pairing.
    All,
}

/// The flag surface clap parses `revoke` from; the required, single-member group is what makes a bare
/// `revoke` a usage error and `<browser> --all` a conflict.
#[derive(Args)]
#[command(group(ArgGroup::new("revoke_target").required(true).multiple(false)))]
struct RevokeFlags {
    /// The browser whose enrolled authenticators to forget (its label, e.g. brave)
    #[arg(group = "revoke_target", value_parser = browser_label, value_name = "BROWSER")]
    browser: Option<BrowserLabel>,
    /// Start over: delete the host key and the signed policy baseline, forget every browser and every trusted client
    #[arg(long, group = "revoke_target")]
    all: bool,
}

impl From<RevokeFlags> for RevokeTarget {
    fn from(flags: RevokeFlags) -> Self {
        match flags.browser {
            Some(browser) => RevokeTarget::Browser(browser),
            None => {
                debug_assert!(flags.all, "clap requires exactly one target");
                RevokeTarget::All
            }
        }
    }
}

/// `pair-client`: the label to trust and exactly one anchor.
#[derive(Debug, PartialEq, Eq)]
pub struct PairClientArgs {
    pub name: ClientName,
    pub anchor: AnchorSpec,
}

/// How `pair-client` was told to identify the client to trust.
#[derive(Debug, PartialEq, Eq)]
pub enum AnchorSpec {
    /// Pin an explicit attested image hash.
    Hash(HashDigest),
    /// Pin an explicit code signer.
    Signer(SignerId),
    /// Measure this invocation's parent process and pin its hash, so a user
    /// can enroll the client they launched `pair-client` from.
    ThisParent,
}

/// The flag surface clap parses `pair-client` from; the required,
/// single-member group is what makes the anchor exactly one.
#[derive(Args)]
#[command(group(ArgGroup::new("anchor").required(true).multiple(false)))]
struct PairClientFlags {
    /// The label to file the client under (1-32 chars of [A-Za-z0-9._-], starting alphanumeric)
    #[arg(long, value_parser = |s: &str| ClientName::try_from(s), value_name = "LABEL")]
    name: ClientName,
    /// Pin this attested image hash (hex; upper case is lowercased)
    #[arg(long, group = "anchor", value_parser = hash_digest, value_name = "HEX")]
    hash: Option<HashDigest>,
    /// Pin this code signer: an Apple Team ID on macOS, an Authenticode publisher subject on Windows
    #[arg(long, group = "anchor", value_parser = |id: &str| SignerId::try_from(id), value_name = "ID")]
    signer: Option<SignerId>,
    /// Measure the process that launched this command and pin its hash
    #[arg(long, group = "anchor")]
    this_parent: bool,
}

impl From<PairClientFlags> for PairClientArgs {
    fn from(flags: PairClientFlags) -> Self {
        let anchor = match (flags.hash, flags.signer) {
            (Some(hash), _) => AnchorSpec::Hash(hash),
            (None, Some(signer)) => AnchorSpec::Signer(signer),
            (None, None) => {
                debug_assert!(flags.this_parent, "clap requires exactly one anchor flag");
                AnchorSpec::ThisParent
            }
        };
        PairClientArgs {
            name: flags.name,
            anchor,
        }
    }
}

/// `uninstall`: the scope to clear, and the `--manifest-dir` targets beyond the
/// known-browser table (re-pass what `doctor --fix` was given).
#[derive(Debug, PartialEq, Eq)]
pub struct UninstallArgs {
    pub manifest_dirs: Vec<PathBuf>,
    pub scope: Scope,
}

/// The flag surface clap parses `uninstall` from; [`UninstallArgs`] is the typed result.
#[derive(Args)]
struct UninstallFlags {
    /// Also clear this NativeMessagingHosts dir (absolute; repeatable)
    #[arg(long = "manifest-dir", value_parser = absolute_dir, value_name = "DIR")]
    manifest_dir: Vec<PathBuf>,
    /// Remove the machine-wide registrations instead of this account's (root only; the .deb's removal)
    #[arg(long, conflicts_with = "manifest_dir")]
    system: bool,
}

impl From<UninstallFlags> for UninstallArgs {
    fn from(flags: UninstallFlags) -> Self {
        UninstallArgs {
            manifest_dirs: flags.manifest_dir,
            scope: scope_flag(flags.system),
        }
    }
}

/// `policy <sub>`: the read surfaces, the two write lanes, and rollback, each
/// carrying exactly the data its lane needs.
#[derive(Debug, PartialEq, Eq, Subcommand)]
pub enum PolicyCommand {
    /// Print the policy: store state, revision, signed?, overlay, effective values
    Show {
        /// The versioned status report as one JSON object
        #[arg(long)]
        json: bool,
    },
    /// Print the superseded-revision ring
    History {
        /// The versioned history report as one JSON object
        #[arg(long)]
        json: bool,
    },
    /// GRANT lane: mint a fresh SIGNED baseline (interactive confirmation); refuses where no host key exists
    #[command(override_usage = "chromium-bridge policy set <field flags> [--json]")]
    Set {
        #[command(flatten)]
        overlay: PolicyOverlay,
        /// The post-write status report on stdout, or the versioned error object on refusal
        #[arg(long)]
        json: bool,
    },
    /// FREE lane: apply an unsigned restriction overlay (no confirmation; only ever removes capability)
    #[command(override_usage = "chromium-bridge policy restrict <field flags>")]
    Restrict {
        #[command(flatten)]
        overlay: PolicyOverlay,
    },
    /// Re-apply a past revision's effective policy as a FRESH write, never a replay
    Rollback {
        /// The history revision to re-derive
        #[arg(long, value_name = "N")]
        revision: u64,
        /// The post-write status report on stdout, or the versioned error object on refusal
        #[arg(long)]
        json: bool,
    },
}

/// The per-field edit flags of `policy set` / `policy restrict`: one flag per
/// catalogue field, read back by the same ids, so a field added to the
/// catalogue gets its flag here or fails to compile in [`edit_flag`].
impl Args for PolicyOverlay {
    fn augment_args(cmd: clap::Command) -> clap::Command {
        PolicyField::ALL.iter().fold(
            cmd.group(ArgGroup::new("edits").multiple(true).required(true)),
            |cmd, field| cmd.arg(edit_arg(*field)),
        )
    }

    fn augment_args_for_update(cmd: clap::Command) -> clap::Command {
        Self::augment_args(cmd)
    }
}

impl FromArgMatches for PolicyOverlay {
    fn from_arg_matches(matches: &ArgMatches) -> Result<Self, clap::Error> {
        let mut overlay = PolicyOverlay::default();
        for field in PolicyField::ALL {
            let id = field.wire_name();
            match field.kind() {
                FieldKind::Bool(f) => *overlay.bool_mut(f) = matches.get_one::<bool>(id).copied(),
                FieldKind::Ms(f) => *overlay.ms_mut(f) = matches.get_one::<Ms>(id).copied(),
                FieldKind::ToolSet(f) => {
                    *overlay.tools_mut(f) = matches.get_one::<Vec<String>>(id).cloned();
                }
            }
        }
        Ok(overlay)
    }

    fn update_from_arg_matches(&mut self, matches: &ArgMatches) -> Result<(), clap::Error> {
        *self = Self::from_arg_matches(matches)?;
        Ok(())
    }
}

fn edit_arg(field: PolicyField) -> Arg {
    let arg = Arg::new(field.wire_name())
        .long(edit_flag(field))
        .group("edits")
        .action(ArgAction::Set)
        .help(field.wire_name());
    match field.kind() {
        FieldKind::Bool(_) => arg.value_name("on|off").value_parser(on_off),
        FieldKind::Ms(_) => arg.value_name("MS").value_parser(ms),
        FieldKind::ToolSet(_) => arg.value_name("A,B,...").value_parser(parse_tool_list),
    }
}

/// The flag spelling of each field: kebab-case of the wire name, with the
/// `Enabled` suffix dropped. Exhaustive on purpose.
const fn edit_flag(field: PolicyField) -> &'static str {
    match field {
        PolicyField::CdpMode => "cdp-mode",
        PolicyField::FileUploadEnabled => "file-upload",
        PolicyField::HandleDialogEnabled => "handle-dialog",
        PolicyField::PageEvalEnabled => "page-eval",
        PolicyField::ConfirmHighRiskClick => "confirm-high-risk-click",
        PolicyField::ConfirmPageEval => "confirm-page-eval",
        PolicyField::PresenceConfirm => "presence-confirm",
        PolicyField::ConfirmTabClose => "confirm-tab-close",
        PolicyField::WarnPreciseSnapshot => "warn-precise-snapshot",
        PolicyField::EvalMask => "eval-mask",
        PolicyField::HostReverifyMs => "host-reverify-ms",
        PolicyField::ConfirmGraceMs => "confirm-grace-ms",
        PolicyField::ClickToastTimeoutMs => "click-toast-timeout-ms",
        PolicyField::EvalToastTimeoutMs => "eval-toast-timeout-ms",
        PolicyField::DisabledTools => "disabled-tools",
    }
}

macro_rules! typed_args {
    ($typed:ty, $raw:ty) => {
        impl FromArgMatches for $typed {
            fn from_arg_matches(matches: &ArgMatches) -> Result<Self, clap::Error> {
                <$raw>::from_arg_matches(matches).map(Self::from)
            }

            fn update_from_arg_matches(&mut self, matches: &ArgMatches) -> Result<(), clap::Error> {
                *self = Self::from_arg_matches(matches)?;
                Ok(())
            }
        }

        impl Args for $typed {
            fn augment_args(cmd: clap::Command) -> clap::Command {
                <$raw>::augment_args(cmd)
            }

            fn augment_args_for_update(cmd: clap::Command) -> clap::Command {
                <$raw>::augment_args_for_update(cmd)
            }
        }
    };
}

typed_args!(DoctorCommand, DoctorFlags);
typed_args!(RevokeTarget, RevokeFlags);
typed_args!(PairClientArgs, PairClientFlags);
typed_args!(UninstallArgs, UninstallFlags);
typed_args!(LangCommand, LangFlags);

// ---- Value parsers: each newtype is validated once, here ----------------------

fn ui_lang(value: &str) -> Result<UiLang, String> {
    UiLang::parse(value).ok_or_else(|| format!("takes one of {}", UI_LANGUAGES.join(", ")))
}

/// One comma-separated `--browser` entry, trimmed so `chrome, brave` reads
/// as two keys.
fn browser_key(key: &str) -> Result<Browser, String> {
    Browser::from_key(key.trim())
        .ok_or_else(|| format!("unknown browser key; known: {}", known_keys()))
}

/// Absolute only, so a registration can never land relative to whatever the
/// current directory happens to be.
fn absolute_dir(value: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err("must be an absolute path".to_string())
    }
}

fn browser_label(value: &str) -> Result<BrowserLabel, String> {
    BrowserLabel::parse(value)
        .ok_or_else(|| "want 1-32 chars of [A-Za-z0-9._-], starting alphanumeric".to_string())
}

/// User input keeps the upper-case convenience; the persisted form is the
/// canonical lowercase the digest type enforces.
fn hash_digest(value: &str) -> Result<HashDigest, String> {
    HashDigest::try_from(value.to_ascii_lowercase())
}

/// Exactly `on` or `off`, never a guess at `y` or `1`.
fn on_off(value: &str) -> Result<bool, String> {
    match value {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err("takes on|off".to_string()),
    }
}

fn ms(value: &str) -> Result<Ms, String> {
    let ms = value
        .parse::<u64>()
        .map_err(|_| "takes a non-negative integer (milliseconds)".to_string())?;
    Ms::try_from(ms).map_err(|e| e.to_string())
}

/// The `--disabled-tools` value: a comma-separated list. Empty entries are
/// dropped, so `--disabled-tools ""` is the empty set (a full clear on the
/// `set` lane). The seam bounds the entry count and size.
fn parse_tool_list(value: &str) -> Result<Vec<String>, std::convert::Infallible> {
    Ok(value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect())
}

// ---- The two parsers and the mode pre-check ------------------------------------

/// The user-facing command line. Native-host mode is recognized before this
/// parser runs ([`parse`]), so it is documented here and parsed elsewhere.
#[derive(Parser)]
#[command(
    name = "chromium-bridge",
    version,
    about = "Bridge an MCP client to your real Chromium browser via an extension + native messaging host",
    long_about = None,
    disable_help_subcommand = true,
    after_help = "Modes you never invoke by hand:\n  \
        chromium-bridge                                    the MCP server; your MCP client launches it with no arguments\n  \
        chromium-bridge --native-host [--label <browser>]  the native messaging host; Chrome launches it via the host manifest",
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

/// The argv of native-host mode. Help and version are disabled: see
/// [`is_native_host_mode`].
#[derive(Parser)]
#[command(
    name = "chromium-bridge",
    disable_help_flag = true,
    disable_version_flag = true
)]
struct NativeHostArgs {
    /// Present on Unix (the registered wrapper passes it), absent on Windows
    /// (the registration points straight at the executable).
    #[arg(long = "native-host")]
    _native_host: bool,
    /// The browser this host fronts; it rides the handshake so one MCP server
    /// can tell several browsers apart. Absent, the server files the
    /// connection under its default slot.
    #[arg(long, value_parser = browser_label, value_name = "BROWSER")]
    label: Option<BrowserLabel>,
    /// What Chrome appends after the registered command line: the calling
    /// extension's origin and, on Windows, `--parent-window=<hwnd>`.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
    _chrome_appended: Vec<String>,
}

/// Chrome launches a Windows native-messaging host directly and appends the
/// calling extension origin (plus a parent-window handle) to its command
/// line. Native-host manifests have no `args` field, so on Windows the
/// registration points straight at chromium-bridge.exe and this origin
/// selects host mode. Unix registrations keep using the explicit
/// `--native-host` wrapper argument. Decided before either parser runs:
/// stdout is the protocol stream in host mode, so nothing may touch it before
/// host mode is known, and clap prints help and version to stdout (the host
/// parser disables both).
pub fn is_native_host_mode(args: &[String]) -> bool {
    if args.get(1).map(String::as_str) == Some("--native-host") {
        return true;
    }
    cfg!(windows)
        && args
            .get(1)
            .is_some_and(|arg| arg.starts_with("chrome-extension://"))
}

/// Parse argv (the program name included) once. `Err` is clap's own report,
/// which the binary prints with [`clap::Error::exit`].
pub fn parse(args: &[String]) -> Result<Command, clap::Error> {
    if is_native_host_mode(args) {
        let host = NativeHostArgs::try_parse_from(args)?;
        return Ok(Command::NativeHost { label: host.label });
    }
    let cli = Cli::try_parse_from(args)?;
    Ok(cli.command.unwrap_or(Command::McpServer))
}

#[cfg(test)]
mod tests {
    use clap::error::ErrorKind;
    use clap::CommandFactory;

    use super::*;
    use crate::policy::{Ms, PolicyOverlay};

    fn args(list: &[&str]) -> Vec<String> {
        std::iter::once("chromium-bridge")
            .chain(list.iter().copied())
            .map(String::from)
            .collect()
    }

    // --manifest-dir demands an absolute path, and "/a" is not absolute on
    // Windows; build one per platform.
    fn abs(tail: &str) -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(format!("C:\\{tail}"))
        } else {
            PathBuf::from(format!("/{tail}"))
        }
    }

    /// clap checks its own definition rules (unique ids and flags, groups
    /// naming real args) at runtime, not at compile time; this is its
    /// documented self-check.
    #[test]
    fn clap_definitions_are_consistent() {
        Cli::command().debug_assert();
        NativeHostArgs::command().debug_assert();
    }

    /// The argv surface the registered wrapper, docs/cli.md, and the protocol
    /// suites invoke, one example per subcommand, parses to its typed form
    /// with every newtype already validated.
    #[test]
    fn each_subcommand_parses_from_one_argv_example() {
        let hash = "DEADBEEF".repeat(5);
        let dir_a = abs("a").to_string_lossy().into_owned();
        let dir_b = abs("b").to_string_lossy().into_owned();
        let cases: Vec<(Vec<&str>, Command)> = vec![
            (vec![], Command::McpServer),
            (vec!["--native-host"], Command::NativeHost { label: None }),
            (
                vec!["--native-host", "--label", "brave"],
                Command::NativeHost {
                    label: BrowserLabel::parse("brave"),
                },
            ),
            (
                vec!["doctor"],
                Command::Doctor(DoctorCommand::Report { json: false }),
            ),
            (
                vec!["status", "--json"],
                Command::Doctor(DoctorCommand::Report { json: true }),
            ),
            (
                vec!["doctor", "--list"],
                Command::Doctor(DoctorCommand::List),
            ),
            (
                vec!["doctor", "--paths"],
                Command::Doctor(DoctorCommand::Paths),
            ),
            (
                vec!["doctor", "--fix"],
                Command::Doctor(DoctorCommand::Fix {
                    targets: FixTargets::Detected,
                    scope: Scope::User,
                }),
            ),
            (
                vec!["doctor", "--fix", "--system"],
                Command::Doctor(DoctorCommand::Fix {
                    targets: FixTargets::Detected,
                    scope: Scope::System,
                }),
            ),
            (
                vec!["doctor", "--fix", "--all"],
                Command::Doctor(DoctorCommand::Fix {
                    targets: FixTargets::All,
                    scope: Scope::User,
                }),
            ),
            (
                vec![
                    "doctor",
                    "--fix",
                    "--browser",
                    "chrome, brave,chrome",
                    "--system",
                ],
                Command::Doctor(DoctorCommand::Fix {
                    targets: FixTargets::Browsers(vec![Browser::Chrome, Browser::Brave]),
                    scope: Scope::System,
                }),
            ),
            (
                vec![
                    "doctor",
                    "--fix",
                    "--manifest-dir",
                    &dir_a,
                    "--manifest-dir",
                    &dir_b,
                ],
                Command::Doctor(DoctorCommand::Fix {
                    targets: FixTargets::ManifestDirs(vec![abs("a"), abs("b")]),
                    scope: Scope::User,
                }),
            ),
            (
                vec!["pair"],
                Command::Pair {
                    reset: false,
                    file_store: false,
                },
            ),
            (
                vec!["pair", "--reset", "--file-store"],
                Command::Pair {
                    reset: true,
                    file_store: true,
                },
            ),
            (
                vec!["revoke", "brave"],
                Command::Revoke(RevokeTarget::Browser(BrowserLabel::parse("brave").unwrap())),
            ),
            (
                vec!["revoke", "default"],
                Command::Revoke(RevokeTarget::Browser(BrowserLabel::default_label())),
            ),
            (vec!["revoke", "--all"], Command::Revoke(RevokeTarget::All)),
            (
                vec!["enclave-status", "--json"],
                Command::EnclaveStatus { json: true },
            ),
            (
                vec!["pair-client", "--name", "codex", "--hash", &hash],
                Command::PairClient(PairClientArgs {
                    name: ClientName::try_from("codex").unwrap(),
                    anchor: AnchorSpec::Hash(
                        HashDigest::try_from(hash.to_ascii_lowercase()).unwrap(),
                    ),
                }),
            ),
            (
                vec!["pair-client", "--name", "x", "--signer", "ABC123"],
                Command::PairClient(PairClientArgs {
                    name: ClientName::try_from("x").unwrap(),
                    anchor: AnchorSpec::Signer(SignerId::try_from("ABC123").unwrap()),
                }),
            ),
            (
                vec!["pair-client", "--name", "pytest", "--this-parent"],
                Command::PairClient(PairClientArgs {
                    name: ClientName::try_from("pytest").unwrap(),
                    anchor: AnchorSpec::ThisParent,
                }),
            ),
            (
                vec!["revoke-client", "--name", "pytest"],
                Command::RevokeClient {
                    name: "pytest".into(),
                },
            ),
            (vec!["list-clients"], Command::ListClients),
            (
                vec!["uninstall", "--manifest-dir", &dir_a],
                Command::Uninstall(UninstallArgs {
                    manifest_dirs: vec![abs("a")],
                    scope: Scope::User,
                }),
            ),
            (
                vec!["uninstall", "--system"],
                Command::Uninstall(UninstallArgs {
                    manifest_dirs: vec![],
                    scope: Scope::System,
                }),
            ),
            (vec!["kill"], Command::Kill),
            (vec!["unkill"], Command::Unkill),
            (
                vec!["policy", "history"],
                Command::Policy(PolicyCommand::History { json: false }),
            ),
            (
                vec![
                    "policy",
                    "set",
                    "--page-eval",
                    "on",
                    "--host-reverify-ms",
                    "60000",
                    "--disabled-tools",
                    "page_upload, tab_close",
                    "--json",
                ],
                Command::Policy(PolicyCommand::Set {
                    overlay: PolicyOverlay {
                        page_eval_enabled: Some(true),
                        host_reverify_ms: Some(Ms::from(60_000u32)),
                        disabled_tools: Some(vec!["page_upload".into(), "tab_close".into()]),
                        ..PolicyOverlay::default()
                    },
                    json: true,
                }),
            ),
            (
                vec!["policy", "restrict", "--confirm-page-eval", "on"],
                Command::Policy(PolicyCommand::Restrict {
                    overlay: PolicyOverlay {
                        confirm_page_eval: Some(true),
                        ..PolicyOverlay::default()
                    },
                }),
            ),
            (
                vec!["policy", "rollback", "--json", "--revision", "7"],
                Command::Policy(PolicyCommand::Rollback {
                    revision: 7,
                    json: true,
                }),
            ),
            (vec!["lang"], Command::Lang(LangCommand::Show)),
            (vec!["lang", "show"], Command::Lang(LangCommand::Show)),
            (
                vec!["lang", "set", "zh_CN"],
                Command::Lang(LangCommand::Set {
                    value: UiLang::parse("zh_CN").unwrap(),
                }),
            ),
        ];
        for (argv, expected) in &cases {
            let parsed = parse(&args(argv)).unwrap_or_else(|e| panic!("{argv:?}: {e}"));
            assert_eq!(&parsed, expected, "{argv:?}");
        }
    }

    /// An explicit `--manifest-dir` is a per-user directory by construction, so pairing it with
    /// `--system` would admit a root run that writes into a home; both commands refuse the pair at the
    /// argv boundary (an absolute path is needed to reach the conflict check, hence not in the table).
    #[test]
    fn system_and_manifest_dir_conflict_in_both_commands() {
        let dir = abs("a").to_string_lossy().into_owned();
        for argv in [
            vec![
                "doctor",
                "--fix",
                "--system",
                "--manifest-dir",
                dir.as_str(),
            ],
            vec!["uninstall", "--system", "--manifest-dir", dir.as_str()],
        ] {
            let err = parse(&args(&argv)).expect_err(&format!("{argv:?} parsed"));
            assert_eq!(err.kind(), ErrorKind::ArgumentConflict, "{argv:?}: {err}");
        }
    }

    /// Refusals the protocol suites never exercise, each pinned to clap's
    /// reason: a loosened exclusivity rule, a dropped value parser, or a flag
    /// that started accepting a stray argument fails here.
    #[test]
    fn refusals_name_their_reason() {
        use ErrorKind::{
            ArgumentConflict, DisplayHelpOnMissingArgumentOrSubcommand, InvalidSubcommand,
            InvalidValue, MissingRequiredArgument, UnknownArgument, ValueValidation,
        };
        let cases: &[(&[&str], ErrorKind)] = &[
            (&["pare"], InvalidSubcommand),
            (&["install"], InvalidSubcommand),
            (&["pair", "--rest"], UnknownArgument),
            // revoke: exactly one target, typed.
            (&["revoke"], MissingRequiredArgument),
            (&["revoke", "brave", "--all"], ArgumentConflict),
            (&["revoke", "bad label"], ValueValidation),
            (&["revoke", "brave", "chrome"], UnknownArgument),
            (&["revoke", "--force"], UnknownArgument),
            (&["enclave-status", "--json", "x"], UnknownArgument),
            (&["kill", "--force"], UnknownArgument),
            (&["unkill", "now"], UnknownArgument),
            (&["list-clients", "--json"], UnknownArgument),
            (&["uninstall", "--browser", "chrome"], UnknownArgument),
            // doctor: targets only with --fix, one target mode, --list and
            // --json alone, typed values.
            (&["doctor", "--browser", "chrome"], MissingRequiredArgument),
            (&["doctor", "--all"], MissingRequiredArgument),
            (&["doctor", "--system"], MissingRequiredArgument),
            (&["doctor", "--list", "--system"], ArgumentConflict),
            (
                &["doctor", "--fix", "--all", "--browser", "chrome"],
                ArgumentConflict,
            ),
            (&["doctor", "--list", "--fix"], ArgumentConflict),
            (&["doctor", "--json", "--list"], ArgumentConflict),
            (&["doctor", "--json", "--fix"], ArgumentConflict),
            (&["doctor", "--paths", "--fix"], ArgumentConflict),
            (&["doctor", "--paths", "--list"], ArgumentConflict),
            (&["doctor", "--paths", "--json"], ArgumentConflict),
            (&["doctor", "--fix", "--browser"], InvalidValue),
            (&["doctor", "--fix", "--browser", ""], ValueValidation),
            (
                &["doctor", "--fix", "--browser", "chrome,"],
                ValueValidation,
            ),
            (
                &[
                    "doctor",
                    "--fix",
                    "--browser",
                    "chrome",
                    "--browser",
                    "brave",
                ],
                ArgumentConflict,
            ),
            (
                &["doctor", "--fix", "--browser", "netscape"],
                ValueValidation,
            ),
            (
                &["doctor", "--fix", "--manifest-dir", "relative/dir"],
                ValueValidation,
            ),
            (&["doctor", "--fix", "--manifest-dir", ""], ValueValidation),
            (&["doctor", "extra"], UnknownArgument),
            // pair-client: a name and exactly one anchor, each typed.
            (&["pair-client", "--name", "x"], MissingRequiredArgument),
            (&["pair-client", "--this-parent"], MissingRequiredArgument),
            (
                &[
                    "pair-client",
                    "--name",
                    "x",
                    "--hash",
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "--this-parent",
                ],
                ArgumentConflict,
            ),
            (
                &["pair-client", "--name", "x", "--hash", "deadbeef"],
                ValueValidation,
            ),
            (
                &["pair-client", "--name", "x", "--signer", ""],
                ValueValidation,
            ),
            (
                &["pair-client", "--name", "bad name!", "--this-parent"],
                ValueValidation,
            ),
            (&["revoke-client"], MissingRequiredArgument),
            // audit: one numeric limit.
            (&["audit", "--limit"], InvalidValue),
            (&["audit", "--limit", "x"], ValueValidation),
            (&["audit", "--limit", "1", "--limit", "2"], ArgumentConflict),
            (&["audit", "extra"], UnknownArgument),
            // policy: a subcommand, at least one field flag per edit, typed
            // values, --json only where a report exists.
            // A bare `policy` gets its subcommand list on stderr, exit 2.
            (&["policy"], DisplayHelpOnMissingArgumentOrSubcommand),
            (&["policy", "grant"], InvalidSubcommand),
            (&["policy", "set"], MissingRequiredArgument),
            (&["policy", "set", "--json"], MissingRequiredArgument),
            (&["policy", "restrict"], MissingRequiredArgument),
            (
                &["policy", "restrict", "--confirm-page-eval", "on", "--json"],
                UnknownArgument,
            ),
            (
                &["policy", "set", "--page-eval", "on", "--page-eval", "off"],
                ArgumentConflict,
            ),
            (
                &["policy", "set", "--page-eval", "on", "--json", "--json"],
                ArgumentConflict,
            ),
            (&["policy", "set", "--bogus", "on"], UnknownArgument),
            (&["policy", "set", "--page-eval", "maybe"], ValueValidation),
            (
                &["policy", "set", "--host-reverify-ms", "soon"],
                ValueValidation,
            ),
            (
                &["policy", "set", "--host-reverify-ms", "9007199254740992"],
                ValueValidation,
            ),
            (
                &["policy", "set", "--page-eval", "--host-reverify-ms"],
                InvalidValue,
            ),
            (&["policy", "show", "extra"], UnknownArgument),
            (&["policy", "rollback"], MissingRequiredArgument),
            (&["policy", "rollback", "--revision", "x"], ValueValidation),
            // lang: `set` takes exactly one accepted value, `show` takes nothing.
            (&["lang", "set"], MissingRequiredArgument),
            (&["lang", "set", "fr"], ValueValidation),
            (&["lang", "set", "EN"], ValueValidation),
            (&["lang", "set", "en", "zh_CN"], UnknownArgument),
            (&["lang", "show", "en"], UnknownArgument),
            (&["lang", "get"], InvalidSubcommand),
            // native host: a validated label, once, with a value.
            (&["--native-host", "--label"], InvalidValue),
            (&["--native-host", "--label", "bad label"], ValueValidation),
            (
                &["--native-host", "--label", "a", "--label", "b"],
                ArgumentConflict,
            ),
            // Not host mode: argv[1] is not the host flag, so the user-facing
            // parser sees an unknown flag.
            (&["--label", "--native-host"], UnknownArgument),
        ];
        for (argv, kind) in cases {
            let err = parse(&args(argv))
                .err()
                .unwrap_or_else(|| panic!("{argv:?} parsed"));
            assert_eq!(err.kind(), *kind, "{argv:?}: {err}");
        }
    }

    /// Chrome on Windows launches the host without `--native-host`: the
    /// appended origin selects host mode and the parent-window handle is
    /// accepted and ignored.
    #[cfg(windows)]
    #[test]
    fn chrome_windows_origin_selects_host_mode() {
        let argv = args(&[
            "chrome-extension://mkjjlmjbcljpcfkfadfmhblmmddkdihf/",
            "--parent-window=123",
        ]);
        assert!(is_native_host_mode(&argv));
        assert_eq!(parse(&argv).unwrap(), Command::NativeHost { label: None });
    }
}

/// Property-based proof of the `--disabled-tools` transport fidelity: the
/// protocol.rs `mod proptests` pattern.
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// Bounded arbitrary tool names over arbitrary Unicode scalar values
    /// (commas and whitespace included, so the validator's refusals are the
    /// only thing standing between a hostile name and the transport).
    fn arb_name() -> impl Strategy<Value = String> {
        prop::collection::vec(any::<char>(), 1..12).prop_map(|cs| cs.into_iter().collect())
    }

    proptest! {
        /// Every disabledTools list the shared validator accepts survives
        /// the CLI's comma-joined argv transport byte-for-byte: join,
        /// re-split, trim - identity. This is the guarantee the validator's
        /// comma and whitespace refusals exist to make PROVABLE: a list that
        /// would not round-trip is refused up front at every write seam,
        /// never mangled (fail closed).
        #[test]
        fn accepted_tool_lists_round_trip_the_comma_transport(
            tools in prop::collection::vec(arb_name(), 0..8)
        ) {
            prop_assume!(crate::policy::validate_disabled_tools(&tools).is_ok());
            prop_assert_eq!(parse_tool_list(&tools.join(",")), Ok(tools));
        }
    }
}
