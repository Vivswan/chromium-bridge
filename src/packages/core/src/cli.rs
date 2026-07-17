//! Command-line entry helpers: argv-based mode selection and the `--help`
//! text. Kept in the library so they are unit-testable and reusable.

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
    /// `enclave-status`: read-only enrollment state report.
    EnclaveStatus,
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
/// line. Native-host manifests have no `args` field, so the Windows installer
/// points straight at chromium-bridge.exe and this origin selects host mode.
/// Unix installs keep using the explicit `--native-host` wrapper argument.
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
    let rest = &args[1.min(args.len())..];
    match rest.first().map(String::as_str) {
        None => Command::McpServer,
        Some("-h" | "--help") => Command::Help,
        // doctor takes flags (--fix/--list/...), parsed by doctor_args in
        // the handler.
        Some("doctor" | "status") => Command::Doctor,
        Some("pair") if rest.len() == 1 => Command::Pair { reset: false },
        Some("pair") if rest.len() == 2 && rest[1] == "--reset" => Command::Pair { reset: true },
        Some("revoke") if rest.len() == 1 => Command::Revoke,
        Some("enclave-status") if rest.len() == 1 => Command::EnclaveStatus,
        // The client-allowlist subcommands take their own flags, parsed by the
        // handler (pair_client_args) so a bad combination reports a clear error
        // rather than a bare help dump.
        Some("pair-client") => Command::PairClient,
        Some("revoke-client") => Command::RevokeClient,
        Some("list-clients") if rest.len() == 1 => Command::ListClients,
        Some("uninstall") => Command::Uninstall,
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

/// The parsed arguments of `doctor` / `status`. Plain `doctor` (all fields
/// off) is the read-only report. `--list` is a short resolver-only listing.
/// `--fix` repairs/registers, with an exclusive targeting choice: explicit
/// `--manifest-dir` dirs, `--all`, `--browser <keys>`, or (none of them)
/// every detected browser.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DoctorArgs {
    /// `--fix`: (re-)register the targeted browsers. Idempotent, so this is
    /// also the fresh-machine registration path.
    pub fix: bool,
    /// `--list`: print detection/registration state, change nothing.
    pub list: bool,
    /// `--browser chrome,brave`: exactly these known browsers (needs --fix).
    pub browsers: Option<Vec<String>>,
    /// `--all`: every known browser, present or not (needs --fix).
    pub all: bool,
    /// `--manifest-dir PATH` (repeatable, needs --fix): exact
    /// NativeMessagingHosts dirs, for Chromium browsers we do not know by
    /// name. Absolute paths only.
    pub manifest_dirs: Vec<String>,
}

/// Parse the flags of `doctor` / `status`. Same strictness as
/// [`pair_client_args`]: conflicting or malformed selections are an error,
/// never a guess.
pub fn doctor_args(args: &[String]) -> Result<DoctorArgs, String> {
    let mut parsed = DoctorArgs::default();
    let mut it = args.iter().skip(2);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--fix" => parsed.fix = true,
            "--list" => parsed.list = true,
            "--browser" => {
                if parsed.browsers.is_some() {
                    return Err("--browser given more than once".into());
                }
                let value = take_value(&mut it, "--browser")?;
                let mut keys: Vec<String> = Vec::new();
                for key in value.split(',').map(str::trim).filter(|k| !k.is_empty()) {
                    if keys.iter().any(|k| k == key) {
                        return Err(format!("--browser lists {key:?} twice"));
                    }
                    keys.push(key.to_string());
                }
                if keys.is_empty() {
                    return Err(format!("--browser selected no browser: {value:?}"));
                }
                parsed.browsers = Some(keys);
            }
            "--all" => parsed.all = true,
            "--manifest-dir" => {
                parsed.manifest_dirs.push(manifest_dir_value(&mut it)?);
            }
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }

    let selections = usize::from(parsed.all)
        + usize::from(parsed.browsers.is_some())
        + usize::from(!parsed.manifest_dirs.is_empty());
    if selections > 1 {
        return Err("--all, --browser, and --manifest-dir are mutually exclusive".into());
    }
    if selections > 0 && !parsed.fix {
        return Err("--browser/--all/--manifest-dir only target a repair; add --fix".into());
    }
    if parsed.list && (parsed.fix || selections > 0) {
        return Err("--list is a read-only report and takes no other flags".into());
    }
    Ok(parsed)
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
/// flag-shaped value, a repeated `--label`, or a label that fails
/// [`crate::ipc::validate_label`] is an error — the caller must refuse to
/// start rather than run under a mangled identity.
pub fn native_host_label(args: &[String]) -> Result<Option<String>, String> {
    let mut found: Option<String> = None;
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
            if !crate::ipc::validate_label(value) {
                return Err(format!(
                    "invalid --label {value:?}: want 1-32 chars of [A-Za-z0-9._-], starting alphanumeric"
                ));
            }
            found = Some(value.clone());
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
         chromium-bridge doctor --fix [--browser <keys> | --all | --manifest-dir <dir>]\n                                Repair (or first-register) the native-messaging\n                                manifests for your Chromium browsers. Default:\n                                every browser detected for this user; keys:\n                                chrome,chromium,brave,edge,vivaldi,opera\n    \
         chromium-bridge pair           Enroll: mint the Secure Enclave key (macOS)\n    \
         chromium-bridge pair --reset   Replace the enrollment key with a fresh one\n    \
         chromium-bridge revoke         Delete the enrollment key (fails closed)\n    \
         chromium-bridge enclave-status Print the enrollment state\n    \
         chromium-bridge pair-client --name <label> (--this-parent | --hash <hex> | --team-id <id>)\n                                Trust an MCP-client harness (ADR-0024)\n    \
         chromium-bridge revoke-client --name <label>   Untrust a client\n    \
         chromium-bridge list-clients   Print the trusted-client allowlist\n    \
         chromium-bridge uninstall [--manifest-dir <dir>]\n                                Remove exactly the registrations this project wrote\n                                (re-pass any --manifest-dir you registered)\n    \
         chromium-bridge --native-host [--label <browser>]\n                                Run as the Chrome native messaging host;\n                                --label names this browser (e.g. chrome, brave)\n                                so one MCP server can address several browsers\n\n\
         Configure your MCP client (Claude Code, Codex, …) to launch this \
         binary with no arguments as an MCP server; Chrome launches it with \
         --native-host via the host manifest. You normally never invoke either \
         mode by hand.",
        version = env!("CARGO_PKG_VERSION")
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
        // A well-formed label is returned.
        assert_eq!(
            native_host_label(&argv(&["--native-host", "--label", "brave"])),
            Ok(Some("brave".into()))
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
        assert_eq!(parse(&args(&["enclave-status"])), Command::EnclaveStatus);
    }

    #[test]
    fn parse_rejects_typos_and_stray_arguments() {
        assert_eq!(parse(&args(&["pare"])), Command::Unknown);
        assert_eq!(parse(&args(&["pair", "--rest"])), Command::Unknown);
        assert_eq!(parse(&args(&["pair", "--reset", "x"])), Command::Unknown);
        assert_eq!(parse(&args(&["revoke", "--force"])), Command::Unknown);
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
        use super::doctor_args;
        let ok = |list: &[&str]| doctor_args(&args(list)).unwrap();
        assert_eq!(ok(&["doctor"]), super::DoctorArgs::default());
        assert!(ok(&["doctor", "--fix"]).fix);
        assert!(ok(&["doctor", "--list"]).list);
        assert!(ok(&["doctor", "--fix", "--all"]).all);
        assert_eq!(
            ok(&["doctor", "--fix", "--browser", "chrome, brave"]).browsers,
            Some(vec!["chrome".to_string(), "brave".to_string()])
        );
        assert_eq!(
            ok(&[
                "doctor",
                "--fix",
                "--manifest-dir",
                "/a",
                "--manifest-dir",
                "/b"
            ])
            .manifest_dirs,
            vec!["/a".to_string(), "/b".to_string()]
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
        assert!(err(&["doctor", "--fix", "--manifest-dir", "relative/dir"]).contains("absolute"));
        assert!(err(&["doctor", "--fix", "--manifest-dir", ""]).contains("absolute"));
        assert!(err(&["doctor", "--bogus"]).contains("unexpected argument"));
    }

    #[test]
    fn uninstall_args_take_only_manifest_dirs() {
        use super::uninstall_args;
        assert_eq!(
            uninstall_args(&args(&["uninstall", "--manifest-dir", "/a"]))
                .unwrap()
                .manifest_dirs,
            vec!["/a".to_string()]
        );
        assert!(uninstall_args(&args(&["uninstall", "--browser", "chrome"])).is_err());
    }
}
