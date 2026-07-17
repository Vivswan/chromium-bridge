//! Command-line entry helpers: argv-based mode selection and the `--help`
//! text. Kept in the library so they are unit-testable and reusable.

/// Which mode/subcommand argv selects. Parsed once in `main` and dispatched.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    /// Default (no args): run as the MCP server.
    McpServer,
    /// `--native-host` (or a Chrome-appended extension origin on Windows).
    NativeHost,
    /// `doctor` / `status`: read-only health report.
    Doctor,
    /// `pair [--reset]`: the enrollment ceremony (ADR-0021).
    Pair { reset: bool },
    /// `revoke`: delete the enrollment key, fail the pinned extension closed.
    Revoke,
    /// `enclave-status`: read-only enrollment state report.
    EnclaveStatus,
    /// `-h` / `--help`.
    Help,
    /// Anything unrecognized: print help, exit non-zero.
    Unknown,
}

/// Chrome launches a Windows native-messaging host directly and appends the
/// calling extension origin (plus a parent-window handle) to its command
/// line. Native-host manifests have no `args` field, so the Windows installer
/// points straight at browser-bridge.exe and this origin selects host mode.
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
        Some("doctor" | "status") if rest.len() == 1 => Command::Doctor,
        Some("pair") if rest.len() == 1 => Command::Pair { reset: false },
        Some("pair") if rest.len() == 2 && rest[1] == "--reset" => Command::Pair { reset: true },
        Some("revoke") if rest.len() == 1 => Command::Revoke,
        Some("enclave-status") if rest.len() == 1 => Command::EnclaveStatus,
        Some(_) => Command::Unknown,
    }
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
        "browser-bridge {version}\n\
         Bridge an MCP client to a real Chrome via an extension + native host.\n\n\
         USAGE:\n    \
         browser-bridge                Run as MCP server (for your MCP client)\n    \
         browser-bridge doctor         Print a read-only health report (alias: status)\n    \
         browser-bridge pair           Enroll: mint the Secure Enclave key (macOS)\n    \
         browser-bridge pair --reset   Replace the enrollment key with a fresh one\n    \
         browser-bridge revoke         Delete the enrollment key (fails closed)\n    \
         browser-bridge enclave-status Print the enrollment state\n    \
         browser-bridge --native-host [--label <browser>]\n                                Run as the Chrome native messaging host;\n                                --label names this browser (e.g. chrome, brave)\n                                so one MCP server can address several browsers\n\n\
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
        std::iter::once("browser-bridge")
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
            std::iter::once("browser-bridge")
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
            "browser-bridge.exe".into(),
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
        assert_eq!(parse(&args(&["doctor", "extra"])), Command::Unknown);
    }
}
