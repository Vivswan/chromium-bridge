//! chromium-bridge - thin binary entry point.
//!
//! All logic lives in the `chromium_bridge_core` library crate
//! (`src/packages/core`); this binary only selects a mode from argv and forwards to
//! the library:
//! - (no args): MCP server (default). Run under your MCP client's server config.
//! - --native-host: Chrome-spawned bridge subprocess. Chrome launches this
//!   via the native messaging host manifest; it should never be invoked by hand.
//! - doctor/status [--fix|--list], uninstall, pair [--reset], revoke,
//!   enclave-status: user-run subcommands (health report + registration
//!   repair, and the enrollment ceremony, ADR-0021).

use chromium_bridge_core::cli::{native_host_label, parse, print_help, Command};
use chromium_bridge_core::{
    allowlist, audit, doctor, enclave, kill, mcp_server, native_host, policy, registration,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = match parse(&args) {
        // The label is resolved here so the host never reads argv itself. A
        // malformed label refuses to start: better no bridge than one filed
        // under a mangled identity.
        Command::NativeHost => match native_host_label(&args) {
            Ok(label) => native_host::run(label),
            Err(e) => {
                eprintln!("native-host: {e}");
                1
            }
        },
        Command::Help => {
            print_help();
            0
        }
        Command::Doctor => doctor::run(&args),
        Command::Pair { reset } => enclave::run_pair(reset),
        Command::Revoke => enclave::run_revoke(),
        Command::EnclaveStatus { json: false } => enclave::run_status(),
        Command::EnclaveStatus { json: true } => enclave::run_status_json(),
        Command::PresenceSelftest => enclave::run_presence_selftest(),
        Command::PairClient => allowlist::run_pair_client(&args),
        Command::RevokeClient => allowlist::run_revoke_client(&args),
        Command::ListClients => allowlist::run_list_clients(),
        Command::Uninstall => registration::run_uninstall_cli(&args),
        Command::Kill => kill::run_kill(),
        Command::Unkill => kill::run_unkill(),
        Command::Audit => audit::run_audit(&args),
        Command::Policy => policy::run_policy(&args),
        Command::McpServer => mcp_server::run(),
        Command::Unknown => {
            print_help();
            2
        }
    };
    std::process::exit(code);
}
