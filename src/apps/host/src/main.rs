//! chromium-bridge - thin binary entry point.
//!
//! All logic lives in the `chromium_bridge_core` library crate
//! (`src/packages/core`); this binary parses argv once into a typed command
//! and dispatches it. `chromium-bridge --help` lists the modes.

use chromium_bridge_core::cli::{parse, Command};
use chromium_bridge_core::{
    allowlist, audit, doctor, enclave, kill, mcp_server, native_host, policy, registration,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let command = match parse(&args) {
        Ok(command) => command,
        Err(report) => report.exit(),
    };
    let code = match command {
        Command::NativeHost { label } => native_host::run(label),
        Command::Doctor(doctor) => doctor::run(doctor),
        Command::Pair { reset } => enclave::run_pair(reset),
        Command::Revoke => enclave::run_revoke(),
        Command::EnclaveStatus { json: false } => enclave::run_status(),
        Command::EnclaveStatus { json: true } => enclave::run_status_json(),
        Command::PresenceSelftest => enclave::run_presence_selftest(),
        Command::PairClient(client) => allowlist::run_pair_client(client),
        Command::RevokeClient { name } => allowlist::run_revoke_client(&name),
        Command::ListClients => allowlist::run_list_clients(),
        Command::Uninstall(uninstall) => registration::run_uninstall(&uninstall),
        Command::Kill => kill::run_kill(),
        Command::Unkill => kill::run_unkill(),
        Command::Audit { limit } => audit::run_audit(limit),
        Command::Policy(policy) => policy::run_policy(policy),
        Command::McpServer => mcp_server::run(),
    };
    std::process::exit(code);
}
