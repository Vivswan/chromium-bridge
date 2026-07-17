//! browser-bridge — thin binary entry point.
//!
//! All logic lives in the `browser_bridge` library crate (`src/lib.rs`); this
//! binary only selects a mode from argv and forwards to the library:
//! - (no args): MCP server (default). Run under your MCP client's server config.
//! - --native-host: Chrome-spawned bridge subprocess. Chrome launches this
//!   via the native messaging host manifest; it should never be invoked by hand.
//! - doctor/status, pair [--reset], revoke, enclave-status: user-run
//!   subcommands (health report and the enrollment ceremony, ADR-0021).

use browser_bridge::cli::{parse, print_help, Command};
use browser_bridge::{doctor, enclave, mcp_server, native_host};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = match parse(&args) {
        Command::NativeHost => native_host::run(),
        Command::Help => {
            print_help();
            0
        }
        Command::Doctor => doctor::run(),
        Command::Pair { reset } => enclave::run_pair(reset),
        Command::Revoke => enclave::run_revoke(),
        Command::EnclaveStatus => enclave::run_status(),
        Command::McpServer => mcp_server::run(),
        Command::Unknown => {
            print_help();
            2
        }
    };
    std::process::exit(code);
}
