//! genkan-core - bridge an MCP client (Claude Code, Codex, ...) to your
//! real Chromium browser.
//!
//! One binary (`src/apps/host`), two modes selected by argv:
//! - (no args): MCP server (default). Run under your MCP client's server config.
//! - --native-host: Chrome-spawned bridge subprocess. Chrome launches this
//!   via the native messaging host manifest; it should never be invoked by hand.
//!
//! This library exposes every module so the modules are reachable from the
//! host binary, integration tests, and future consumers.

// clippy.toml's allow-*-in-tests switches exempt test code from the panic family; these two lints have no such
// switch, so the test build is exempted here. Production code gets no exception: a panic path is removed
// structurally, never allowed.
#![cfg_attr(
    test,
    expect(
        clippy::arithmetic_side_effects,
        clippy::as_conversions,
        reason = "tests assert with plain arithmetic and casts; clippy.toml has no in-tests switch for these two"
    )
)]

#[macro_use]
pub mod log;
pub mod allowlist;
pub mod audit;
pub mod broker;
pub mod browsers;
pub mod cli;
pub mod doctor;
pub mod enclave;
pub mod error;
pub(crate) mod fsguard;
pub mod identity;
pub mod ipc;
pub mod kill;
pub mod lang;
pub mod mcp;
pub mod mcp_server;
pub(crate) mod migrations;
pub mod native_host;
pub mod policy;
pub mod presence;
pub mod protocol;
pub mod registration;
pub mod runtime_record;
pub mod session;
pub(crate) mod sys;
#[cfg(test)]
pub(crate) mod test_support;
pub mod tools;
pub mod trust;
pub mod webauthn;
