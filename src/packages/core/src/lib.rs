//! chromium-bridge-core - bridge an MCP client (Claude Code, Codex, ...) to your
//! real Chromium browser.
//!
//! One binary (`src/apps/host`), two modes selected by argv:
//! - (no args): MCP server (default). Run under your MCP client's server config.
//! - --native-host: Chrome-spawned bridge subprocess. Chrome launches this
//!   via the native messaging host manifest; it should never be invoked by hand.
//!
//! This library exposes every module so the modules are reachable from the
//! host binary, integration tests, and future consumers.

// No-panic security core: the panic-family and numeric-strictness lints are
// denied workspace-wide in the root Cargo.toml. clippy.toml's
// allow-*-in-tests switches exempt test code from the panic family;
// arithmetic_side_effects and as_conversions have no such config, so the
// test-harness build is exempted here (the non-test lib target still
// enforces both on production code). Production exceptions require a
// structural proof that the panic path cannot exist, not an #[allow].
#![cfg_attr(test, allow(clippy::arithmetic_side_effects, clippy::as_conversions))]

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
pub mod mcp;
pub mod mcp_server;
pub mod native_host;
pub mod policy;
pub mod presence;
pub mod protocol;
pub mod registration;
pub mod revocation;
pub mod session;
pub(crate) mod sys;
pub mod tools;
