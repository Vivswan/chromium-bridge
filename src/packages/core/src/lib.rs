//! chromium-bridge-core — bridge an MCP client (Claude Code, Codex, …) to your
//! real Chromium browser.
//!
//! One binary (`src/apps/host`), two modes selected by argv:
//! - (no args): MCP server (default). Run under your MCP client's server config.
//! - --native-host: Chrome-spawned bridge subprocess. Chrome launches this
//!   via the native messaging host manifest; it should never be invoked by hand.
//!
//! This library exposes every module so the modules are reachable from the
//! host binary, integration tests, and future consumers.

// No-panic security core: this crate is the enforcement boundary (attestation,
// handshake, allowlist, enclave, wire parsers), and a panic here is a
// denial-of-service primitive plus an unaudited failure path. Every fallible
// operation must fail closed through a typed error instead of unwinding.
// Test code is exempt via clippy.toml's allow-*-in-tests switches; production
// exceptions require a structural proof that the panic path cannot exist, not
// an #[allow].
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::unreachable
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
pub mod identity;
pub mod ipc;
pub mod kill;
pub mod mcp_server;
pub mod native_host;
pub mod presence;
pub mod protocol;
pub mod registration;
pub mod revocation;
pub mod session;
pub(crate) mod sys;
pub mod tools;
