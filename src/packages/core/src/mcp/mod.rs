//! The MCP protocol layer, built on the official `rmcp` SDK (ADR-0034) rather than a hand-rolled dialect: the
//! many-eyes library ADR-0023 prefers over bespoke protocol code. MCP 2026-07-28 is stateless (no mandatory
//! `initialize`; each request may claim its revision in `params._meta`; clients discover the server via
//! `server/discover`), and rmcp owns that whole surface, including the `-32022` unsupported-version refusal
//! and legacy `initialize` negotiation for pre-2026 harnesses.
//!
//! What stays ours:
//!
//! ```text
//! broker.rs serve loop      -> line caps, parse-error replies, harness attestation, per-relay rate
//!                              limiting, and the per-request revocation recheck, all BEFORE a message reaches here
//! `handler::BridgeHandler`  -> serves the catalogue (`tools::all`) and funnels every `tools/call` through
//!                              the kill-switch gate, audit record, and `route_and_dispatch`
//! `connection::Connection`  -> the seam: one rmcp service per harness connection on a small shared tokio
//!                              runtime, fed by the synchronous serve loop through in-memory channels
//! ```

pub mod connection;
pub(crate) mod handler;

pub use connection::Connection;
