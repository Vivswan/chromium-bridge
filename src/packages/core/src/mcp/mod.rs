//! The MCP protocol layer, built on the official `rmcp` SDK (ADR-0034).
//!
//! MCP 2026-07-28 is stateless: there is no mandatory `initialize`
//! handshake, every request may claim its protocol revision in
//! `params._meta`, results carry `resultType` (the `server/discover`
//! result also carries the server identity in `_meta`), and clients
//! (re)discover the server via `server/discover`.
//! Rather than hand-rolling that dialect, this module delegates the whole
//! protocol surface - lifecycle, per-request version validation, the
//! `-32022` unsupported-version refusal, legacy `initialize` negotiation
//! for pre-2026 harnesses, and the wire model - to `rmcp`, the many-eyes
//! library ADR-0023's policy prefers over bespoke protocol code.
//!
//! What stays ours, unchanged:
//! - the broker serve loop (`broker.rs`) keeps owning the wire and every
//!   security gate: line caps, parse-error replies, harness attestation,
//!   per-relay rate limiting, and the per-request revocation recheck all
//!   run BEFORE a message reaches this layer;
//! - the tool surface: [`handler::BridgeHandler`] serves the catalogue
//!   (`tools::all`) and funnels every `tools/call` through the same
//!   kill-switch gate, audit record, and `route_and_dispatch` path as
//!   before.
//!
//! [`connection::Connection`] is the seam: one rmcp service per harness
//! connection, running on a small shared tokio runtime, fed typed messages
//! by the synchronous serve loop through in-memory channels.

pub mod connection;
pub(crate) mod handler;

pub use connection::Connection;
