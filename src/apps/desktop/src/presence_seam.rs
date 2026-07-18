//! PHASE 8 INTEGRATION POINT: user-presence attestation for the app's two
//! capability-granting acts (releasing the kill switch, pairing a trusted
//! client).
//!
//! Both call sites route through [`chromium_bridge_core::presence`], hardware
//! rung first. Until the Phase 8 LocalAuthentication provider lands
//! (feat/phase8-touchid), the hardware rung reports Unavailable and the only
//! floor a GUI process can honestly claim - the CLI's typed confirmation -
//! refuses because a GUI's stdin is not a terminal. The result is deliberate:
//! these two buttons FAIL CLOSED from the app until Touch ID is wired, and
//! the error strings below tell the user which trusted surface works today.
//! The extension floor is out of reach on purpose: claiming
//! `Floor::ExtensionConfirm` from here would assert a confirmation that never
//! happened (see the warning on `presence::Floor`).
//!
//! When Phase 8 lands, `require_presence` raises Touch ID from the hardware
//! rung and both functions start succeeding with `PresencePath::TouchId` -
//! no change needed here unless Phase 8 ships a dedicated gated API (e.g. a
//! presence-gated `allowlist` pairing entry point), in which case
//! [`pairing_presence`]'s caller swaps to it.

use chromium_bridge_core::presence::{self, Floor, PresenceAttestation, PresenceError};

/// Presence for releasing the global kill switch from the app window.
pub fn release_presence() -> Result<PresenceAttestation, PresenceError> {
    presence::require_presence(
        "Releasing the kill switch lets MCP clients drive your browser again.",
        Floor::CliConfirm,
    )
}

/// Presence for adding a trusted MCP client from the app window (the
/// user-idea gate recorded with the Phase 8 plan: a program the user runs
/// must never be able to enroll itself silently).
pub fn pairing_presence(client_name: &str) -> Result<PresenceAttestation, PresenceError> {
    presence::require_presence(
        &format!("Trusting the MCP client '{client_name}' lets it drive your browser."),
        Floor::CliConfirm,
    )
}

/// The user-facing explanation when presence is unavailable from the app.
/// Names the surfaces that DO work today instead of a bare refusal.
pub fn unavailable_guidance(err: &PresenceError) -> String {
    format!(
        "{err}. The in-app path needs the hardware user-presence gate \
         (Touch ID, Phase 8); until it lands, use the terminal \
         (`chromium-bridge unkill` / `pair-client`) or the extension's \
         options page for the kill switch."
    )
}
