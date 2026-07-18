//! PHASE 8 INTEGRATION POINT: user-presence attestation for the app's two
//! capability-granting acts (releasing the kill switch, pairing a trusted
//! client).
//!
//! The contract agreed with phase8 (feat/phase8-touchid), which this file
//! swaps to when that branch lands:
//!
//! - Client pairing calls `allowlist::pair_client_with_presence(name, anchor,
//!   Surface::Core, Floor::AppConfirm)`: it validates the name BEFORE any
//!   prompt, raises Touch ID itself on capable hardware, falls back to the
//!   floor only when hardware is UNAVAILABLE (never on refusal), and returns
//!   the `PresencePath` that authorized it (shown in the UI).
//! - Unkill calls `presence::require_presence(reason, Floor::AppConfirm)`
//!   then `kill::release(Surface::Core, auth)`.
//!
//! `Floor::AppConfirm` succeeds by construction when hardware is unavailable:
//! it asserts the app ALREADY showed its own explicit modal confirmation.
//! That makes the UI ordering load-bearing: the webview shows the confirm
//! dialog first, and only its confirm handler invokes these commands (see
//! `ui/src/components/ui/confirm-dialog.tsx`). Calling these functions
//! without that dialog would claim a confirmation that never happened.
//! Engage and revoke stay ungated on every surface: they only reduce
//! capability.
//!
//! Until the phase8 branch lands, `Floor::AppConfirm` does not exist, so
//! [`APP_FLOOR`] is `Floor::CliConfirm` and both acts FAIL CLOSED from a GUI
//! (hardware unavailable, and a GUI's stdin is not a terminal). That is the
//! intended pre-phase8 posture; the error strings name the trusted surfaces
//! that work today. The extension floor is out of reach on purpose: claiming
//! `Floor::ExtensionConfirm` from here would assert a channel-attested
//! confirmation that never happened (see the warning on `presence::Floor`).

use chromium_bridge_core::presence::{self, Floor, PresenceAttestation, PresenceError};

/// The floor the app claims once phase8 lands: `Floor::AppConfirm`.
/// `CliConfirm` until then, which refuses in a GUI - fail closed, on purpose.
const APP_FLOOR: Floor = Floor::CliConfirm;

/// Presence for releasing the kill switch from the app window. The caller
/// must have shown the in-app confirm dialog first (see the module docs).
pub fn release_presence() -> Result<PresenceAttestation, PresenceError> {
    presence::require_presence(
        "Releasing the kill switch lets MCP clients drive your browser again.",
        APP_FLOOR,
    )
}

/// Presence for adding a trusted MCP client from the app window (the
/// user-idea gate recorded with the Phase 8 plan: a program the user runs
/// must never be able to enroll itself silently). Same dialog-first
/// obligation; the caller swaps to `pair_client_with_presence` when phase8
/// lands.
pub fn pairing_presence(client_name: &str) -> Result<PresenceAttestation, PresenceError> {
    presence::require_presence(
        &format!("Trusting the MCP client '{client_name}' lets it drive your browser."),
        APP_FLOOR,
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
