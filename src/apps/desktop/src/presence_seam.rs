//! User-presence attestation for the app's two capability-granting acts:
//! releasing the kill switch, and pairing a trusted client (ADR-0031, wired
//! here per ADR-0029).
//!
//! Both route through core's presence ladder: the hardware rung first
//! (per-action Secure Enclave signing - a real Touch ID sheet on an enrolled
//! Mac), then, only when hardware is genuinely UNAVAILABLE and never on a
//! refusal, the app's floor, [`Floor::AppConfirm`].
//!
//! `AppConfirm` succeeds by construction: it asserts the app ALREADY showed
//! its own explicit modal confirmation. That makes the UI ordering
//! load-bearing: the webview shows the confirm dialog first, and only its
//! confirm handler invokes the presence-gated commands (see
//! `ui/src/components/ui/confirm-dialog.tsx`). Claiming this floor without
//! that dialog would assert a confirmation that never happened; treat any
//! new caller as a security change (see the `Floor` docs in core).
//!
//! Pairing does not call `require_presence` here: it goes through
//! [`chromium_bridge_core::allowlist::pair_client_with_presence`] (see
//! `crate::clients`), the one entry point every surface uses to grant
//! harness capability - it validates the name before any prompt, runs this
//! same ladder, and audits both outcomes itself. Engage and revoke stay
//! ungated on every surface: they only reduce capability.

use chromium_bridge_core::presence::{self, Floor, PresenceAttestation, PresenceError};

/// The floor the app is entitled to claim, because every presence-gated
/// command is reachable only from the confirm dialog (the obligation above).
pub const APP_FLOOR: Floor = Floor::AppConfirm;

/// Presence for releasing the kill switch from the app window. The caller
/// must have shown the in-app confirm dialog first (see the module docs).
/// On an enrolled Mac this raises the Touch ID sheet; a refusal is final
/// (never downgraded to the floor) and leaves the switch engaged.
pub fn release_presence() -> Result<PresenceAttestation, PresenceError> {
    presence::require_presence(
        "Releasing the kill switch lets MCP clients drive your browser again.",
        APP_FLOOR,
    )
}
