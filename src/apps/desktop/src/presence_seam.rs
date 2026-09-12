//! User-presence attestation for the app's two capability-granting acts: releasing the kill switch and pairing a
//! trusted client (ADR-0031; wired here per ADR-0029). `AppConfirm` succeeds by construction, asserting the app
//! ALREADY showed its own modal confirmation, so the UI ordering is load-bearing: the webview shows the dialog first
//! and only its confirm handler invokes the presence-gated commands (`ui/src/components/ui/confirm-dialog.tsx`); treat
//! any new caller as a security change (see the `Floor` docs in core).
//!
//! ```text
//! ladder          -> the hardware rung first (per-action Secure Enclave signing, a real Touch ID sheet on an enrolled
//!                    Mac), then the app's floor Floor::AppConfirm only when hardware is genuinely UNAVAILABLE, never
//!                    on a refusal
//! pairing         -> chromium_bridge_core::allowlist::pair_client_with_presence (see crate::clients), not
//!                    require_presence here
//! engage, revoke  -> ungated on every surface: they only reduce capability
//! ```

use chromium_bridge_core::policy::PolicyGrantFloor;
use chromium_bridge_core::presence::{self, Floor, PresenceAttestation, PresenceError};

/// The floor the app is entitled to claim, because every presence-gated
/// command is reachable only from the confirm dialog (the obligation above).
pub const APP_FLOOR: Floor = Floor::AppConfirm;

/// The policy-grant analogue of [`APP_FLOOR`] (ADR-0032 decision 5): the one surface allowed to store an
/// UNSIGNED policy baseline where the hardware rung is genuinely unavailable. Same obligation as
/// [`Floor::AppConfirm`], and the grant seam adds its own (see [`crate::policy_cmds::grant_lane`]):
///
/// ```text
/// enclave-status `supported && key == none`      -> this floor may be passed to `set_signed`
/// a key exists                                   -> the signed subprocess lane; a refused Touch ID there is terminal
/// key invalid, unreadable, or status unreadable  -> refused, pointing at enrollment or repair
/// ```
pub const APP_POLICY_FLOOR: PolicyGrantFloor = PolicyGrantFloor::AppConfirm;

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
