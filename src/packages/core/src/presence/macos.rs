//! macOS hardware user presence: a Secure Enclave signing operation gated on
//! the enrollment key's `kSecAccessControlUserPresence` ACL. Performing that
//! operation forces Touch ID (or the login password through the same system
//! sheet), and it CANNOT succeed without a live user action - which is the
//! whole security property.
//!
//! Why not LocalAuthentication (`LAContext.evaluatePolicy`)? Empirically, on
//! this platform `deviceOwnerAuthentication` can return success WITHOUT any
//! fresh user interaction (a recently-authenticated session satisfies it), so
//! it is not a reliable proof of presence for a capability-restoring act. The
//! Enclave key's user-presence ACL is the primitive we have already proven
//! prompts on real hardware (the `pair` ceremony and the per-action presence
//! signing, ADR-0021/0031), so the local presence attestation reuses exactly
//! that: sign a throwaway challenge and discard the signature - we care only
//! that the presence-gated Enclave operation SUCCEEDED.
//!
//! Ladder mapping (see [`super::require_presence`] for the no-downgrade rule):
//! - no enrollment key on this machine -> `Unavailable` (there is no hardware
//!   rung here; the caller's interactive floor still requires a human);
//! - a lookup error (unusable/planted key) -> `Unavailable` (fall to the
//!   floor, which is itself a human check - never silently succeed);
//! - the Enclave signing op succeeds -> `Verified` (a human was present);
//! - the signing op fails (the user cancelled the prompt, biometry failed, or
//!   no window server could raise it) -> `Refused`, which never falls back.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::enclave::EnrollmentKey;

use super::HardwareOutcome;

/// Domain-separated context for the LOCAL presence attestation (kill/pair),
/// distinct from any per-action page context. The signature is discarded, so
/// this only documents intent; the security property is that the
/// user-presence-gated Enclave op ran at all.
const LOCAL_PRESENCE_CONTEXT: &str = "host-local-presence-v1";

/// One user-presence attestation via a Secure Enclave signing operation.
/// Raises the system Touch ID sheet on a machine with a logged-in session; the
/// returned signature is thrown away.
pub(super) fn authenticate(_reason: &str) -> HardwareOutcome {
    let key = match EnrollmentKey::lookup() {
        Ok(Some(key)) => key,
        Ok(None) => {
            // Not enrolled: there is no Enclave key to gate on, so there is no
            // hardware rung here. The caller's interactive floor - itself a
            // human check - holds the line.
            log_info!(
                "presence",
                "no enrollment key; hardware user presence unavailable (using the floor)"
            );
            return HardwareOutcome::Unavailable;
        }
        Err(e) => {
            // The key could not be resolved (unsupported, or a suspect/planted
            // key). Do not treat this as a refusal - fall to the floor, which
            // still requires a human. Never silently succeed.
            log_info!(
                "presence",
                "enrollment key not usable for a presence attestation ({e}); using the floor"
            );
            return HardwareOutcome::Unavailable;
        }
    };
    // A fresh, unique nonce per attestation so each is a distinct Enclave op.
    // It need not be unpredictable (nothing verifies or stores it); a
    // monotonic timestamp is enough to avoid any keychain-level caching.
    let nonce = format!(
        "presence-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    match key.sign_presence(&nonce, Some(LOCAL_PRESENCE_CONTEXT)) {
        Ok(_sig) => HardwareOutcome::Verified,
        Err(e) => {
            // The key exists but the presence-gated signing did not complete:
            // the user cancelled, biometry failed, or no prompt could be
            // raised. This is a genuine REFUSAL and must never downgrade to
            // the floor (an attacker who can make the prompt fail must not
            // thereby soften the gate).
            log_warn!(
                "presence",
                "hardware user-presence attestation refused: {e}"
            );
            HardwareOutcome::Refused(e.to_string())
        }
    }
}
