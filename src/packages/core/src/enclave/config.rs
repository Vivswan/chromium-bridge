//! The enrollment record (`config.json`).

use serde::{Deserialize, Serialize};

use crate::runtime_record::{Ladder, Record};

/// Enrollment policy recorded on disk, policy only: the key material lives in the Secure Enclave / keychain, and the
/// security decisions are enforced by the keychain ACL (presence-gated signing) and the extension's public-key pin,
/// so a same-user process editing this file gains nothing. Parsing is fail-closed (`deny_unknown_fields`)
/// because only this binary reads and writes the file, with no cross-version coexistence window (unlike the lock file,
/// which brokers and Chrome-spawned hosts of different builds may read during an upgrade), so a tampered or newer file
/// is refused instead of half-read, and a new field is a deliberate schema change: a rung in `crate::migrations`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    /// Whether a `pair` ceremony has completed on this machine.
    pub enrolled: bool,
    /// Verification granularity the user selected. Only "session" exists
    /// today (one presence proof per enrollment; reconnects are not
    /// presence-gated).
    pub granularity: String,
}

impl Record for HostConfig {
    const FILE: &'static str = "config.json";
    const MAX_BYTES: usize = 4 * 1024;
    const LADDER: Ladder = crate::migrations::config::LADDER;
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            enrolled: false,
            granularity: "session".into(),
        }
    }
}
