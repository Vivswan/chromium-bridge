//! Host policy config (runtime_dir()/config.json, 0600).

use std::fs;
use std::io;

use serde::{Deserialize, Serialize};

/// Enrollment policy recorded on disk. This is policy only — the key material
/// lives exclusively in the Secure Enclave / keychain, never here. The file is
/// informational for `doctor`/`enclave-status` and for the extension-side
/// enrollment flow; the security decisions are enforced by the keychain ACL
/// (presence-gated signing) and the extension's public-key pin, not by these
/// bits, so a same-user process editing this file gains nothing.
///
/// Parsing is fail-closed (`deny_unknown_fields`, ADR-0025): this file is
/// written and read only by this binary on one machine, with no cross-version
/// coexistence window (unlike the lock file, which live brokers and
/// Chrome-spawned hosts of different builds may read concurrently during an
/// upgrade), so rejecting an unknown shape costs nothing and refuses a
/// tampered or newer file instead of half-reading it. A future field is a
/// deliberate schema change: bump [`HOST_CONFIG_VERSION`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    /// Schema version; see [`HOST_CONFIG_VERSION`]. Absent in files written
    /// before the version field existed, which `default` maps to v1 (their
    /// exact shape).
    #[serde(default = "default_config_version")]
    pub version: u32,
    /// Whether a `pair` ceremony has completed on this machine.
    pub enrolled: bool,
    /// Verification granularity the user selected. Only "session" exists
    /// today (one presence proof per enrollment; reconnects are not
    /// presence-gated — see ADR-0021 for why and what that leaves open).
    pub granularity: String,
}

/// Current schema version of `config.json`.
const HOST_CONFIG_VERSION: u32 = 1;

fn default_config_version() -> u32 {
    HOST_CONFIG_VERSION
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            version: HOST_CONFIG_VERSION,
            enrolled: false,
            granularity: "session".into(),
        }
    }
}

impl HostConfig {
    pub fn path() -> std::path::PathBuf {
        crate::ipc::runtime_dir().join("config.json")
    }

    pub fn read() -> io::Result<Option<Self>> {
        match fs::read(Self::path()) {
            Ok(bytes) => {
                let cfg: HostConfig = serde_json::from_slice(&bytes).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("config decode: {e}"))
                })?;
                if cfg.version != HOST_CONFIG_VERSION {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "config version {} is not supported (this binary understands {})",
                            cfg.version, HOST_CONFIG_VERSION
                        ),
                    ));
                }
                Ok(Some(cfg))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Write via the hardened [`crate::ipc::write_private_atomic`] (exclusive
    /// 0600 temp file + rename), like every other private record in the
    /// runtime directory.
    pub fn write(&self) -> io::Result<()> {
        let bytes = serde_json::to_vec_pretty(self)?;
        crate::ipc::write_private_atomic(&Self::path(), &bytes)
    }

    pub fn remove() {
        let _ = fs::remove_file(Self::path());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_config_serde_roundtrip_and_default() {
        let cfg = HostConfig::default();
        assert!(!cfg.enrolled);
        assert_eq!(cfg.granularity, "session");
        assert_eq!(cfg.version, HOST_CONFIG_VERSION);
        let bytes = serde_json::to_vec(&cfg).unwrap();
        let back: HostConfig = serde_json::from_slice(&bytes).unwrap();
        assert!(!back.enrolled);
        assert_eq!(back.granularity, "session");
        assert_eq!(HostConfig::path().file_name().unwrap(), "config.json");
    }

    #[test]
    fn host_config_parsing_is_fail_closed() {
        // Unknown fields are rejected (deny_unknown_fields, ADR-0025): this
        // file has no cross-version coexistence window, so strictness is free.
        assert!(serde_json::from_value::<HostConfig>(serde_json::json!({
            "version": 1, "enrolled": true, "granularity": "session", "surprise": 1
        }))
        .is_err());
        // A pre-version-field file (the original v1 shape) still parses, with
        // the version defaulted.
        let old: HostConfig = serde_json::from_value(serde_json::json!({
            "enrolled": true, "granularity": "session"
        }))
        .unwrap();
        assert_eq!(old.version, HOST_CONFIG_VERSION);
    }
}
