//! Host policy config (runtime_dir()/config.json, 0600).

use std::fs;
use std::io::{self, Write};

use serde::{Deserialize, Serialize};

/// Enrollment policy recorded on disk. This is policy only — the key material
/// lives exclusively in the Secure Enclave / keychain, never here. The file is
/// informational for `doctor`/`enclave-status` and for the extension-side
/// enrollment flow; the security decisions are enforced by the keychain ACL
/// (presence-gated signing) and the extension's public-key pin, not by these
/// bits, so a same-user process editing this file gains nothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfig {
    /// Whether a `pair` ceremony has completed on this machine.
    pub enrolled: bool,
    /// Verification granularity the user selected. Only "session" exists
    /// today (one presence proof per enrollment; reconnects are not
    /// presence-gated — see ADR-0021 for why and what that leaves open).
    pub granularity: String,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
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
                Ok(Some(cfg))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Write atomically (temp file + rename), 0600 on Unix, mirroring
    /// [`crate::ipc::LockFile::write`].
    pub fn write(&self) -> io::Result<()> {
        let path = Self::path();
        let mut tmp = path.clone();
        tmp.set_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(self)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.flush()?;
        }
        #[cfg(not(unix))]
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.flush()?;
        }
        #[cfg(not(unix))]
        if path.exists() {
            fs::remove_file(&path)?;
        }
        fs::rename(&tmp, &path)?;
        Ok(())
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
        let bytes = serde_json::to_vec(&cfg).unwrap();
        let back: HostConfig = serde_json::from_slice(&bytes).unwrap();
        assert!(!back.enrolled);
        assert_eq!(back.granularity, "session");
        assert_eq!(HostConfig::path().file_name().unwrap(), "config.json");
    }
}
