//! The app's status view: the same facts `chromium-bridge doctor` reports,
//! gathered through the same core APIs, returned as data instead of text.
//! Read-only: nothing here mutates state, probes send no bytes, and the
//! browser is never touched.

use serde::Serialize;

use chromium_bridge_core::ipc::LockFile;
use chromium_bridge_core::{doctor, kill};

use crate::host;

#[derive(Serialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(rename_all = "camelCase")]
pub struct BridgeStatus {
    pub version: &'static str,
    pub os: &'static str,
    pub arch: &'static str,
    pub kill: KillState,
    pub server: ServerStatus,
    /// The bundled host binary this app manages, when it resolves.
    pub host_path: Option<String>,
    pub host_error: Option<String>,
}

/// The kill switch as the status view names it. An unreadable record is its
/// own state, not "off": while it is unreadable every enforcement point is
/// refusing, and the UI must say so.
#[derive(Serialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum KillState {
    Off,
    Engaged,
    Unreadable { detail: String },
}

#[derive(Serialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(rename_all = "camelCase")]
pub struct ServerStatus {
    pub lock_present: bool,
    pub lock_error: Option<String>,
    pub endpoint: Option<String>,
    pub pid: Option<u32>,
    /// `None` when no probe was attempted (no lock file / no endpoint).
    pub reachable: Option<bool>,
}

pub fn gather() -> BridgeStatus {
    let kill = match kill::is_killed() {
        Ok(true) => KillState::Engaged,
        Ok(false) => KillState::Off,
        Err(e) => KillState::Unreadable {
            detail: e.to_string(),
        },
    };

    let server = match LockFile::read() {
        Ok(Some(lf)) => ServerStatus {
            lock_present: true,
            lock_error: None,
            reachable: Some(doctor::probe(&lf.endpoint)),
            endpoint: Some(lf.endpoint),
            pid: Some(lf.pid),
        },
        Ok(None) => ServerStatus {
            lock_present: false,
            lock_error: None,
            endpoint: None,
            pid: None,
            reachable: None,
        },
        Err(e) => ServerStatus {
            lock_present: true,
            lock_error: Some(e.to_string()),
            endpoint: None,
            pid: None,
            reachable: None,
        },
    };

    let (host_path, host_error) = match host::resolve_host() {
        Ok(p) => (Some(p.display().to_string()), None),
        Err(e) => (None, Some(e)),
    };

    BridgeStatus {
        version: env!("CARGO_PKG_VERSION"),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        kill,
        server,
        host_path,
        host_error,
    }
}
