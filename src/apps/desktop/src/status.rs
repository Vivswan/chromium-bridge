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
    /// The bundled host binary this app manages: resolved to its path, or the
    /// everywhere-it-looked error.
    pub host: HostResolution,
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

/// The MCP server, classified once from `LockFile::read()`'s three-way
/// result: exactly stopped (no lock file), running (parsed, with the probe
/// result), or lock-unreadable. A discriminated union on the wire, so the UI
/// matches states instead of re-deriving them from correlated nullables.
#[derive(Serialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ServerStatus {
    /// No lock file: not running.
    Stopped,
    /// Lock file parsed; `reachable` is the passive connect probe.
    Running {
        endpoint: String,
        pid: u32,
        reachable: bool,
    },
    /// The lock file exists but could not be read/parsed.
    Unreadable { detail: String },
}

/// Where the bundled host binary resolved to, mirroring the `Result` it
/// flattens onto the webview wire: exactly one of a path or an error.
#[derive(Serialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum HostResolution {
    Resolved { path: String },
    Unresolved { error: String },
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
        Ok(Some(lf)) => ServerStatus::Running {
            reachable: doctor::probe(&lf.endpoint),
            endpoint: lf.endpoint,
            pid: lf.pid,
        },
        Ok(None) => ServerStatus::Stopped,
        Err(e) => ServerStatus::Unreadable {
            detail: e.to_string(),
        },
    };

    let host = match host::resolve_host() {
        Ok(p) => HostResolution::Resolved {
            path: p.display().to_string(),
        },
        Err(e) => HostResolution::Unresolved { error: e },
    };

    BridgeStatus {
        version: env!("CARGO_PKG_VERSION"),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        kill,
        server,
        host,
    }
}
