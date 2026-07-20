//! Trusted-client management from the app: list, revoke, and the
//! presence-gated add (ADR-0024/0029). Reads honor the tamper-evidence latch
//! exactly like `list-clients`; writes go through the core entry points,
//! which audit with `Surface::Core` so the trail names which surface acted.

use serde::Serialize;

use chromium_bridge_core::allowlist::{self, Allowlist, Anchor};
use chromium_bridge_core::audit::Surface;
use chromium_bridge_core::cli::AnchorSpec;
use chromium_bridge_core::revocation::Revocation;

use crate::presence_seam;

/// The anchor kind on the wire: the same `hash` / `team_id` names
/// `AnchorSpec` parses back in [`pair`]. An enum rather than a string so the
/// generated TS carries the literal union straight from the serde attribute.
#[derive(Serialize, Clone, Copy)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum AnchorKind {
    Hash,
    TeamId,
}

#[derive(Serialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(rename_all = "camelCase")]
pub struct ClientRow {
    pub name: String,
    pub anchor_kind: AnchorKind,
    pub anchor_value: String,
    pub added_unix: u64,
}

/// Whether client admission is enforced: `unenrolled` (no allowlist yet) or
/// `enforced`.
#[derive(Serialize, Clone, Copy)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum Posture {
    Unenrolled,
    Enforced,
}

#[derive(Serialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(rename_all = "camelCase")]
pub struct ClientsPayload {
    pub posture: Posture,
    pub clients: Vec<ClientRow>,
}

/// List the allowlist. A corrupt list or a latched-but-absent one (tampering)
/// is an `Err` the UI must show as loudly as the CLI does - never an empty
/// table.
pub fn list() -> Result<ClientsPayload, String> {
    let latched = Revocation::current()
        .map_err(|e| format!("revocation record unreadable (failing closed): {e}"))?
        .clients_enrolled;
    let list = allowlist::load_enforced(latched).map_err(|e| e.to_string())?;
    Ok(match list {
        None => ClientsPayload {
            posture: Posture::Unenrolled,
            clients: Vec::new(),
        },
        Some(list) => ClientsPayload {
            posture: Posture::Enforced,
            clients: list
                .clients
                .into_iter()
                .map(|c| {
                    let (anchor_kind, anchor_value) = match c.anchor {
                        Anchor::Hash(h) => (AnchorKind::Hash, h),
                        Anchor::TeamId(t) => (AnchorKind::TeamId, t),
                    };
                    ClientRow {
                        name: c.name,
                        anchor_kind,
                        anchor_value,
                        added_unix: c.added_unix,
                    }
                })
                .collect(),
        },
    })
}

/// Revoke one client. Friction-free by design (revocation reduces
/// capability). The audit record is written inside `Allowlist::revoke`
/// itself, with our surface, so this caller cannot forget the trail entry.
/// Returns whether an entry was removed.
pub fn revoke(name: &str) -> Result<bool, String> {
    Allowlist::revoke(name, Surface::Core).map_err(|e| e.to_string())
}

/// Add (or re-pair) a trusted client, behind the user-presence gate: pairing
/// GRANTS capability, so it demands proof of the user, not just a click in a
/// window. Goes through `allowlist::pair_client_with_presence` (ADR-0031),
/// the one entry point every surface uses - it validates the name before any
/// prompt, runs the presence ladder (a real Touch ID sheet on an enrolled
/// Mac; the app floor only when hardware is unavailable), audits both
/// outcomes, and only then writes the allowlist. The caller must have shown
/// the in-app confirm dialog first (see `crate::presence_seam`). Returns the
/// presence path that authorized the pairing, for the UI to show. The anchor
/// is validated by the same core path as the CLI's flags, also before any
/// prompt.
pub fn pair(name: &str, anchor_kind: &str, anchor_value: &str) -> Result<&'static str, String> {
    let spec = match anchor_kind {
        "hash" => AnchorSpec::Hash(anchor_value.to_string()),
        "team_id" => AnchorSpec::TeamId(anchor_value.to_string()),
        other => return Err(format!("unknown anchor kind {other:?}")),
    };
    let anchor = allowlist::resolve_anchor(&spec)?;
    let path =
        allowlist::pair_client_with_presence(name, anchor, Surface::Core, presence_seam::APP_FLOOR)
            .map_err(|e| e.to_string())?;
    Ok(path.wire_name())
}
