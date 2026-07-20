//! The kill switch and the audit trail, from the app (ADR-0030/0029).
//! Engaging is zero-friction (it only reduces capability); releasing demands
//! the user-presence gate. Reading the trail applies the same strict
//! per-record parse as `chromium-bridge audit`: an unparsable line is shown
//! as unrecognized, never guessed at.

use serde::Serialize;

use chromium_bridge_core::audit::{self, AuditKind, AuditRecord, Surface, AUDIT_VERSION};
use chromium_bridge_core::kill;

use crate::presence_seam;

/// Engage: one click, no confirmation. Returns the new revocation epoch.
pub fn engage() -> Result<u64, String> {
    kill::engage(Surface::Core).map_err(|e| {
        format!(
            "could not write the revocation record: {e} (note: an unreadable record \
             already fails every enforcement point closed, so bridge activity is \
             refused either way)"
        )
    })
}

/// A granted release: the new epoch, and the presence path that authorized
/// it (the UI shows which proof was used - Touch ID or the app floor).
#[derive(Serialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(rename_all = "camelCase")]
pub struct ReleaseOutcome {
    pub epoch: u64,
    /// Which presence proof authorized the release (touch_id, app_confirm, ...).
    pub auth: &'static str,
}

/// Release, behind the presence gate (the caller must have shown the in-app
/// confirm dialog first, see `crate::presence_seam`). A refused gate is
/// audited so an attempted silent unkill is visible in the trail, mirroring
/// the CLI's `unkill` handler; the switch stays exactly as engaged as it was.
pub fn release() -> Result<ReleaseOutcome, String> {
    let att = match presence_seam::release_presence() {
        Ok(att) => att,
        Err(e) => {
            // Log-after-decide: the refusal already happened.
            audit::record(
                AuditRecord::new(AuditKind::KillRelease)
                    .surface(Surface::Core)
                    .outcome("refused")
                    .detail(&format!("presence: {e}")),
            );
            return Err(format!("{e}. The kill switch stays engaged."));
        }
    };
    let auth = att.path().wire_name();
    let epoch = kill::release(Surface::Core, att).map_err(|e| {
        format!(
            "refusing - the revocation record could not be read: {e}. Releasing \
             from an unknown state would fail open; see docs/operations.md."
        )
    })?;
    Ok(ReleaseOutcome { epoch, auth })
}

/// One line of the audit panel: a strictly parsed record, or an explicit
/// unrecognized marker in its place (order preserved).
#[derive(Serialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(untagged)]
pub enum AuditLine {
    Record(AuditRecord),
    Unrecognized { unrecognized: bool },
}

#[derive(Serialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(rename_all = "camelCase")]
pub struct AuditPage {
    /// Oldest first, rotated file included, capped to `limit` newest.
    pub lines: Vec<AuditLine>,
    pub unrecognized: usize,
    pub path: String,
}

/// Read the on-disk trail (live file plus the single rotation), newest
/// `limit` records. Read-only.
pub fn read(limit: usize) -> Result<AuditPage, String> {
    let live = audit::audit_path();
    let rotated = {
        let mut s = live.as_os_str().to_owned();
        s.push(".1");
        std::path::PathBuf::from(s)
    };
    let mut raw: Vec<String> = Vec::new();
    for path in [rotated, live.clone()] {
        match std::fs::read_to_string(&path) {
            Ok(text) => raw.extend(text.lines().map(str::to_string)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        }
    }
    let start = raw.len().saturating_sub(limit);
    let mut lines = Vec::new();
    let mut unrecognized = 0usize;
    for line in raw.iter().skip(start) {
        match parse_record(line) {
            Some(rec) => lines.push(AuditLine::Record(rec)),
            None => {
                unrecognized += 1;
                lines.push(AuditLine::Unrecognized { unrecognized: true });
            }
        }
    }
    Ok(AuditPage {
        lines,
        unrecognized,
        path: live.display().to_string(),
    })
}

/// Strict parse, same rules as the CLI reader: valid JSON, known fields only
/// (`deny_unknown_fields` on the record), supported version.
fn parse_record(line: &str) -> Option<AuditRecord> {
    let rec: AuditRecord = serde_json::from_str(line).ok()?;
    (rec.v == AUDIT_VERSION).then_some(rec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_is_strict_about_version_and_shape() {
        assert!(parse_record("not json").is_none());
        assert!(parse_record(r#"{"v":99,"ts_ms":1,"kind":"tool_call"}"#).is_none());
        assert!(parse_record(r#"{"v":1,"ts_ms":1,"kind":"tool_call"}"#).is_some());
        assert!(parse_record(r#"{"v":1,"ts_ms":1,"kind":"tool_call","surprise":1}"#).is_none());
    }
}
