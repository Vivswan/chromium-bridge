//! The global kill switch: one fail-closed latch that halts ALL bridge activity until a trusted surface
//! explicitly releases it. The latch is the `killed` flag of the trust record ([`crate::trust::Trust`]),
//! flipped by [`engage`] / [`release`] in one atomic write with an epoch bump, and it IS the authority: every
//! host-side enforcement point (tool dispatch, the broker's browser leg, the native host) reads that record the
//! same way and fails closed on an unreadable one; the extension only mirrors what the host pushes.
//!
//! Nothing clears the latch on its own: no timeout, restart, or reconnect. Only [`release`], reached from
//! `genkan unkill` and from the extension's `kill_release` behind a WebAuthn presence exchange, and it
//! demands a [`crate::presence::PresenceAttestation`]. Every attempt is audited: an attestation's grant or
//! refusal with its auth path, a presence-gate refusal with its error ([`audit_refused_release`]). A corrupt
//! record refuses BOTH directions ([`crate::trust::Trust::mutate_locked`]): an unkill from an unknown state
//! would be a fail-open.
//!
//! Residual: the trust record is writable by any same-user process, which can flip the latch off. That is
//! inside the conceded same-user boundary (such a process could equally replace the host binary); the kill
//! switch is a brake reachable from the user's own trusted surfaces, not a defense against it. Named in the
//! threat model.

use std::io;

use crate::audit::{self, AuditKind, AuditRecord, Surface};
use crate::error::CallError;
use crate::ipc;
use crate::presence::{self, PresenceAttestation};
use crate::trust::{Scope, Trust, TrustState};

/// Whether the kill switch is engaged. An unreadable record is an error the
/// caller must fail closed on, exactly like every other read of this record.
pub fn is_killed() -> io::Result<bool> {
    TrustState::current().map(|trust| trust.killed())
}

/// The dispatch gate: `Ok(())` only when the record is readable and the
/// switch is off. Both refusal shapes map to the stable `BRIDGE_KILLED` code.
pub fn check() -> Result<(), CallError> {
    verdict(TrustState::current())
}

/// The pure core of [`check`], with the disk read injected so the fail-closed
/// matrix is unit-testable without a runtime directory.
pub(crate) fn verdict(trust: io::Result<TrustState>) -> Result<(), CallError> {
    match trust {
        Ok(trust) if trust.killed() => Err(CallError::Killed),
        Ok(_) => Ok(()),
        Err(e) => Err(CallError::KillStateUnknown(e.to_string())),
    }
}

/// Engage the kill switch: `killed = true` and the epoch bump in one atomic write under the runtime lock.
/// Idempotent in effect (engaging an already-killed bridge just re-bumps), and every explicit act is
/// audited. Returns the new epoch.
pub fn engage(surface: Surface) -> io::Result<u64> {
    let epoch = set_killed(true)?;
    audit::record(
        AuditRecord::new(AuditKind::KillEngage)
            .surface(surface)
            .outcome("ok"),
    );
    Ok(epoch)
}

/// Release the kill switch. Same write shape as [`engage`]; refuses on an unreadable record (an unkill from an
/// unknown state would fail open). The attestation parameter makes the user-presence gate structural: only
/// [`crate::presence`] produces one, so no caller can release without presence attested, and the audit record
/// names the path that authorized it.
///
/// ```text
/// latch cleared                   -> audited `ok`
/// presence passed, write refused  -> audited `error`; the bridge stays killed and the caller still gets the `Err`
/// ```
pub fn release(surface: Surface, auth: PresenceAttestation) -> io::Result<u64> {
    let result = set_killed(false);
    let auth_name = auth.path().audit_label();
    match &result {
        Ok(_) => audit::record(
            AuditRecord::new(AuditKind::KillRelease)
                .surface(surface)
                .outcome("ok")
                .detail(&format!("auth={auth_name}")),
        ),
        Err(e) => audit::record(
            AuditRecord::new(AuditKind::KillRelease)
                .surface(surface)
                .outcome("error")
                .detail(&format!("auth={auth_name}; write refused: {e}")),
        ),
    }
    result
}

/// The words a release refuses with when the trust record fails it, read or written: `unkill` prints them and
/// the `kill_status_result` the options page reads carries them. Spelled here alone so the two cannot drift.
pub fn record_failure_sentence(e: &io::Error) -> String {
    format!("the trust record could not be read or written: {e}")
}

fn set_killed(killed: bool) -> io::Result<u64> {
    ipc::with_runtime_lock(|lock| Trust::mutate_locked(lock, Scope::Kill, |t| t.set_killed(killed)))
        .map(|trust| trust.epoch())
}

/// Record a release that was REFUSED at the presence gate, so an attempted
/// silent unkill (a piped stdin, a declined prompt, a refused assertion)
/// is visible in the trail.
pub(crate) fn audit_refused_release(surface: Surface, err: &presence::PresenceError) {
    audit::record(
        AuditRecord::new(AuditKind::KillRelease)
            .surface(surface)
            .outcome("refused")
            .detail(&format!("presence: {err}")),
    );
}

// ---- CLI handlers ------------------------------------------------------------

/// `genkan kill`: engage the switch. Returns a process exit code.
pub fn run_kill() -> i32 {
    match engage(Surface::Cli) {
        Ok(epoch) => {
            println!("kill switch ENGAGED (trust epoch {epoch})");
            println!(
                "all bridge activity is now refused: live browser connections are dropped \
                 within a second, every tool call fails with BRIDGE_KILLED, and the state \
                 survives restarts until `genkan unkill`"
            );
            0
        }
        Err(e) => {
            eprintln!("kill: could not write the trust record: {e}");
            eprintln!(
                "note: an unreadable record already fails every enforcement point closed, \
                 so bridge activity is refused either way; see docs/troubleshooting.md to recover"
            );
            1
        }
    }
}

/// `genkan unkill`: release the switch behind the CLI's presence path, an explicit typed confirmation
/// on a real terminal. A piped stdin or a declined prompt leaves the switch exactly as engaged as it was,
/// audited as a refused release. Returns a process exit code.
pub fn run_unkill() -> i32 {
    // The terminal witness comes first, by construction: tty_confirm demands it, so a piped stdin is refused
    // before any prompt is reachable.
    let auth = match presence::TerminalStdin::require().and_then(|terminal| {
        presence::tty_confirm(
            "Releasing the kill switch lets MCP clients drive your browser again.",
            terminal,
        )
    }) {
        Ok(auth) => auth,
        Err(e) => {
            audit_refused_release(Surface::Cli, &e);
            eprintln!("unkill: refused - {e}");
            eprintln!("the kill switch stays engaged");
            return 1;
        }
    };
    match release(Surface::Cli, auth) {
        Ok(epoch) => {
            println!("kill switch released (trust epoch {epoch})");
            println!("bridge activity resumes as connections re-establish");
            0
        }
        Err(e) => {
            eprintln!("unkill: refusing - {}", record_failure_sentence(&e));
            eprintln!(
                "releasing the kill switch from an unknown state would fail open; \
                 see docs/troubleshooting.md for the recovery path"
            );
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trust(killed: bool) -> TrustState {
        TrustState::from(Trust::fixture(
            3,
            killed,
            crate::trust::Clients::NeverPaired,
        ))
    }

    #[test]
    fn verdict_refuses_killed_and_unreadable_records_with_one_code() {
        // An unreadable record is indistinguishable from a suppressed kill, so both refusals carry the one
        // stable code the harness keys on.
        let cases = [
            ("readable, off", Ok(trust(false)), None),
            ("readable, killed", Ok(trust(true)), Some("BRIDGE_KILLED")),
            (
                "unreadable",
                Err(io::Error::other("corrupt")),
                Some("BRIDGE_KILLED"),
            ),
        ];
        for (case, record, want_code) in cases {
            let got = verdict(record);
            assert_eq!(got.as_ref().err().map(CallError::code), want_code, "{case}");
            match (case, got) {
                ("readable, killed", Err(CallError::Killed)) => {}
                ("unreadable", Err(CallError::KillStateUnknown(_))) => {}
                ("readable, off", Ok(())) => {}
                (case, got) => panic!("{case}: unexpected {got:?}"),
            }
        }
    }
}
