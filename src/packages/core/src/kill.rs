//! The global kill switch (ADR-0030): one fail-closed latch that halts ALL bridge activity until a trusted
//! surface explicitly releases it.
//!
//! The latch is the `killed` flag in `runtime_dir()/revocation.json` ([`crate::revocation::Revocation`]), flipped
//! by [`engage`] / [`release`] in one atomic write with an epoch bump and the `kill_epoch` marker. Unlike the
//! revocation epoch, the latch IS the authority: every enforcement point that already reads that record
//! fail-closed reads the kill state the same way, and no reader can observe a kill without the epoch bump.
//!
//! Enforcement points, each failing closed on an unreadable record:
//!
//! ```text
//! tool dispatch (`crate::mcp::handler`)       -> `check` first; refused with `BRIDGE_KILLED`, and the harness
//!                                                connection stays up so the refusal is delivered
//! the broker's browser leg (`crate::broker`)  -> live connections severed within one watcher tick; attaches refused
//! the native host (`crate::native_host`)      -> control-plane only: kill/status frames work, release is refused
//! the extension                               -> mirrors the state in SW-only trusted storage; the host is authoritative
//! ```
//!
//! Nothing clears the latch on its own: no timeout, restart, or reconnect. Only [`release`], reached from
//! `chromium-bridge unkill` and the desktop app (ADR-0032 decision 6 retired the extension release surface), and
//! it demands a [`crate::presence::PresenceAttestation`], so the user-presence ladder must have run
//! ([`crate::presence`]). Every release, granted or refused, is audited with the auth path that decided it. A corrupt
//! record refuses BOTH directions ([`crate::revocation::set_killed_locked`]): an unkill from an unknown state would
//! be a fail-open.
//!
//! Residual: `revocation.json` is writable by any same-user process, which can flip the latch off. That is inside
//! the conceded same-user boundary (such a process could equally replace the host binary); the kill switch is a
//! brake reachable from the user's own trusted surfaces, not a defense against it. Named in the threat model.

use std::io;

use crate::audit::{self, AuditKind, AuditRecord, Surface};
use crate::error::CallError;
use crate::ipc;
use crate::presence::{self, Floor, PresenceAttestation};
use crate::revocation::{self, Revocation};

/// Whether the kill switch is engaged. An unreadable record is an error the
/// caller must fail closed on, exactly like every other read of this record.
pub fn is_killed() -> io::Result<bool> {
    Revocation::current().map(|rev| rev.killed)
}

/// The dispatch gate: `Ok(())` only when the record is readable and the
/// switch is off. Both refusal shapes map to the stable `BRIDGE_KILLED` code.
pub fn check() -> Result<(), CallError> {
    verdict(Revocation::current())
}

/// The pure core of [`check`], with the disk read injected so the fail-closed
/// matrix is unit-testable without a runtime directory.
pub(crate) fn verdict(rev: io::Result<Revocation>) -> Result<(), CallError> {
    match rev {
        Ok(rev) if rev.killed => Err(CallError::Killed),
        Ok(_) => Ok(()),
        Err(e) => Err(CallError::KillStateUnknown(e.to_string())),
    }
}

/// Engage the kill switch: `killed = true`, `kill_epoch` stamped, epoch
/// bumped, one atomic write under the runtime lock. Idempotent in effect
/// (engaging an already-killed bridge just re-bumps), and every explicit act
/// is audited. Returns the new epoch.
pub fn engage(surface: Surface) -> io::Result<u64> {
    let epoch = ipc::with_runtime_lock(|lock| revocation::set_killed_locked(lock, true))?;
    // Log-after-decide, outside the critical section.
    audit::record(
        AuditRecord::new(AuditKind::KillEngage)
            .surface(surface)
            .outcome("ok"),
    );
    Ok(epoch)
}

/// Release the kill switch. Same write shape as [`engage`]; refuses on an unreadable record (an unkill from an
/// unknown state would fail open). The attestation parameter makes the user-presence gate structural: only
/// [`presence::require_presence`] produces one, so no caller can release without the ladder having run, and the
/// audit record names the rung that authorized it.
///
/// ```text
/// latch cleared                   -> audited `ok`
/// presence passed, write refused  -> audited `error`; the bridge stays killed and the caller still gets the `Err`
/// ```
pub fn release(surface: Surface, auth: PresenceAttestation) -> io::Result<u64> {
    let result = ipc::with_runtime_lock(|lock| revocation::set_killed_locked(lock, false));
    // Log-after-decide, outside the critical section, on BOTH arms.
    let auth_name = auth.path().wire_name();
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

/// Record a release that was REFUSED at the presence gate, so an attempted
/// silent unkill (a piped stdin, a declined prompt, a failed hardware check)
/// is visible in the trail. Log-after-decide: the refusal already happened.
pub(crate) fn audit_refused_release(surface: Surface, err: &presence::PresenceError) {
    audit::record(
        AuditRecord::new(AuditKind::KillRelease)
            .surface(surface)
            .outcome("refused")
            .detail(&format!("presence: {err}")),
    );
}

// ---- CLI handlers ------------------------------------------------------------

/// `chromium-bridge kill`: engage the switch. Returns a process exit code.
pub fn run_kill() -> i32 {
    match engage(Surface::Cli) {
        Ok(epoch) => {
            println!("kill switch ENGAGED (revocation epoch {epoch})");
            println!(
                "all bridge activity is now refused: live browser connections are dropped \
                 within a second, every tool call fails with BRIDGE_KILLED, and the state \
                 survives restarts until `chromium-bridge unkill`"
            );
            0
        }
        Err(e) => {
            eprintln!("kill: could not write the revocation record: {e}");
            eprintln!(
                "note: an unreadable record already fails every enforcement point closed, \
                 so bridge activity is refused either way; see docs/operations.md to recover"
            );
            1
        }
    }
}

/// `chromium-bridge unkill`: release the switch, behind the user-presence
/// gate (ADR-0030/0031): a Secure Enclave Touch ID tap on an enrolled Mac,
/// otherwise the CLI floor - an explicit typed confirmation on a real
/// terminal. A piped stdin, a declined prompt, or a failed hardware check
/// leaves the switch exactly as engaged as it was, audited as a refused
/// release. Returns a process exit code.
pub fn run_unkill() -> i32 {
    // The terminal witness comes first, by construction: `Floor::CliConfirm`
    // cannot exist without it, so a piped stdin is refused before
    // require_presence - and any hardware prompt - is reachable.
    let auth = match presence::TerminalStdin::require()
        .map(Floor::CliConfirm)
        .and_then(|floor| {
            presence::require_presence(
                "Releasing the kill switch lets MCP clients drive your browser again.",
                floor,
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
            println!("kill switch released (revocation epoch {epoch})");
            println!("bridge activity resumes as connections re-establish");
            0
        }
        Err(e) => {
            eprintln!("unkill: refusing - the revocation record could not be read: {e}");
            eprintln!(
                "releasing the kill switch from an unknown state would fail open; \
                 see docs/operations.md for the recovery path"
            );
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rev(killed: bool) -> Revocation {
        Revocation {
            version: 1,
            epoch: 3,
            clients_epoch: 0,
            host_key_epoch: 0,
            policy_epoch: 0,
            lang_epoch: 0,
            clients_enrolled: false,
            killed,
            kill_epoch: if killed { 3 } else { 0 },
        }
    }

    #[test]
    fn verdict_allows_only_a_readable_unkilled_record() {
        assert!(verdict(Ok(rev(false))).is_ok());
    }

    #[test]
    fn verdict_refuses_while_killed_with_the_stable_code() {
        let err = verdict(Ok(rev(true))).unwrap_err();
        assert!(matches!(err, CallError::Killed));
        assert_eq!(err.code(), "BRIDGE_KILLED");
    }

    #[test]
    fn verdict_fails_closed_on_an_unreadable_record() {
        // "Corrupt/missing kill marker while latch state unknown -> refuse":
        // an unreadable record is indistinguishable from a suppressed kill,
        // so the call is refused with the same stable code.
        let err = verdict(Err(io::Error::other("corrupt"))).unwrap_err();
        assert!(matches!(err, CallError::KillStateUnknown(_)));
        assert_eq!(err.code(), "BRIDGE_KILLED");
    }
}
