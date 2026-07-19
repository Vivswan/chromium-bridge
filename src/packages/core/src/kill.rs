//! The global kill switch (ADR-0030): one fail-closed latch that halts ALL
//! bridge activity until a trusted surface explicitly releases it.
//!
//! ## Where the state lives
//!
//! The latch is the `killed` flag in `runtime_dir()/revocation.json`
//! ([`crate::revocation::Revocation`]), flipped by [`engage`] / [`release`]
//! in one atomic write together with an epoch bump (and the `kill_epoch`
//! marker observers watch). Unlike the revocation epoch, the latch IS the
//! authority: there is no second file to re-read. Riding in the atomically
//! written revocation record buys two things for free: every enforcement
//! point that already reads that record fail-closed now reads the kill state
//! the same way, and no reader can ever observe a kill without the epoch bump
//! that announces it.
//!
//! ## Enforcement points
//!
//! - **Tool dispatch** ([`crate::mcp_server::handle`]): every `tools/call`
//!   from every harness (the broker's own and every relay) passes [`check`]
//!   first; while killed (or the state is unreadable) the call is answered
//!   with the stable `BRIDGE_KILLED` taxonomy code, fail closed, and the
//!   harness connection stays up so the refusal is *delivered* rather than
//!   the server dying opaquely.
//! - **The broker's browser leg**: a kill severs every live browser
//!   connection within one watcher tick ([`crate::broker`]), and browser
//!   attaches are refused while killed, so no path to a browser exists even
//!   if a dispatch bug were found.
//! - **The native host** runs a control-plane-only mode while killed
//!   ([`crate::native_host`]): no bridge traffic, but the extension's
//!   kill/unkill/status control frames keep working, which is what lets the
//!   options page release the switch again.
//! - **The extension** mirrors the state into its #32 SW-only trusted storage
//!   and refuses ops locally while killed (defense in depth; the host side is
//!   authoritative).
//!
//! ## Unkill is explicit, user-present, never automatic
//!
//! Nothing in the bridge clears the latch on its own -- no timeout, no
//! restart, no reconnect. Only [`release`], reached from the CLI
//! (`chromium-bridge unkill`), the extension options page, or a future app
//! through this same API -- and `release` demands a
//! [`crate::presence::PresenceAttestation`], so no path can clear the latch
//! without the user-presence ladder having run (Touch ID via a Secure Enclave
//! signing op on an enrolled Mac; the per-surface interactive floors where no
//! Enclave key exists, see [`crate::presence`]).
//! Failed or unavailable auth leaves the bridge killed, and every release --
//! granted or refused -- is audited with the auth path that decided it. A
//! corrupt record refuses BOTH directions (see
//! [`crate::revocation::set_killed_locked`]): while the state is unknowable
//! every enforcement point is already refusing, and an unkill from an unknown
//! state would be a fail-open.
//!
//! ## Residual (same-user writer)
//!
//! `revocation.json` is writable by any process of the same user; such a
//! process can flip the latch off. That is inside the conceded same-user
//! boundary (threat #4: it could equally substitute the host binary or delete
//! the trust files), and the kill switch is not a defense against it -- it is
//! a fail-closed brake reachable from the user's own trusted surfaces. Named
//! in the threat model rather than implied covered.

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
    let epoch = ipc::with_runtime_lock(|| revocation::set_killed_locked(true))?;
    // Log-after-decide, outside the critical section.
    audit::record(
        AuditRecord::new(AuditKind::KillEngage)
            .surface(surface)
            .outcome("ok"),
    );
    Ok(epoch)
}

/// Release the kill switch. Same write shape as [`engage`]; refuses on an
/// unreadable record (an unkill from an unknown state would fail open). The
/// attestation parameter is the user-presence gate made structural: the only
/// way to obtain one is [`presence::require_presence`], so a caller cannot
/// release without the ladder having run, and the audit record names the
/// rung that authorized it.
///
/// BOTH outcomes are audited here, so the trail covers the full release
/// attempt space: `ok` when the latch cleared, `error` when presence passed
/// but the record write refused (corrupt record). The error arm changes
/// nothing about enforcement - the bridge stays killed and the caller still
/// gets the `Err` - it only makes the attempt durably visible with the auth
/// rung that vouched for it.
pub fn release(surface: Surface, auth: PresenceAttestation) -> io::Result<u64> {
    let result = ipc::with_runtime_lock(|| revocation::set_killed_locked(false));
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
    let auth = match presence::require_presence(
        "Releasing the kill switch lets MCP clients drive your browser again.",
        Floor::CliConfirm,
    ) {
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
