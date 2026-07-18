//! Proof of user presence for capability-RESTORING acts (ADR-0030/0031).
//!
//! The presence symmetry rule: removing capability is always friction-free
//! (kill, revoke, uninstall - fail-closed is the safe state), but RESTORING
//! or GRANTING capability requires proof of a human. Two acts in this
//! codebase do that - releasing the kill switch ([`crate::kill::release`])
//! and pairing a trusted client ([`crate::allowlist`]) - and both demand a
//! [`PresenceAttestation`] from this module. On macOS the proof is hardware:
//! a Secure Enclave signing operation gated on the enrollment key's
//! user-presence ACL, which forces Touch ID (or the login password through
//! the same system sheet) and cannot succeed without a live user action.
//! Elsewhere, and on a Mac with no enrollment key to gate on, the caller's
//! interactive floor holds the line.
//!
//! ## The ladder, and why failure never falls down it
//!
//! [`require_presence`] tries the hardware provider first and falls back to
//! the caller's floor ONLY when hardware is genuinely unavailable (non-macOS,
//! or no usable Enclave key on this machine). A hardware check that RAN and
//! REFUSED never falls back: an attacker who can make the Enclave prompt fail
//! must not thereby downgrade the gate to a softer prompt. Failed or
//! unavailable auth leaves capability exactly as reduced as it was.
//!
//! ## Preconditions run BEFORE the hardware prompt
//!
//! The CLI floor's surface requirement (stdin is a real terminal) is checked
//! before any hardware prompt is raised, not merely inside the floor. A
//! background script driving `chromium-bridge unkill` must not be able to
//! put an unexplained Touch ID sheet in front of the user - a tap-phishing
//! primitive - so a non-interactive invocation is refused outright, promptless.
//!
//! ## The floors
//!
//! - [`Floor::CliConfirm`]: an explicit, typed confirmation on the CLI's own
//!   controlling terminal. Stdin must BE a terminal - a piped or redirected
//!   stdin is refused outright, so `echo release | chromium-bridge unkill`
//!   in some background script cannot silently reopen the bridge - and the
//!   user must type the exact phrase.
//! - [`Floor::ExtensionConfirm`]: the extension options page's explicit
//!   confirmation dialog. The native host cannot raise a text prompt of its
//!   own (its stdin/stdout are the native-messaging protocol), so where
//!   hardware is unavailable it accepts the surface's confirmation as the
//!   floor: the `kill_release` frame only arrives from the extension Chrome
//!   pinned via `allowed_origins`, and only the extension's own pages can
//!   make the service worker send it (the #32 sender gate).
//! - [`Floor::AppConfirm`]: the desktop app's explicit confirmation dialog,
//!   same shape as the extension floor - the evidence lives in the calling
//!   surface, which shows its own modal confirmation before asking. Only the
//!   app's presence-gated actions may select it (see the variant docs).
//!
//! ## Residual, named
//!
//! The floors attest intent on a trusted surface; none of them is hardware.
//! A same-user process can allocate a pty and type the phrase, or (more
//! directly) edit `revocation.json` itself - the conceded same-user boundary.
//! The floors exist to make a silent, accidental, or script-driven
//! capability restoration impossible, not to beat a hostile local process;
//! Touch ID is what upgrades the gate to hardware where the machine has it.
//! The audit trail records which rung authorized every act, so a
//! floor-authorized one is always distinguishable from a hardware-authorized
//! one.
//!
//! ## Testing rule (no real prompts, ever)
//!
//! In a dev or prod build, [`require_presence`] with a non-CLI floor raises a
//! REAL system prompt on a Touch-ID Mac. Automated UNIT tests must never do
//! that, and cannot: under `cfg(test)`, [`hardware_authenticate`] returns the
//! injected [`test_hook`] outcome (default `Unavailable`) instead of calling
//! LocalAuthentication or signing with the enrolled Enclave key, and the real
//! backend module is not even compiled into a `cfg(test)` build. Set the
//! outcome with `test_hook::set` to exercise the verified/refused/unavailable
//! branches. The mock is `cfg(test)`-only, compiled out of every shipped
//! binary; there is NO runtime env var, flag, or config that disables the
//! real hardware path (a bypass an attacker could set is forbidden by
//! AGENTS.md).
//!
//! `cfg(test)` covers this crate's own unit tests. Integration tests (in
//! `tests/`) and the release binary link the crate WITHOUT `cfg(test)`, so
//! they use the real path - the suite keeps them promptless by construction,
//! not by this mock: every enclave/presence e2e supplies only MALFORMED
//! challenges (refused before the keychain), and the presence-gated CLI
//! commands are skipped on an enrolled machine (see `tests/protocol/e2e.py`,
//! `enclave_key_present`). The real hardware path is exercised only by the
//! explicit user runbook (`just touchid-gates`), consciously run and
//! tapped.

// The real hardware backend is compiled only into non-test macOS builds:
// under cfg(test) `hardware_authenticate` returns the injected mock instead,
// so the module (and its enrolled-key signing) would be dead code in a test
// build. Gating it out is what makes "no test can reach the real key"
// structural rather than merely conventional.
#[cfg(all(target_os = "macos", not(test)))]
mod macos;

use std::fmt;
use std::io::{self, BufRead, IsTerminal, Write};

/// Which rung of the ladder vouched for the user. Recorded in the audit
/// trail (`auth=<wire name>`) for every release, successful or refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresencePath {
    /// Hardware user presence via a Secure Enclave signing operation gated on
    /// the enrollment key's user-presence ACL (Touch ID or the login
    /// password through the same system sheet).
    TouchId,
    /// The typed confirmation on the CLI's controlling terminal.
    CliConfirm,
    /// The extension options page's confirmation dialog, attested by the
    /// native-messaging channel (`allowed_origins` + the #32 sender gate).
    ExtensionConfirm,
    /// The desktop app's confirmation dialog, attested by the app surface
    /// that raised it.
    AppConfirm,
}

impl PresencePath {
    pub fn wire_name(self) -> &'static str {
        match self {
            PresencePath::TouchId => "touch_id",
            PresencePath::CliConfirm => "cli_confirm",
            PresencePath::ExtensionConfirm => "extension_confirm",
            PresencePath::AppConfirm => "app_confirm",
        }
    }
}

/// Evidence that [`require_presence`] ran and succeeded. The private field
/// means the only way to obtain one is through this module: an API that
/// demands an attestation (like `kill::release`) structurally cannot be
/// called with presence unchecked.
#[derive(Debug, Clone, Copy)]
pub struct PresenceAttestation {
    path: PresencePath,
}

impl PresenceAttestation {
    pub fn path(self) -> PresencePath {
        self.path
    }
}

/// Why presence could not be attested. Every variant means the same thing to
/// the caller - refuse, stay killed - but the distinctions matter to the user
/// message and the audit record.
#[derive(Debug)]
pub enum PresenceError {
    /// The hardware provider ran and did not verify the user. Deliberately
    /// terminal: a failed hardware check never falls back to a softer floor.
    HardwareRefused(String),
    /// The CLI floor needs a terminal on stdin and did not get one.
    NotInteractive,
    /// The user did not type the confirmation phrase (mismatch, empty, EOF).
    Declined,
    /// The confirmation could not be read at all.
    Io(io::Error),
}

impl fmt::Display for PresenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PresenceError::HardwareRefused(e) => {
                write!(f, "hardware user-presence check refused: {e}")
            }
            PresenceError::NotInteractive => write!(
                f,
                "stdin is not a terminal; this action restores or grants capability \
                 and requires an interactive confirmation (run it from a terminal, \
                 or use the app or the extension's options page)"
            ),
            PresenceError::Declined => {
                write!(
                    f,
                    "the confirmation phrase was not entered; nothing was changed"
                )
            }
            PresenceError::Io(e) => write!(f, "could not read the confirmation: {e}"),
        }
    }
}

/// The interactive fallback a call site is entitled to when hardware is
/// unavailable. Chosen by the surface, because each surface has exactly one
/// honest option (see the module docs).
///
/// `ExtensionConfirm` and `AppConfirm` succeed without further checks here,
/// because the evidence lives in the CALLING SURFACE, not in this process:
/// only the native host's control path (a `kill_release` frame from the
/// pinned extension) may select the extension floor, and only the desktop
/// app's own presence-gated actions - which show their own modal
/// confirmation first - may select the app floor. Selecting either from any
/// other call site would be claiming a confirmation that never happened;
/// treat adding such a caller as a security change (SECURITY.md).
#[derive(Debug, Clone, Copy)]
pub enum Floor {
    CliConfirm,
    ExtensionConfirm,
    AppConfirm,
}

/// What the hardware provider said. Public because it is the seam's
/// contract: the Secure Enclave signing provider ([`macos`]) returns exactly
/// this. Distinct from [`PresenceError`] so the refused/unavailable
/// distinction - the one that decides whether the floor is reachable - is
/// explicit at the seam.
pub enum HardwareOutcome {
    Verified,
    Refused(String),
    Unavailable,
}

/// The hardware rung: a Secure Enclave signing operation gated on user
/// presence (Touch ID / login password) on macOS; no provider exists on any
/// other platform, so every call there reports `Unavailable` and
/// [`require_presence`] uses the floor.
///
/// On a capable Mac this RAISES A REAL SYSTEM PROMPT - see the module docs'
/// testing rule. That is precisely why, under `cfg(test)`, this function
/// NEVER reaches the real LocalAuthentication / Secure Enclave key: it returns
/// the injected [`test_hook`] outcome instead. So no automated test binary can
/// raise a real prompt or sign with the user's enrolled key, even one that
/// drives the full [`require_presence`] path. `cfg(test)` is compiled OUT of
/// dev and prod builds; there is no runtime env var, flag, or config that
/// disables the real hardware path in a shipped binary (that would be a
/// bypass an attacker could set - forbidden by AGENTS.md).
fn hardware_authenticate(reason: &str) -> HardwareOutcome {
    #[cfg(test)]
    {
        let _ = reason;
        test_hook::outcome()
    }
    #[cfg(all(not(test), target_os = "macos"))]
    {
        macos::authenticate(reason)
    }
    #[cfg(all(not(test), not(target_os = "macos")))]
    {
        let _ = reason;
        HardwareOutcome::Unavailable
    }
}

/// The `cfg(test)`-only presence mock: canned [`HardwareOutcome`]s injected in
/// place of real hardware, so the full [`require_presence`] path is testable
/// without ever raising a system prompt or touching the enrolled Enclave key.
/// Compiled out of every non-test build. Per-thread state, so parallel tests
/// do not interfere.
#[cfg(test)]
mod test_hook {
    use std::cell::Cell;

    use super::HardwareOutcome;

    #[derive(Clone, Copy)]
    pub(super) enum Mock {
        Verified,
        Refused,
        Unavailable,
    }

    thread_local! {
        // Default Unavailable: a test that does not opt in behaves as a
        // machine with no hardware rung (falls to the floor), so no test can
        // accidentally assert a hardware "grant" it did not set up.
        static OUTCOME: Cell<Mock> = const { Cell::new(Mock::Unavailable) };
    }

    /// Set the outcome the next `hardware_authenticate` on THIS thread returns.
    pub(super) fn set(mock: Mock) {
        OUTCOME.with(|c| c.set(mock));
    }

    /// Reset to the default (no hardware rung). Call at the end of a test that
    /// changed it, so a reused thread does not leak state to the next test.
    pub(super) fn reset() {
        OUTCOME.with(|c| c.set(Mock::Unavailable));
    }

    pub(super) fn outcome() -> HardwareOutcome {
        match OUTCOME.with(Cell::get) {
            Mock::Verified => HardwareOutcome::Verified,
            Mock::Refused => HardwareOutcome::Refused("injected test refusal".into()),
            Mock::Unavailable => HardwareOutcome::Unavailable,
        }
    }

    /// RAII: restore the default outcome on scope exit, so a test that sets
    /// the mock and then fails mid-way cannot leak state to the next test on a
    /// reused thread. (State leakage could never reach hardware - the real
    /// module is uncompiled under cfg(test) - but a stale `Verified` could
    /// skew a later assertion.)
    pub(super) struct ResetOnDrop;

    impl Drop for ResetOnDrop {
        fn drop(&mut self) {
            reset();
        }
    }
}

/// Attest user presence for `reason`, hardware first, `floor` only when
/// hardware is unavailable. See the module docs for the no-downgrade rule.
///
/// The CLI floor's precondition (stdin is a terminal) runs BEFORE the
/// hardware prompt: a script-driven invocation is refused promptless, so a
/// background process cannot use this gate to put an unexplained Touch ID
/// sheet in front of the user (tap phishing).
pub fn require_presence(reason: &str, floor: Floor) -> Result<PresenceAttestation, PresenceError> {
    if matches!(floor, Floor::CliConfirm) && !io::stdin().is_terminal() {
        return Err(PresenceError::NotInteractive);
    }
    ladder(hardware_authenticate(reason), floor, |floor| match floor {
        Floor::CliConfirm => cli_confirm(reason),
        Floor::ExtensionConfirm => Ok(PresenceAttestation {
            path: PresencePath::ExtensionConfirm,
        }),
        Floor::AppConfirm => Ok(PresenceAttestation {
            path: PresencePath::AppConfirm,
        }),
    })
}

/// The pure rung-selection of [`require_presence`], with the hardware
/// outcome and the floor prompt injected so the no-downgrade rule is
/// unit-testable: `Refused` must return an error WITHOUT the floor ever
/// running.
fn ladder(
    hardware: HardwareOutcome,
    floor: Floor,
    confirm_floor: impl FnOnce(Floor) -> Result<PresenceAttestation, PresenceError>,
) -> Result<PresenceAttestation, PresenceError> {
    match hardware {
        HardwareOutcome::Verified => Ok(PresenceAttestation {
            path: PresencePath::TouchId,
        }),
        HardwareOutcome::Refused(e) => Err(PresenceError::HardwareRefused(e)),
        HardwareOutcome::Unavailable => confirm_floor(floor),
    }
}

/// The exact phrase the CLI floor demands. A full word the user must mean,
/// not a `y` a wrapper script might emit by habit. Shared by every
/// capability-restoring CLI act (`unkill`, `pair-client`): each prints its
/// own reason first, so the word is the deliberate keystroke, not the
/// context.
pub const CLI_CONFIRM_PHRASE: &str = "release";

/// The CLI floor: refuse a non-terminal stdin, then require the phrase.
/// Prompts go to stderr so they reach the user even with stdout redirected.
fn cli_confirm(reason: &str) -> Result<PresenceAttestation, PresenceError> {
    let stdin = io::stdin();
    let interactive = stdin.is_terminal();
    // The prompt is written only on the interactive path; the verdict logic
    // itself is pure and tested (`cli_confirm_verdict`).
    if interactive {
        eprintln!("{reason}");
        eprint!("type '{CLI_CONFIRM_PHRASE}' to confirm: ");
        let _ = io::stderr().flush();
    }
    let mut lock = stdin.lock();
    cli_confirm_verdict(interactive, || {
        let mut line = String::new();
        let n = lock.read_line(&mut line)?;
        Ok((n > 0).then_some(line))
    })
}

/// The pure fail-closed matrix of the CLI floor: not a terminal -> refuse
/// without reading; EOF, a read error, or anything but the exact phrase ->
/// refuse. Factored so the matrix is unit-testable without a terminal.
fn cli_confirm_verdict(
    interactive: bool,
    read_line: impl FnOnce() -> io::Result<Option<String>>,
) -> Result<PresenceAttestation, PresenceError> {
    if !interactive {
        return Err(PresenceError::NotInteractive);
    }
    match read_line() {
        Ok(Some(line)) if line.trim() == CLI_CONFIRM_PHRASE => Ok(PresenceAttestation {
            path: PresencePath::CliConfirm,
        }),
        Ok(_) => Err(PresenceError::Declined),
        Err(e) => Err(PresenceError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_non_terminal_stdin_refuses_without_reading() {
        // The read closure must never run: a piped stdin is refused before
        // any input could be consumed (or waited on).
        let err = cli_confirm_verdict(false, || panic!("must not read a non-terminal stdin"))
            .unwrap_err();
        assert!(matches!(err, PresenceError::NotInteractive));
    }

    #[test]
    fn only_the_exact_phrase_confirms() {
        let ok = cli_confirm_verdict(true, || Ok(Some("release\n".into()))).unwrap();
        assert_eq!(ok.path(), PresencePath::CliConfirm);
        // Whitespace is forgiven; anything else is not.
        assert!(cli_confirm_verdict(true, || Ok(Some("  release  \n".into()))).is_ok());
        for wrong in ["y\n", "yes\n", "RELEASE\n", "release now\n", "\n", ""] {
            let err = cli_confirm_verdict(true, || Ok(Some(wrong.into()))).unwrap_err();
            assert!(matches!(err, PresenceError::Declined), "{wrong:?}");
        }
    }

    #[test]
    fn eof_and_read_errors_refuse() {
        assert!(matches!(
            cli_confirm_verdict(true, || Ok(None)).unwrap_err(),
            PresenceError::Declined
        ));
        assert!(matches!(
            cli_confirm_verdict(true, || Err(io::Error::other("tty gone"))).unwrap_err(),
            PresenceError::Io(_)
        ));
    }

    #[test]
    fn a_refused_hardware_check_never_reaches_the_floor() {
        // The no-downgrade rule: an attacker who can make Touch ID FAIL must
        // not thereby demote the gate to the softer interactive floor. The
        // floor closure panics if consulted.
        let err = ladder(
            HardwareOutcome::Refused("biometry mismatch".into()),
            Floor::ExtensionConfirm,
            |_| panic!("a refused hardware check must never fall back to the floor"),
        )
        .unwrap_err();
        assert!(matches!(err, PresenceError::HardwareRefused(_)));
    }

    #[test]
    fn verified_hardware_attests_touch_id_without_the_floor() {
        let att = ladder(HardwareOutcome::Verified, Floor::CliConfirm, |_| {
            panic!("verified hardware needs no floor")
        })
        .unwrap();
        assert_eq!(att.path(), PresencePath::TouchId);
    }

    #[test]
    fn unavailable_hardware_uses_exactly_the_given_floor() {
        let att = ladder(HardwareOutcome::Unavailable, Floor::CliConfirm, |floor| {
            assert!(matches!(floor, Floor::CliConfirm));
            Ok(PresenceAttestation {
                path: PresencePath::CliConfirm,
            })
        })
        .unwrap();
        assert_eq!(att.path(), PresencePath::CliConfirm);
    }

    #[test]
    fn the_extension_and_app_floors_attest_their_own_paths() {
        // With hardware unavailable, the surface floors succeed and name
        // themselves, so the audit trail can never conflate them with
        // hardware. Injected through the pure ladder here; the full
        // require_presence path is covered separately, driven through the
        // cfg(test) mock (never real hardware).
        for (floor, path) in [
            (Floor::ExtensionConfirm, PresencePath::ExtensionConfirm),
            (Floor::AppConfirm, PresencePath::AppConfirm),
        ] {
            let att = ladder(HardwareOutcome::Unavailable, floor, |floor| match floor {
                Floor::CliConfirm => panic!("wrong floor selected"),
                Floor::ExtensionConfirm => Ok(PresenceAttestation {
                    path: PresencePath::ExtensionConfirm,
                }),
                Floor::AppConfirm => Ok(PresenceAttestation {
                    path: PresencePath::AppConfirm,
                }),
            })
            .unwrap();
            assert_eq!(att.path(), path);
        }
    }

    #[test]
    fn a_non_interactive_cli_invocation_is_refused_before_any_prompt() {
        // The anti-tap-phishing precondition: under a test harness stdin is
        // never a terminal, so the CLI floor refuses HERE, before
        // hardware_authenticate could run at all.
        let err = require_presence("test", Floor::CliConfirm).unwrap_err();
        assert!(matches!(err, PresenceError::NotInteractive));
    }

    #[test]
    fn require_presence_uses_the_injected_mock_never_real_hardware() {
        // The full require_presence path is driven end to end through the
        // cfg(test) mock (test_hook), proving no test ever reaches real
        // LocalAuthentication or the enrolled Enclave key: a verified mock
        // attests touch_id, a refused mock never falls back to the floor, and
        // an unavailable mock uses the floor. The RAII guard restores the
        // default even if an assertion below panics, so no state leaks to a
        // reused thread.
        let _reset = test_hook::ResetOnDrop;

        test_hook::set(test_hook::Mock::Verified);
        let att = require_presence("test", Floor::ExtensionConfirm).unwrap();
        assert_eq!(att.path(), PresencePath::TouchId);

        test_hook::set(test_hook::Mock::Refused);
        let err = require_presence("test", Floor::ExtensionConfirm).unwrap_err();
        assert!(matches!(err, PresenceError::HardwareRefused(_)));

        test_hook::set(test_hook::Mock::Unavailable);
        let att = require_presence("test", Floor::ExtensionConfirm).unwrap();
        assert_eq!(att.path(), PresencePath::ExtensionConfirm);
    }

    #[test]
    fn the_default_test_hook_reaches_no_hardware() {
        // Without opting in, the mock is Unavailable, so require_presence with
        // a surface floor succeeds via that floor - never a hardware call.
        // This is the default posture every other test in the crate runs
        // under.
        let att = require_presence("test", Floor::AppConfirm).unwrap();
        assert_eq!(att.path(), PresencePath::AppConfirm);
    }

    #[test]
    fn wire_names_are_stable() {
        // These land in audit records; renaming one is a schema change.
        assert_eq!(PresencePath::TouchId.wire_name(), "touch_id");
        assert_eq!(PresencePath::CliConfirm.wire_name(), "cli_confirm");
        assert_eq!(
            PresencePath::ExtensionConfirm.wire_name(),
            "extension_confirm"
        );
        assert_eq!(PresencePath::AppConfirm.wire_name(), "app_confirm");
    }
}
