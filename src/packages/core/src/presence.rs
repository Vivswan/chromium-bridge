//! Proof of user presence for capability-RESTORING acts (ADR-0030).
//!
//! The kill switch's release is the one act in this codebase that restores
//! capability instead of reducing it, and the user's directive for it is
//! hardware-backed: releasing requires Touch ID. The hardware plumbing
//! (LocalAuthentication) arrives with Phase 8; this module is the seam it
//! plugs into, plus the interactive floor that holds the line until then.
//!
//! ## The ladder, and why failure never falls down it
//!
//! [`require_presence`] tries the hardware provider first and falls back to
//! the caller's floor ONLY when hardware is genuinely unavailable (no
//! provider built yet, no sensor on this machine). A hardware check that ran
//! and REFUSED never falls back: an attacker who can make Touch ID fail must
//! not thereby downgrade the gate to a softer prompt. Failed or unavailable
//! auth leaves the bridge exactly as killed as it was.
//!
//! ## The floors
//!
//! - [`Floor::CliConfirm`]: an explicit, typed confirmation on the CLI's own
//!   controlling terminal. Stdin must BE a terminal - a piped or redirected
//!   stdin is refused outright, so `echo release | chromium-bridge unkill`
//!   in some background script cannot silently reopen the bridge - and the
//!   user must type the exact phrase.
//! - [`Floor::ExtensionConfirm`]: the extension options page's explicit
//!   confirmation dialog. The native host cannot raise a prompt of its own
//!   (its stdin/stdout are the native-messaging protocol), so pre-Phase-8 it
//!   accepts the surface's confirmation as the floor: the `kill_release`
//!   frame only arrives from the extension Chrome pinned via
//!   `allowed_origins`, and only the extension's own pages can make the
//!   service worker send it (the #32 sender gate).
//!
//! ## Residual, named
//!
//! Both floors attest intent on a trusted surface; neither is hardware. A
//! same-user process can allocate a pty and type the phrase, or (more
//! directly) edit `revocation.json` itself - the conceded same-user boundary.
//! The floors exist to make a silent, accidental, or script-driven unkill
//! impossible, not to beat a hostile local process; Touch ID (Phase 8) is
//! what upgrades this gate to hardware. The audit trail records which rung
//! authorized every release, so a floor-authorized release is always
//! distinguishable from a hardware-authorized one.

use std::fmt;
use std::io::{self, BufRead, IsTerminal, Write};

/// Which rung of the ladder vouched for the user. Recorded in the audit
/// trail (`auth=<wire name>`) for every release, successful or refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresencePath {
    /// Hardware user presence via LocalAuthentication (Phase 8).
    TouchId,
    /// The typed confirmation on the CLI's controlling terminal.
    CliConfirm,
    /// The extension options page's confirmation dialog, attested by the
    /// native-messaging channel (`allowed_origins` + the #32 sender gate).
    ExtensionConfirm,
}

impl PresencePath {
    pub fn wire_name(self) -> &'static str {
        match self {
            PresencePath::TouchId => "touch_id",
            PresencePath::CliConfirm => "cli_confirm",
            PresencePath::ExtensionConfirm => "extension_confirm",
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
                "stdin is not a terminal; releasing the kill switch requires an \
                 interactive confirmation (run it from a terminal, or use the \
                 extension's options page)"
            ),
            PresenceError::Declined => {
                write!(
                    f,
                    "the confirmation phrase was not entered; nothing was released"
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
/// `ExtensionConfirm` succeeds without further checks here, because the
/// evidence lives in the CHANNEL, not in this process: only the native
/// host's control path (a `kill_release` frame from the pinned extension)
/// may select it. Selecting it from any other call site would be claiming a
/// confirmation that never happened; treat adding such a caller as a
/// security change (SECURITY.md).
#[derive(Debug, Clone, Copy)]
pub enum Floor {
    CliConfirm,
    ExtensionConfirm,
}

/// What the hardware provider said. Public because it is the seam's
/// contract: the Phase 8 LocalAuthentication provider returns exactly this.
/// Distinct from [`PresenceError`] so the refused/unavailable distinction -
/// the one that decides whether the floor is reachable - is explicit at the
/// seam.
pub enum HardwareOutcome {
    Verified,
    Refused(String),
    Unavailable,
}

/// The Phase 8 seam: LocalAuthentication (Touch ID) plugs in here. Until
/// that lands there is no hardware provider on any platform, so every call
/// reports `Unavailable` and [`require_presence`] uses the floor.
fn hardware_authenticate(_reason: &str) -> HardwareOutcome {
    HardwareOutcome::Unavailable
}

/// Attest user presence for `reason`, hardware first, `floor` only when
/// hardware is unavailable. See the module docs for the no-downgrade rule.
pub fn require_presence(reason: &str, floor: Floor) -> Result<PresenceAttestation, PresenceError> {
    ladder(hardware_authenticate(reason), floor, |floor| match floor {
        Floor::CliConfirm => cli_confirm(reason),
        Floor::ExtensionConfirm => Ok(PresenceAttestation {
            path: PresencePath::ExtensionConfirm,
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
/// not a `y` a wrapper script might emit by habit.
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
    fn the_extension_floor_attests_its_own_path() {
        // Pre-Phase-8 (hardware unavailable) the extension floor succeeds and
        // names itself, so the audit trail can never conflate it with
        // hardware.
        let att = require_presence("test", Floor::ExtensionConfirm).unwrap();
        assert_eq!(att.path(), PresencePath::ExtensionConfirm);
        assert_eq!(att.path().wire_name(), "extension_confirm");
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
    }
}
