//! Proof of user presence for capability-granting acts. Removing capability is friction-free (kill, revoke,
//! uninstall: fail-closed is the safe state); granting or restoring it demands a [`PresenceAttestation`],
//! which only this module mints. [`crate::kill::release`], [`crate::allowlist`] pairing, the policy grant
//! lane, host-key minting and WebAuthn enrollment are the callers.
//!
//! ```text
//! extension   WebAuthn(credential)  -> an assertion from a credential enrolled under THIS browser's label, verified by
//!                                      crate::webauthn against the stored key (request.rs)
//! extension   ConfirmWindow         -> the extension's off-DOM window, labelled "software confirmation"; minted only for
//!                                      a browser with no enrollment, so an enrolled browser is never demoted to it
//! CLI         Tty                   -> the typed phrase on a stdin the TerminalStdin witness proved to be a terminal
//! ```
//!
//! Residual, named: the window and the terminal attest intent on a trusted surface, not hardware. A same-user
//! process can allocate a pty and type the phrase, or edit `trust.json`; the audit trail records which path
//! authorized every act, so a software-attested one is always distinguishable from a WebAuthn one.

pub mod request;

use std::io::{self, BufRead, IsTerminal, Write};

use sha2::{Digest, Sha256};

use crate::ipc::BrowserLabel;
use crate::webauthn::{CredentialId, Refusal, RefusalCode};

/// Which path vouched for the user. Recorded in the audit trail (`auth=<label>`) for every act, granted or
/// refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresencePath {
    /// A WebAuthn assertion from this enrolled credential.
    WebAuthn(CredentialId),
    /// The extension's confirmation window: the software fallback for a browser with no enrolled credential.
    ConfirmWindow,
    /// The typed confirmation on the CLI's controlling terminal.
    Tty,
}

impl PresencePath {
    pub fn wire_name(&self) -> &'static str {
        match self {
            PresencePath::WebAuthn(_) => "webauthn",
            PresencePath::ConfirmWindow => "confirm_window",
            PresencePath::Tty => "tty",
        }
    }

    /// The audit spelling: the wire name, and for WebAuthn the SHA-256 of the credential id. A fingerprint
    /// rather than the id itself because audit details are truncated to a fixed bound (audit.rs) and a
    /// credential id may run to a kilobyte.
    pub fn audit_label(&self) -> String {
        match self {
            PresencePath::WebAuthn(id) => {
                format!("webauthn:{}", hex::encode(Sha256::digest(id.as_bytes())))
            }
            PresencePath::ConfirmWindow | PresencePath::Tty => self.wire_name().to_string(),
        }
    }
}

/// Evidence that presence was attested; the private field makes this module the only producer, so an API
/// that demands one (like `kill::release`) structurally cannot run with presence unchecked. LINEAR on purpose,
/// not `Clone` (so not `Copy` either): one attestation authorizes exactly one capability-granting act, so a
/// tap minted for "pair client X" cannot also release the kill switch with both audit records claiming presence.
///
/// ```compile_fail
/// fn takes_clone<T: Clone>() {}
/// takes_clone::<genkan_core::presence::PresenceAttestation>();
/// ```
#[derive(Debug)]
pub struct PresenceAttestation {
    path: PresencePath,
}

impl PresenceAttestation {
    /// The path that vouched. Reading it does not consume the witness; only the act it is handed to does.
    pub fn path(&self) -> &PresencePath {
        &self.path
    }

    /// The one constructor outside the two minters below, for tests of the acts that consume an attestation.
    #[cfg(test)]
    pub(crate) fn assume_for_tests(path: PresencePath) -> Self {
        PresenceAttestation { path }
    }
}

/// Why presence could not be attested. Every variant means the same thing to the caller (refuse, change
/// nothing) but the distinctions reach the user message, the audit record, and the extension's reason code.
#[derive(Debug, thiserror::Error)]
pub enum PresenceError {
    /// The CLI path needs a terminal on stdin and did not get one.
    #[error("stdin is not a terminal; this action restores or grants capability and requires an interactive confirmation (run it from a terminal)")]
    NotInteractive,
    /// The user did not type the confirmation phrase (mismatch, empty, EOF).
    #[error("the confirmation phrase was not entered; nothing was changed")]
    Declined,
    /// The confirmation could not be read at all.
    #[error("could not read the confirmation: {0}")]
    Io(io::Error),
    /// The assertion failed verification; the refusal names the check.
    #[error("assertion refused: {0}")]
    Refused(Refusal),
    /// The asserting credential matches no enrollment on this machine.
    #[error("the asserting credential is not enrolled on this machine")]
    CredentialNotEnrolled,
    /// The credential is enrolled, under another browser's label.
    #[error("the asserting credential is enrolled under browser '{enrolled_under}', not this one")]
    WrongBrowser { enrolled_under: BrowserLabel },
    /// The browser has an enrolled credential, so the window may not vouch in its place.
    #[error(
        "this browser has an enrolled authenticator; a window confirmation cannot stand in for it"
    )]
    SoftwareConfirmationNotAllowed,
    /// The window's confirmation names a request that is not the outstanding one (a superseded nonce).
    #[error("the confirmation names a request that is not the outstanding one")]
    RequestMismatch,
    /// The enrollment record could not be read or the sign counter could not be persisted.
    #[error("enrollment store: {0}")]
    Store(io::Error),
}

impl PresenceError {
    /// The stable snake_case code a `presence_result` carries.
    pub fn code(&self) -> RefusalCode {
        match self {
            PresenceError::NotInteractive => RefusalCode::NotInteractive,
            PresenceError::Declined => RefusalCode::Declined,
            PresenceError::Io(_) => RefusalCode::IoError,
            PresenceError::Refused(refusal) => refusal.code(),
            PresenceError::CredentialNotEnrolled => RefusalCode::CredentialNotEnrolled,
            PresenceError::WrongBrowser { .. } => RefusalCode::WrongBrowserLabel,
            PresenceError::SoftwareConfirmationNotAllowed => {
                RefusalCode::SoftwareConfirmationNotAllowed
            }
            PresenceError::RequestMismatch => RefusalCode::RequestMismatch,
            PresenceError::Store(_) => RefusalCode::StoreError,
        }
    }
}

/// Proof that stdin was a real terminal when the CLI path was selected: the anti-tap-phishing precondition
/// made structural. The private field keeps [`require`](TerminalStdin::require) the only constructor, and
/// [`tty_confirm`] demands the witness, so `echo release | genkan unkill` is refused before any prompt can
/// run at all. The witness encodes ORDERING (the check ran before anything else), not a permanent fact, which
/// is why [`tty_confirm`] re-samples before reading.
#[derive(Debug)]
pub struct TerminalStdin(());

impl TerminalStdin {
    /// The one constructor: refuse unless stdin IS a terminal.
    pub fn require() -> Result<TerminalStdin, PresenceError> {
        if io::stdin().is_terminal() {
            Ok(TerminalStdin(()))
        } else {
            Err(PresenceError::NotInteractive)
        }
    }
}

/// The exact phrase the CLI path demands. A full word the user must mean, not a `y` a wrapper script might
/// emit by habit. Shared by every capability-granting CLI act (`unkill`, `pair-client`, `pair`, `policy
/// set`): each prints its own reason first, so the word is the deliberate keystroke, not the context.
pub const CLI_CONFIRM_PHRASE: &str = "release";

/// The CLI path: require the phrase on the terminal the witness proved; prompts go to stderr so they reach the
/// user even with stdout redirected. Terminal-ness is re-sampled immediately before the read: fd 0 can be
/// swapped for a pipe in the window between witness and prompt, and a mismatch refuses `NotInteractive`
/// without reading rather than accept a phrase from a non-terminal.
pub fn tty_confirm(
    reason: &str,
    _terminal: TerminalStdin,
) -> Result<PresenceAttestation, PresenceError> {
    let stdin = io::stdin();
    let still_terminal = stdin.is_terminal();
    if still_terminal {
        eprintln!("{reason}");
        eprint!("type '{CLI_CONFIRM_PHRASE}' to confirm: ");
        let _ = io::stderr().flush();
    }
    let mut lock = stdin.lock();
    tty_verdict(still_terminal, || {
        let mut line = String::new();
        let n = lock.read_line(&mut line)?;
        Ok((n > 0).then_some(line))
    })
}

/// The pure fail-closed matrix of the CLI path: no longer a terminal at read time -> refuse without reading;
/// EOF, a read error, or anything but the exact phrase -> refuse.
fn tty_verdict(
    still_terminal: bool,
    read_line: impl FnOnce() -> io::Result<Option<String>>,
) -> Result<PresenceAttestation, PresenceError> {
    if !still_terminal {
        return Err(PresenceError::NotInteractive);
    }
    match read_line() {
        Ok(Some(line)) if line.trim() == CLI_CONFIRM_PHRASE => Ok(PresenceAttestation {
            path: PresencePath::Tty,
        }),
        Ok(_) => Err(PresenceError::Declined),
        Err(e) => Err(PresenceError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The verdict matrix: whitespace around the phrase is forgiven, nothing else is, EOF and a read error
    /// refuse, and a stdin that stopped being a terminal refuses WITHOUT reading (the read closure panicking
    /// is the assertion).
    #[test]
    fn tty_verdict_accepts_exactly_the_phrase_on_a_terminal() {
        let ok = tty_verdict(true, || Ok(Some("release\n".into()))).unwrap();
        assert_eq!(ok.path(), &PresencePath::Tty);
        assert!(tty_verdict(true, || Ok(Some("  release  \n".into()))).is_ok());
        for wrong in ["y\n", "yes\n", "RELEASE\n", "release now\n", "\n", ""] {
            let err = tty_verdict(true, || Ok(Some(wrong.into()))).unwrap_err();
            assert!(matches!(err, PresenceError::Declined), "{wrong:?}");
        }
        assert!(matches!(
            tty_verdict(true, || Ok(None)).unwrap_err(),
            PresenceError::Declined
        ));
        assert!(matches!(
            tty_verdict(true, || Err(io::Error::other("tty gone"))).unwrap_err(),
            PresenceError::Io(_)
        ));
        let err = tty_verdict(false, || panic!("must not read a non-terminal stdin")).unwrap_err();
        assert!(matches!(err, PresenceError::NotInteractive));
        assert_eq!(err.code().to_string(), "not_interactive");
    }
}
