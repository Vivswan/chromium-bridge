//! Proof of user presence for capability-RESTORING acts (ADR-0030/0031). Removing capability is always
//! friction-free (kill, revoke, uninstall: fail-closed is the safe state), but restoring or granting it
//! demands a [`PresenceAttestation`] from this module; [`crate::kill::release`] and [`crate::allowlist`]
//! pairing are the two callers.
//!
//! [`require_presence`] tries hardware first and falls to the caller's floor ONLY when hardware is
//! genuinely unavailable: an attacker who can make the Enclave prompt fail must not thereby downgrade
//! the gate to a softer prompt.
//! ```text
//! macOS, enrollment key present  -> Secure Enclave signing gated on the key's user-presence ACL (Touch ID or the login password)
//! macOS without a key, other OS  -> the caller's interactive floor (`Floor`)
//! hardware RAN and REFUSED       -> error; the floor never runs, capability stays exactly as reduced
//! ```
//!
//! Residual, named: the floors attest intent on a trusted surface, and none of them is hardware. A
//! same-user process can allocate a pty and type the phrase, or edit `revocation.json` directly (the
//! conceded same-user boundary); the audit trail records which rung authorized every act, so a
//! floor-authorized one is always distinguishable from a hardware-authorized one.
//!
//! No test raises a real prompt: under `cfg(test)` the hardware seams return the injected `test_hook` /
//! `policy_test_hook` outcome and the real backend is not compiled; there is NO runtime env var, flag, or
//! config that disables the real path in a shipped binary. Integration tests (`tests/`) link WITHOUT
//! `cfg(test)` and stay promptless by construction, not by this mock.
//! ```text
//! enclave/presence e2e          -> only MALFORMED challenges, refused before the keychain
//! presence-gated CLI commands   -> skipped on an enrolled machine (`tests/protocol/e2e.py`, `enclave_key_present`)
//! `moon run touchid-gates`      -> the ONLY real-hardware exercise, consciously run and tapped by the user
//! ```

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
    /// native-messaging channel (`allowed_origins` + the router's sender gate).
    /// Retained as a stable audit LABEL only (ADR-0032 decision 6 retired the
    /// extension floor that produced it); no host path emits it anymore.
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

/// Evidence that [`require_presence`] ran and succeeded; the private field makes this module the only
/// producer, so an API that demands one (like `kill::release`) structurally cannot run with presence
/// unchecked. LINEAR on purpose, neither `Copy` nor `Clone`: one attestation authorizes exactly one
/// capability-restoring act, so a tap minted for "pair client X" cannot also release the kill switch
/// with both audit records claiming presence.
///
/// Both snippets fail to compile today, which is what the fences assert; an impl coming back makes its
/// snippet compile and that test fail:
///
/// ```compile_fail
/// fn takes_copy<T: Copy>() {}
/// takes_copy::<chromium_bridge_core::presence::PresenceAttestation>();
/// ```
///
/// ```compile_fail
/// fn takes_clone<T: Clone>() {}
/// takes_clone::<chromium_bridge_core::presence::PresenceAttestation>();
/// ```
#[derive(Debug)]
pub struct PresenceAttestation {
    path: PresencePath,
}

impl PresenceAttestation {
    /// The rung that vouched. Reading it does not consume the witness - only
    /// the capability-restoring act it is handed to does.
    pub fn path(&self) -> PresencePath {
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
                 or use the desktop app)"
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

/// Proof that stdin was a real terminal when the CLI floor was selected: the anti-tap-phishing precondition made
/// structural. The private field keeps [`require`](TerminalStdin::require) the only constructor, so a
/// [`Floor::CliConfirm`] cannot exist for a piped or redirected stdin, and `echo release | chromium-bridge unkill`
/// is refused before [`require_presence`], and therefore before any hardware prompt, can run at all.
///
/// ```text
/// fd 0 swapped for a pipe between witness and floor -> the witness encodes ORDERING, not a permanent fact; cli_confirm
///                                                      re-samples terminal-ness right before reading the phrase and
///                                                      refuses on a mismatch
/// ```
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

    /// Test-only bypass so unit tests (whose stdin is never a terminal) can
    /// exercise the CLI floor's read/verdict path. Compiled out of every
    /// shipped binary, exactly like [`test_hook`].
    #[cfg(test)]
    pub(crate) fn assume_for_tests() -> TerminalStdin {
        TerminalStdin(())
    }
}

/// The interactive fallback a call site is entitled to when hardware is unavailable; each surface has
/// exactly one honest option.
/// ```text
/// `CliConfirm`  -> carries the `TerminalStdin` witness, so selecting it IS the interactivity precondition
/// `AppConfirm`  -> succeeds without further checks here: the evidence is the desktop app's own modal
///                  confirmation, shown before it asks, so only the app's presence-gated actions may select it
/// ```
/// Any other `AppConfirm` caller would claim a confirmation that never happened; treat adding one as a
/// security change (SECURITY.md). There is no extension floor: ADR-0032 decision 6 retired its only
/// caller (the extension's `kill_release`), and a zero-caller constructible floor is a latent grant primitive.
#[derive(Debug)]
pub enum Floor {
    CliConfirm(TerminalStdin),
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

/// Outcome of one policy-signing presence act ([`sign_policy_as_presence`],
/// ADR-0032). Same seam discipline as [`HardwareOutcome`]: `Refused` is
/// terminal (the no-downgrade rule - never a fallthrough to a floor), and
/// `Unavailable` means there is no hardware rung here at all, leaving what
/// happens next to the calling surface (the app's interactive floor; the
/// CLI refuses outright, ADR-0032 decision 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySignOutcome {
    /// The presence-gated Enclave signing succeeded: the tap IS the grant
    /// approval, and the signature is the artifact the extension verifies
    /// against its pinned key (`key_id` / `pubkey_b64` are the key's public
    /// info, host-side bookkeeping only).
    Signed {
        sig: [u8; 64],
        key_id: String,
        pubkey_b64: String,
    },
    /// The hardware rung exists and did not sign (the user cancelled,
    /// biometry failed, or no prompt could be raised).
    Refused(String),
    /// No enrollment key on this machine (or not macOS) - genuine absence
    /// only. A key that exists but fails lookup or public-half export is
    /// ambiguity and maps to `Refused` (see the macOS provider's
    /// `sign_policy`), because `Unavailable` is what entitles a floor to
    /// write a persistent unsigned baseline.
    Unavailable,
}

/// Sign `doc_bytes` under the POLICY signing domain as the presence act (ADR-0032): the user-presence-gated Enclave
/// signing over the policy message IS the Touch ID approval, so `policy::set_signed` never takes a pre-made
/// attestation and can never double-prompt. Policy-typed on purpose: it builds the policy-domain message internally
/// from raw document bytes, so it can never sign enrollment- or presence-domain bytes; do not widen it to "sign the
/// caller's message".
///
/// ```text
/// capable Mac  -> RAISES A REAL SYSTEM PROMPT
/// cfg(test)    -> the injected policy_test_hook outcome (default Unavailable); the real backend is not compiled
/// ```
pub fn sign_policy_as_presence(doc_bytes: &[u8]) -> PolicySignOutcome {
    #[cfg(test)]
    {
        policy_test_hook::record_call(doc_bytes);
        policy_test_hook::outcome()
    }
    #[cfg(all(not(test), target_os = "macos"))]
    {
        macos::sign_policy(doc_bytes)
    }
    #[cfg(all(not(test), not(target_os = "macos")))]
    {
        let _ = doc_bytes;
        PolicySignOutcome::Unavailable
    }
}

/// The hardware rung: a Secure Enclave signing operation gated on user presence (Touch ID / login password) on macOS;
/// no provider exists elsewhere, so every call there reports `Unavailable` and [`require_presence`] uses the floor.
/// There is no runtime env var, flag, or config that disables the real path in a shipped binary (a bypass an attacker
/// could set).
///
/// ```text
/// capable Mac  -> RAISES A REAL SYSTEM PROMPT
/// cfg(test)    -> the injected test_hook outcome, never LocalAuthentication or the enrolled key, so no automated test
///                 binary can raise a prompt even through the full require_presence path
/// ```
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

/// The `cfg(test)`-only mock for [`sign_policy_as_presence`]: an injectable
/// [`PolicySignOutcome`] in place of the real Enclave signing, plus a
/// panic-if-called mode for tests that must prove the primitive is never
/// reached (a malformed document must refuse BEFORE any prompt could exist,
/// the validate-before-prompt rule). Compiled out of every non-test build;
/// per-thread state, so parallel tests do not interfere. `pub(crate)` so the
/// policy module's own tests can drive it.
#[cfg(test)]
pub(crate) mod policy_test_hook {
    use std::cell::RefCell;

    use super::PolicySignOutcome;

    pub(crate) enum Mock {
        Return(PolicySignOutcome),
        PanicIfCalled,
    }

    thread_local! {
        // Default Unavailable: a test that does not opt in behaves as a
        // machine with no hardware rung, so no test can accidentally assert
        // a signed grant it did not set up.
        static OUTCOME: RefCell<Mock> =
            const { RefCell::new(Mock::Return(PolicySignOutcome::Unavailable)) };
        // The bytes the last sign_policy_as_presence on this thread was
        // called with, so a test can pin the signed bytes byte-identical to
        // the stored ones.
        static LAST_DOC_BYTES: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
    }

    /// Set what the next `sign_policy_as_presence` on THIS thread does.
    pub(crate) fn set(mock: Mock) {
        OUTCOME.with(|c| *c.borrow_mut() = mock);
    }

    /// Reset to the default (no hardware rung), clearing any recorded call.
    pub(crate) fn reset() {
        set(Mock::Return(PolicySignOutcome::Unavailable));
        LAST_DOC_BYTES.with(|c| *c.borrow_mut() = None);
    }

    /// Record the bytes the primitive was called with; called by
    /// `sign_policy_as_presence` itself before consulting the mock.
    pub(super) fn record_call(doc_bytes: &[u8]) {
        LAST_DOC_BYTES.with(|c| *c.borrow_mut() = Some(doc_bytes.to_vec()));
    }

    /// The bytes the last call on this thread passed to the primitive;
    /// `None` when it was never reached (or after a reset).
    pub(crate) fn last_doc_bytes() -> Option<Vec<u8>> {
        LAST_DOC_BYTES.with(|c| c.borrow().clone())
    }

    pub(crate) fn outcome() -> PolicySignOutcome {
        OUTCOME.with(|c| match &*c.borrow() {
            Mock::Return(outcome) => outcome.clone(),
            Mock::PanicIfCalled => {
                panic!("sign_policy_as_presence must not be reached by this test")
            }
        })
    }

    /// RAII: restore the default on scope exit, same rationale as
    /// [`super::test_hook::ResetOnDrop`].
    pub(crate) struct ResetOnDrop;

    impl Drop for ResetOnDrop {
        fn drop(&mut self) {
            reset();
        }
    }
}

/// Attest user presence for `reason`, hardware first, `floor` only when
/// hardware is unavailable. See the module docs for the no-downgrade rule.
///
/// The CLI floor's precondition (stdin is a terminal) has necessarily
/// already run: [`Floor::CliConfirm`] cannot be constructed without the
/// [`TerminalStdin`] witness, so a script-driven invocation was refused
/// promptless before this function - and its hardware prompt - was
/// reachable (tap phishing, see the module docs).
pub fn require_presence(reason: &str, floor: Floor) -> Result<PresenceAttestation, PresenceError> {
    ladder(hardware_authenticate(reason), floor, |floor| match floor {
        Floor::CliConfirm(terminal) => cli_confirm(reason, terminal),
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

/// The CLI floor: require the phrase on the terminal the witness proved; prompts go to stderr so they reach the user
/// even with stdout redirected. Terminal-ness is re-sampled here, immediately before the read: the witness ordered
/// the FIRST check before the hardware prompt, but fd 0 can be swapped for a pipe in the window between witness and
/// floor, and a mismatch must refuse `NotInteractive` without reading rather than accept a phrase from a non-terminal.
fn cli_confirm(
    reason: &str,
    _terminal: TerminalStdin,
) -> Result<PresenceAttestation, PresenceError> {
    let stdin = io::stdin();
    let still_terminal = stdin.is_terminal();
    // The prompt is written only when the re-check holds; the verdict logic
    // itself is pure and tested (`cli_confirm_verdict`).
    if still_terminal {
        eprintln!("{reason}");
        eprint!("type '{CLI_CONFIRM_PHRASE}' to confirm: ");
        let _ = io::stderr().flush();
    }
    let mut lock = stdin.lock();
    cli_confirm_verdict(still_terminal, || {
        let mut line = String::new();
        let n = lock.read_line(&mut line)?;
        Ok((n > 0).then_some(line))
    })
}

/// The pure fail-closed matrix of the CLI floor: no longer a terminal at
/// read time -> refuse without reading (the fd-swap re-check; the witness
/// already ordered the FIRST check before the hardware prompt); EOF, a read
/// error, or anything but the exact phrase -> refuse. Factored so the matrix
/// is unit-testable without a terminal.
fn cli_confirm_verdict(
    still_terminal: bool,
    read_line: impl FnOnce() -> io::Result<Option<String>>,
) -> Result<PresenceAttestation, PresenceError> {
    if !still_terminal {
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
    fn a_non_terminal_stdin_cannot_even_construct_the_cli_floor() {
        // The anti-tap-phishing precondition, structural form: under a test
        // harness stdin is never a terminal, so the witness - and with it
        // `Floor::CliConfirm` - is unconstructible, and no CLI-floor presence
        // request (or hardware prompt) can exist at all.
        let err = TerminalStdin::require().unwrap_err();
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
    fn a_stale_witness_cannot_reach_the_read_after_an_fd_swap() {
        // The witness orders the terminal check before the hardware prompt,
        // but it cannot freeze a dynamic fact: if fd 0 stops being a
        // terminal in the window between witness construction and the floor,
        // the re-check at read time refuses without consuming any input.
        // The read closure panicking is the assertion that nothing is read
        // from a non-terminal stdin.
        let err = cli_confirm_verdict(false, || panic!("must not read a non-terminal stdin"))
            .unwrap_err();
        assert!(matches!(err, PresenceError::NotInteractive));
    }

    #[test]
    fn a_refused_hardware_check_never_reaches_the_floor() {
        // The no-downgrade rule: an attacker who can make Touch ID FAIL must
        // not thereby demote the gate to the softer interactive floor. The
        // floor closure panics if consulted.
        let err = ladder(
            HardwareOutcome::Refused("biometry mismatch".into()),
            Floor::AppConfirm,
            |_| panic!("a refused hardware check must never fall back to the floor"),
        )
        .unwrap_err();
        assert!(matches!(err, PresenceError::HardwareRefused(_)));
    }

    #[test]
    fn verified_hardware_attests_touch_id_without_the_floor() {
        let att = ladder(
            HardwareOutcome::Verified,
            Floor::CliConfirm(TerminalStdin::assume_for_tests()),
            |_| panic!("verified hardware needs no floor"),
        )
        .unwrap();
        assert_eq!(att.path(), PresencePath::TouchId);
    }

    #[test]
    fn unavailable_hardware_uses_exactly_the_given_floor() {
        let att = ladder(
            HardwareOutcome::Unavailable,
            Floor::CliConfirm(TerminalStdin::assume_for_tests()),
            |floor| {
                assert!(matches!(floor, Floor::CliConfirm(_)));
                Ok(PresenceAttestation {
                    path: PresencePath::CliConfirm,
                })
            },
        )
        .unwrap();
        assert_eq!(att.path(), PresencePath::CliConfirm);
    }

    #[test]
    fn the_app_floor_attests_its_own_path() {
        // With hardware unavailable, the app floor succeeds and names itself,
        // so the audit trail can never conflate it with hardware. Injected
        // through the pure ladder here; the full require_presence path is
        // covered separately, driven through the cfg(test) mock (never real
        // hardware). (The extension floor was retired, ADR-0032 decision 6.)
        let att = ladder(
            HardwareOutcome::Unavailable,
            Floor::AppConfirm,
            |floor| match floor {
                Floor::CliConfirm(_) => panic!("wrong floor selected"),
                Floor::AppConfirm => Ok(PresenceAttestation {
                    path: PresencePath::AppConfirm,
                }),
            },
        )
        .unwrap();
        assert_eq!(att.path(), PresencePath::AppConfirm);
    }

    #[test]
    fn a_non_interactive_cli_invocation_is_refused_before_any_prompt() {
        // The anti-tap-phishing precondition end to end, as a CLI surface
        // performs it: build the witness first, only then the floor and the
        // presence request. Under a test harness stdin is never a terminal,
        // so the chain refuses at the witness - hardware_authenticate is
        // structurally unreachable (there is no Floor to call it with).
        let err = TerminalStdin::require()
            .map(Floor::CliConfirm)
            .and_then(|floor| require_presence("test", floor))
            .unwrap_err();
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
        let att = require_presence("test", Floor::AppConfirm).unwrap();
        assert_eq!(att.path(), PresencePath::TouchId);

        test_hook::set(test_hook::Mock::Refused);
        let err = require_presence("test", Floor::AppConfirm).unwrap_err();
        assert!(matches!(err, PresenceError::HardwareRefused(_)));

        test_hook::set(test_hook::Mock::Unavailable);
        let att = require_presence("test", Floor::AppConfirm).unwrap();
        assert_eq!(att.path(), PresencePath::AppConfirm);
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

    #[test]
    fn sign_policy_as_presence_defaults_to_unavailable() {
        // Without opting in, the policy mock is Unavailable - the same
        // no-hardware default posture as test_hook, so no test can
        // accidentally observe a signed grant it did not inject.
        assert_eq!(
            sign_policy_as_presence(b"doc"),
            PolicySignOutcome::Unavailable
        );
    }

    #[test]
    fn sign_policy_as_presence_returns_the_injected_outcome() {
        let _reset = policy_test_hook::ResetOnDrop;

        policy_test_hook::set(policy_test_hook::Mock::Return(PolicySignOutcome::Signed {
            sig: [7; 64],
            key_id: "kid".into(),
            pubkey_b64: "pk".into(),
        }));
        assert_eq!(
            sign_policy_as_presence(b"doc"),
            PolicySignOutcome::Signed {
                sig: [7; 64],
                key_id: "kid".into(),
                pubkey_b64: "pk".into(),
            }
        );

        policy_test_hook::set(policy_test_hook::Mock::Return(PolicySignOutcome::Refused(
            "injected test refusal".into(),
        )));
        assert_eq!(
            sign_policy_as_presence(b"doc"),
            PolicySignOutcome::Refused("injected test refusal".into())
        );
    }

    #[test]
    #[should_panic(expected = "sign_policy_as_presence must not be reached")]
    fn the_panic_if_called_mock_fires_when_the_primitive_is_reached() {
        // The lever for validate-before-prompt tests: install PanicIfCalled,
        // drive the code under test, and any path that reaches the signing
        // primitive fails loudly.
        let _reset = policy_test_hook::ResetOnDrop;
        policy_test_hook::set(policy_test_hook::Mock::PanicIfCalled);
        let _ = sign_policy_as_presence(b"doc");
    }
}
