//! The app-side sync surfaces for ADR-0032 decision 7 (shared language) and
//! D-P4-1 (change notification): the `lang_current` / `lang_set` commands
//! over the core's language store, and ONE background watch thread that
//! polls the revocation record's `policy_epoch` and `lang_epoch` (~1s,
//! read-only) and emits a Tauri event when either moves.
//!
//! The events are CHANGE NOTICES, never authority (the same posture as the
//! native host's watch): the payload is only the new epoch number, and every
//! command stays pull-based - a listener re-reads `policy_status` /
//! `lang_current` when poked. Language is deliberately not policy (no
//! signature, no ratchet, zero capability), so its store I/O runs in-process
//! like every other plain-file read.
//!
//! Echo-loop rule (decision 7): `lang_set` may be invoked ONLY on an
//! explicit user gesture in the app's own language picker - never from the
//! path that APPLIES an incoming `lang-epoch-changed` event, or the
//! app and the extension would ping-pong sets forever. The core's seq
//! discipline (a no-op set bumps nothing) is the backstop; the webview's
//! gesture-only call site is the contract (see `ui/src/lib/lang-sync.ts`).

use std::time::Duration;

use serde::Serialize;
use tauri::Emitter;

use chromium_bridge_core::lang;
use chromium_bridge_core::revocation::Revocation;

/// Emitted when the revocation record's `policy_epoch` moved: a policy
/// write landed somewhere (this app, the CLI, a rollback) - or the host
/// recorded a legacy-import receipt, which bumps the same epoch so an open
/// app surfaces the arrival. Payload: the new epoch. Listeners re-read
/// `policy_status` (and the import surfaces re-read `pending_import` - a
/// receipt creates it, revision 1 consumes it).
pub const POLICY_EPOCH_EVENT: &str = "policy-epoch-changed";

/// Emitted when `lang_epoch` moved: the shared language changed (the
/// extension's picker, or this app's own set - harmless, the re-read is a
/// no-op). Payload: the new epoch. Listeners re-read `lang_current`.
pub const LANG_EPOCH_EVENT: &str = "lang-epoch-changed";

/// The poll cadence. Matches the native host's watch order of magnitude:
/// cheap (one small file read) and fast enough for a settings screen.
const POLL_INTERVAL: Duration = Duration::from_millis(1000);

/// The shared-language state the webview renders and the picker round-trips:
/// `seq == 0` means "never explicitly set anywhere" (the host store's
/// default), which the applying side treats as no signal.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(rename_all = "camelCase")]
pub struct LangState {
    /// One of the shared `uiLanguage` values (`auto`, `en`, `zh_CN`, `zh_TW`).
    pub value: String,
    /// The echo-suppression sequence; apply a value only when it is strictly
    /// greater than the last applied.
    pub seq: u64,
}

/// The current shared language (pull lane). Fail closed: an unreadable
/// store is an error the webview shows, never a guessed value.
pub fn lang_current() -> Result<LangState, String> {
    let (value, seq) = lang::load_current()
        .map_err(|e| format!("the language store is unreadable ({e}); failing closed"))?;
    Ok(LangState { value, seq })
}

/// Record a language choice (USER GESTURE ONLY - see the module docs). An
/// out-of-enum value is refused at this boundary and the stored value
/// stands. Returns the resulting state; a no-op set returns the unchanged
/// seq, so the caller can keep its last-applied cursor exact.
pub fn lang_set(value: &str) -> Result<LangState, String> {
    if !lang::is_valid_lang(value) {
        return Err(format!(
            "unsupported language {value:?}; expected one of: {}",
            lang::UI_LANGUAGES.join(", ")
        ));
    }
    let (value, seq) = lang::set(value).map_err(|e| e.to_string())?;
    Ok(LangState { value, seq })
}

/// The last epochs the watch reported. Starts at the fresh-install values
/// (0, 0), so a machine with prior epochs gets one event per scope on the
/// first tick - a harmless pull-based re-read that closes any gap between
/// the webview's initial reads and the watch starting.
struct SeenEpochs {
    policy: u64,
    lang: u64,
}

/// Diff one revocation read against the last-seen epochs (pure, so the
/// watch's decision is unit-testable without a thread): the events to emit,
/// updating the cursor. Inequality, not order - a rolled-back or wiped
/// record still notifies, the enforcement points' own comparison rule.
fn epoch_events(seen: &mut SeenEpochs, rev: &Revocation) -> Vec<(&'static str, u64)> {
    let mut events = Vec::new();
    if rev.policy_epoch != seen.policy {
        seen.policy = rev.policy_epoch;
        events.push((POLICY_EPOCH_EVENT, rev.policy_epoch));
    }
    if rev.lang_epoch != seen.lang {
        seen.lang = rev.lang_epoch;
        events.push((LANG_EPOCH_EVENT, rev.lang_epoch));
    }
    events
}

/// Start the one epoch watch thread (D-P4-1): both scopes ride a single
/// poll, since the import screen and the policy editor want `policy_epoch`
/// and the language sync wants `lang_epoch` on the same cadence. Read-only
/// forever; an unreadable revocation record skips the tick (the record is
/// written atomically, so a transient read failure heals on the next one)
/// rather than fabricating a change or dying.
pub fn spawn_epoch_watch(app: tauri::AppHandle) {
    std::thread::Builder::new()
        .name("epoch-watch".into())
        .spawn(move || {
            let mut seen = SeenEpochs { policy: 0, lang: 0 };
            loop {
                if let Ok(rev) = Revocation::current() {
                    for (event, epoch) in epoch_events(&mut seen, &rev) {
                        // A failed emit only loses one notice; the next
                        // change (or pull) catches the listener up.
                        let _ = app.emit(event, epoch);
                    }
                }
                std::thread::sleep(POLL_INTERVAL);
            }
        })
        // Spawn failure leaves the app usable, just without live-change
        // events (every surface still pulls); nothing to do but say so.
        .map_err(|e| eprintln!("chromium-bridge-desktop: the epoch watch did not start: {e}"))
        .ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rev(policy_epoch: u64, lang_epoch: u64) -> Revocation {
        Revocation {
            policy_epoch,
            lang_epoch,
            ..Revocation::default()
        }
    }

    #[test]
    fn epoch_events_reports_each_scope_change_once() {
        let mut seen = SeenEpochs { policy: 0, lang: 0 };
        // Nothing moved: no events.
        assert!(epoch_events(&mut seen, &rev(0, 0)).is_empty());
        // Policy moved: one policy event, the cursor advances.
        assert_eq!(
            epoch_events(&mut seen, &rev(3, 0)),
            vec![(POLICY_EPOCH_EVENT, 3)]
        );
        // Unchanged again: silence (no re-emit per tick).
        assert!(epoch_events(&mut seen, &rev(3, 0)).is_empty());
        // Both moved in one tick: both events, one poll.
        assert_eq!(
            epoch_events(&mut seen, &rev(4, 7)),
            vec![(POLICY_EPOCH_EVENT, 4), (LANG_EPOCH_EVENT, 7)]
        );
    }

    #[test]
    fn epoch_events_notifies_on_inequality_not_order() {
        // A wiped or rolled-back record still pokes the listeners: the
        // re-read is pull-based, so notifying is always safe and staying
        // silent is not.
        let mut seen = SeenEpochs { policy: 9, lang: 9 };
        assert_eq!(
            epoch_events(&mut seen, &rev(0, 9)),
            vec![(POLICY_EPOCH_EVENT, 0)]
        );
    }

    #[test]
    fn lang_set_refuses_an_out_of_enum_value_at_the_boundary() {
        // The refusal happens before any store I/O, so this test never
        // touches the real runtime dir.
        let err = lang_set("fr").expect_err("fr is not a shared language");
        assert!(err.contains("unsupported language"), "got: {err}");
        assert!(err.contains("zh_CN"), "the message names the enum: {err}");
    }
}
