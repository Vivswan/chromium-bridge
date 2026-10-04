//! The host-side shared-language store (ADR-0032 decision 7): the
//! `{ value, seq }` state for `uiLanguage`, persisted host-side while paired
//! and pushed to the extension over the `lang_current` control frame.
//!
//! Language is deliberately NOT policy: not signed, not ratcheted, and unable
//! to affect any security decision. A substituted host can forge
//! `lang_current` and flip the UI language - a nuisance with zero capability
//! attached, which is exactly why language gets the free lane and policy does
//! not. The store is a plain [`RuntimeRecord`], not a policy store: none of the
//! policy machinery (signatures, overlays, history) applies here.
//!
//! Loop prevention is by sequence, not by guessing (decision 7): a receiver
//! applies a push only when its `seq` is strictly greater than the last it
//! applied, and a `lang_set` that does not change the stored value does not
//! bump `seq` - so a set-apply-set cycle has nothing to ride on. Values
//! outside the generated enum are refused and the previous value stands.

use std::io;

use serde::{Deserialize, Serialize};

use crate::ipc;
use crate::policy::JS_SAFE_INT_MAX;
use crate::runtime_record::{Record, Rung, RuntimeRecord};

/// The accepted `uiLanguage` values. This mirrors the browser-owned
/// canonical list in `src/packages/shared/src/settings.ts` (`UI_LANGUAGES`):
/// language stays browser-owned (ADR-0032 decision 1), so it is NOT emitted
/// into the Rust core by `moon run gen` the way the policy schema is, and
/// this list is the host's hand-kept copy of that source of truth - pinned
/// against it by the shared suite's `tests/lang-parity.test.ts`, which reads
/// this file. A value outside it is refused (decision 7) and the previous
/// value stands.
pub const UI_LANGUAGES: &[&str] = &["auto", "en", "zh_CN", "zh_TW"];

/// The default language when the host has no stored value yet. Matches
/// `settings.ts`'s `uiLanguage` default of `"en"`, so a host that never had a
/// language set answers `lang_current` with the same value the extension
/// would default to.
const DEFAULT_LANG: &str = "en";

/// Whether `value` is one of the accepted [`UI_LANGUAGES`].
pub fn is_valid_lang(value: &str) -> bool {
    UI_LANGUAGES.contains(&value)
}

/// The persisted shared-language state (`lang.json`). `value` is one of [`UI_LANGUAGES`]; `seq` is a
/// monotonic counter bumped on every accepted change, constrained to the JS-safe range (the same
/// posture as the policy revision) so the Rust parser and the extension's Zod parser read the same
/// number. Both bounds sit in the parsers themselves, so a damaged store fails the load (the caller
/// skips its push/reply) rather than answering with a fabricated value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LangStore {
    #[serde(deserialize_with = "de_ui_language")]
    pub value: String,
    #[serde(deserialize_with = "de_js_safe_u64")]
    pub seq: u64,
}

impl Record for LangStore {
    const FILE: &'static str = "lang.json";
    const MAX_BYTES: usize = 4 * 1024;
    const MIGRATIONS: &'static [Rung] = crate::migrations::lang::LADDER;
}

fn de_ui_language<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let value = String::deserialize(d)?;
    if !is_valid_lang(&value) {
        return Err(serde::de::Error::custom(format!(
            "out-of-enum uiLanguage {value:?}"
        )));
    }
    Ok(value)
}

/// Mirror of `crate::policy`'s bounded-u64 deserializer: a `seq` above the
/// JS-safe integer bound is refused at the parse boundary, so a tampered
/// store can never carry a value the extension's frame parser would reject.
fn de_js_safe_u64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    let value = u64::deserialize(d)?;
    if value > JS_SAFE_INT_MAX {
        return Err(serde::de::Error::custom(
            "value exceeds the JS-safe integer bound (2^53 - 1)",
        ));
    }
    Ok(value)
}

/// The current shared language and its sequence, mapping the absent store to
/// the default (`"en"`, seq 0). Errors still propagate, so a corrupt store
/// fails closed at the caller rather than answering with a guessed value.
pub fn load_current() -> io::Result<(String, u64)> {
    match LangStore::load()? {
        Some(store) => Ok((store.value, store.seq)),
        None => Ok((DEFAULT_LANG.to_string(), 0)),
    }
}

/// Apply a language change (ADR-0032 decision 7) and return the resulting
/// `(value, seq)`. The caller must have validated `value` against
/// [`is_valid_lang`] first (an out-of-enum value is refused at the frame
/// boundary, where the previous value stands). Under ONE runtime-lock hold:
/// read the current value; if `value` is unchanged, return it with the seq
/// untouched (NO seq bump, NO epoch bump, so a set-apply-set cycle cannot
/// echo); otherwise bump the seq (refused at the JS-safe bound rather than
/// wrapped), write the store, and bump the language epoch so the native
/// host's watch pushes `lang_current` on its next tick.
pub fn set(value: &str) -> io::Result<(String, u64)> {
    debug_assert!(is_valid_lang(value), "set() requires an in-enum value");
    ipc::with_runtime_lock(|lock| set_locked(lock, value))
}

fn set_locked(lock: &ipc::RuntimeLockToken, value: &str) -> io::Result<(String, u64)> {
    let (current_value, current_seq) = match LangStore::load()? {
        Some(store) => (store.value, store.seq),
        None => (DEFAULT_LANG.to_string(), 0),
    };
    if current_value == value {
        // A no-op set does not bump seq and leaves the store (and the epoch)
        // untouched, so nothing propagates - the echo-suppression base case.
        return Ok((current_value, current_seq));
    }
    let seq = current_seq
        .checked_add(1)
        .filter(|s| *s <= JS_SAFE_INT_MAX)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "language sequence counter would exceed the JS-safe integer bound (2^53 - 1)",
            )
        })?;
    let next = LangStore {
        value: value.to_string(),
        seq,
    };
    next.write(lock)?;
    if let Err(e) = crate::trust::Trust::mutate_locked(lock, crate::trust::Scope::Lang, |_| {}) {
        log_warn!(
            "lang",
            "language written but the language epoch bump failed ({e}); a connected \
             extension notices the change only at its next connect"
        );
    }
    Ok((value.to_string(), seq))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_support::scratch_runtime_dir;

    fn lang_epoch() -> u64 {
        crate::trust::TrustState::current().unwrap().lang_epoch()
    }

    #[test]
    fn absent_store_reads_the_default() {
        let _dir = scratch_runtime_dir("lang-absent-default");
        assert!(LangStore::load().unwrap().is_none());
        assert_eq!(load_current().unwrap(), ("en".to_string(), 0));
    }

    #[test]
    fn a_changing_set_round_trips_and_bumps_seq_and_epoch() {
        let _dir = scratch_runtime_dir("lang-set-round-trip");
        let before = lang_epoch();
        let (value, seq) = set("zh_CN").unwrap();
        assert_eq!(value, "zh_CN");
        assert_eq!(seq, 1);
        assert_eq!(load_current().unwrap(), ("zh_CN".to_string(), 1));
        assert!(lang_epoch() > before, "a changing set bumps the lang epoch");

        // A second, different value bumps again.
        let (value, seq) = set("zh_TW").unwrap();
        assert_eq!(value, "zh_TW");
        assert_eq!(seq, 2);
    }

    #[test]
    fn a_noop_set_does_not_bump_seq_or_epoch() {
        let _dir = scratch_runtime_dir("lang-noop-set");
        set("zh_CN").unwrap();
        let epoch_after_change = lang_epoch();
        // Re-setting the same value is a no-op: seq stands, epoch stands, so a
        // set-apply-set cycle has nothing to ride on (decision 7).
        let (value, seq) = set("zh_CN").unwrap();
        assert_eq!(value, "zh_CN");
        assert_eq!(seq, 1);
        assert_eq!(lang_epoch(), epoch_after_change);
    }

    #[test]
    fn setting_the_default_value_on_a_fresh_store_is_a_noop() {
        let _dir = scratch_runtime_dir("lang-noop-default");
        let before = lang_epoch();
        // The host's implicit value is the default "en"; setting "en" changes
        // nothing, so seq stays 0 and nothing propagates.
        let (value, seq) = set("en").unwrap();
        assert_eq!(value, "en");
        assert_eq!(seq, 0);
        assert!(LangStore::load().unwrap().is_none());
        assert_eq!(lang_epoch(), before);
    }

    #[test]
    fn out_of_enum_values_are_rejected() {
        for bad in ["fr", "EN", "zh", "", "en_US", "auto "] {
            assert!(!is_valid_lang(bad), "{bad:?} must be refused");
        }
        for ok in UI_LANGUAGES {
            assert!(is_valid_lang(ok));
        }
    }

    #[test]
    fn a_stored_value_outside_the_enum_or_the_js_safe_bound_fails_the_load() {
        // The two bounds the extension's Zod parser enforces on `lang_current`; a store carrying a value
        // past either would make the host push a frame the extension refuses.
        let decode = |value: &str, seq: u64| {
            LangStore::decode(
                &serde_json::to_vec(&serde_json::json!({
                    "version": LangStore::VERSION, "value": value, "seq": seq
                }))
                .unwrap(),
            )
        };
        assert!(decode("fr", 0).is_err(), "out-of-enum value");
        assert!(
            decode("en", JS_SAFE_INT_MAX + 1).is_err(),
            "seq past the bound"
        );
        // Positive control: the exact shape at the bound loads.
        assert_eq!(decode("en", JS_SAFE_INT_MAX).unwrap().seq, JS_SAFE_INT_MAX);
    }
}
