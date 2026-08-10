//! The host-side shared-language store (ADR-0032 decision 7): the
//! `{ value, seq }` state for `uiLanguage`, persisted host-side while paired
//! and pushed to the extension over the `lang_current` control frame.
//!
//! Language is deliberately NOT policy: not signed, not ratcheted, and unable
//! to affect any security decision. A substituted host can forge
//! `lang_current` and flip the UI language - a nuisance with zero capability
//! attached, which is exactly why language gets the free lane and policy does
//! not. The store follows [`crate::revocation`]'s on-disk pattern (a small,
//! capped, `deny_unknown_fields`, atomically-written 0600 file under the
//! runtime lock) rather than the heavier policy store, because none of the
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

/// The on-disk language store schema version. Bumped only on a
/// breaking-shape change; unknown-field parsing is fail-closed
/// (`deny_unknown_fields`) so a newer file is rejected rather than
/// misinterpreted by an older binary.
pub const LANG_STORE_VERSION: u32 = 1;

/// Upper bound on `lang.json` when reading it back. The record is a version,
/// a short enum string, and a counter - a few dozen bytes - so anything
/// larger is not ours and is refused rather than slurped.
const LANG_MAX_BYTES: usize = 4 * 1024;

/// The accepted `uiLanguage` values. This mirrors the browser-owned
/// `uiLanguage` enum in `src/packages/shared/src/settings.ts`
/// (`z.enum(["auto", "en", "zh_CN", "zh_TW"])`): language stays browser-owned
/// (ADR-0032 decision 1), so it is NOT emitted into the Rust core by
/// `moon run gen` the way the policy schema is, and this list is the host's
/// hand-kept copy of that source of truth. A value outside it is refused
/// (decision 7) and the previous value stands.
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

/// The persisted shared-language state (ADR-0032 decision 7). `value` is one
/// of [`UI_LANGUAGES`]; `seq` is a monotonic counter bumped on every accepted
/// change, constrained to the JS-safe range (the same posture as the policy
/// revision) so the Rust parser and the extension's Zod parser read the same
/// number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LangStore {
    /// Schema version; see [`LANG_STORE_VERSION`].
    pub version: u32,
    /// The stored language, one of [`UI_LANGUAGES`].
    pub value: String,
    /// The echo-suppression sequence; bounded to [`JS_SAFE_INT_MAX`] in the
    /// parser itself so both sides read the same number.
    #[serde(deserialize_with = "de_js_safe_u64")]
    pub seq: u64,
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

impl LangStore {
    /// Path of the language store in the 0700 per-user runtime directory.
    pub fn path() -> std::path::PathBuf {
        ipc::runtime_dir().join("lang.json")
    }

    /// Read the store. `Ok(None)` when the file does not exist (no language
    /// stored yet). A present-but-corrupt, oversized, wrong-version, or
    /// out-of-enum file is an error, NOT a silent default: a damaged store
    /// fails closed (the caller skips its push/reply) rather than masking a
    /// tamper with a fabricated value.
    pub fn load() -> io::Result<Option<Self>> {
        let Some(bytes) = ipc::read_capped(&Self::path(), LANG_MAX_BYTES)? else {
            return Ok(None);
        };
        let store: LangStore = serde_json::from_slice(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("lang store: {e}")))?;
        if store.version != LANG_STORE_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "lang store version {} is not supported (this binary understands {})",
                    store.version, LANG_STORE_VERSION
                ),
            ));
        }
        if !is_valid_lang(&store.value) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("lang store carries an out-of-enum value {:?}", store.value),
            ));
        }
        Ok(Some(store))
    }

    /// Write atomically, 0600. The [`ipc::RuntimeLockToken`] proves the caller
    /// holds the runtime lock, so a lock-free rewrite of the language store
    /// does not compile (the `Allowlist::write` / policy-store pattern).
    fn write(&self, _lock: &ipc::RuntimeLockToken) -> io::Result<()> {
        let bytes = serde_json::to_vec_pretty(self)?;
        ipc::write_private_atomic(&Self::path(), &bytes)
    }
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
        version: LANG_STORE_VERSION,
        value: value.to_string(),
        seq,
    };
    next.write(lock)?;
    if let Err(e) = crate::revocation::bump_locked(lock, crate::revocation::Scope::Lang) {
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
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use super::*;

    #[cfg(unix)]
    const RUNTIME_ENV: &str = "XDG_RUNTIME_DIR";
    #[cfg(windows)]
    const RUNTIME_ENV: &str = "LOCALAPPDATA";

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    /// Points `runtime_dir()` at a fresh scratch directory for one test (the
    /// policy store's `RuntimeDirGuard` pattern), so no test reads or writes
    /// the user's real runtime state.
    struct RuntimeDirGuard {
        _serial: MutexGuard<'static, ()>,
        dir: PathBuf,
        prev: Option<std::ffi::OsString>,
    }

    impl RuntimeDirGuard {
        fn new(test: &str) -> Self {
            let serial = env_lock().lock().unwrap_or_else(|e| e.into_inner());
            let dir = std::env::temp_dir().join(format!(
                "chromium-bridge-lang-test-{}-{test}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            let prev = std::env::var_os(RUNTIME_ENV);
            std::env::set_var(RUNTIME_ENV, &dir);
            RuntimeDirGuard {
                _serial: serial,
                dir,
                prev,
            }
        }
    }

    impl Drop for RuntimeDirGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(RUNTIME_ENV, v),
                None => std::env::remove_var(RUNTIME_ENV),
            }
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn lang_epoch() -> u64 {
        crate::revocation::Revocation::current().unwrap().lang_epoch
    }

    #[test]
    fn absent_store_reads_the_default() {
        let _dir = RuntimeDirGuard::new("absent-default");
        assert!(LangStore::load().unwrap().is_none());
        assert_eq!(load_current().unwrap(), ("en".to_string(), 0));
    }

    #[test]
    fn a_changing_set_round_trips_and_bumps_seq_and_epoch() {
        let _dir = RuntimeDirGuard::new("set-round-trip");
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
        let _dir = RuntimeDirGuard::new("noop-set");
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
        let _dir = RuntimeDirGuard::new("noop-default");
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
    fn load_is_fail_closed_on_shape_version_and_out_of_enum() {
        let _dir = RuntimeDirGuard::new("load-fail-closed");
        // Unknown field refused.
        fs::write(
            LangStore::path(),
            br#"{"version":1,"value":"en","seq":0,"surprise":true}"#,
        )
        .unwrap();
        assert!(LangStore::load().is_err());
        // Wrong version refused.
        fs::write(LangStore::path(), br#"{"version":99,"value":"en","seq":0}"#).unwrap();
        assert!(LangStore::load().is_err());
        // Out-of-enum value refused (a tampered store never answers with a
        // fabricated language).
        fs::write(LangStore::path(), br#"{"version":1,"value":"fr","seq":0}"#).unwrap();
        assert!(LangStore::load().is_err());
        // A seq past the JS-safe bound refused.
        fs::write(
            LangStore::path(),
            br#"{"version":1,"value":"en","seq":9007199254740992}"#,
        )
        .unwrap();
        assert!(LangStore::load().is_err());
        // Positive control: the exact shape at the bound loads.
        fs::write(
            LangStore::path(),
            br#"{"version":1,"value":"en","seq":9007199254740991}"#,
        )
        .unwrap();
        let store = LangStore::load().unwrap().unwrap();
        assert_eq!(store.seq, JS_SAFE_INT_MAX);
    }

    #[test]
    fn store_round_trips_through_serde() {
        let store = LangStore {
            version: LANG_STORE_VERSION,
            value: "zh_TW".into(),
            seq: 42,
        };
        let bytes = serde_json::to_vec(&store).unwrap();
        let back: LangStore = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, store);
    }

    #[test]
    fn path_has_expected_filename() {
        assert_eq!(LangStore::path().file_name().unwrap(), "lang.json");
    }
}
