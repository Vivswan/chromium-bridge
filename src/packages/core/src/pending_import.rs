//! The host-side pending-import store (ADR-0032 decision 8): the snapshotted
//! legacy settings bag the extension sends once (`legacy_settings { bag }`)
//! when a policy-capable host has identified itself and has no policy store.
//! The bag is RECORDED here as a pending import and NEVER applied - the app's
//! first-run import screen reads it, shows the imported values against the
//! defaults, and ends in one Touch ID tap that signs revision 1 (decision 8),
//! at which point the pending import is consumed.
//!
//! The store is a proper state sum, [`StoreState`]:
//!
//! - `Absent` -> `Pending` via [`record_if_absent`] (the one legitimate
//!   `legacy_settings` receipt);
//! - `Absent` or `Pending` -> `Consumed` via [`consume_locked`] (the first
//!   signed baseline);
//! - `Consumed` is terminal: no transition leaves it.
//!
//! First-bag-wins (D-P4-4): [`record_if_absent`] writes only when the file is
//! absent in EVERY sense - a later `legacy_settings` receipt is logged and
//! DROPPED whether the store holds a pending bag, the consumed tombstone, or
//! an unreadable file (not proof of absence; left untouched, fail closed) -
//! so a later-compromised extension cannot replace or re-plant the user's
//! real legacy bag.
//!
//! Consuming WRITES the `Consumed` tombstone rather than deleting the file:
//! deletion would return the store to `Absent`, and since key disposal keeps
//! this file while clearing the signed baseline (D-P4-5), a compromised
//! extension could then plant a forged bag for the NEXT first-run import.
//! The durable tombstone closes the import window for the lifetime of the
//! file, disposal or not.
//!
//! The store follows [`crate::lang`]'s lighter on-disk pattern (a versioned,
//! capped, `deny_unknown_fields`, atomically-written 0600 file under the
//! runtime lock) rather than the heavier policy store: none of the policy
//! machinery (signatures, overlays, history) applies to a receipt the host
//! never trusts for enforcement. The bag itself is capped at
//! [`LEGACY_BAG_MAX_BYTES`]; an oversize receipt is logged and dropped, never
//! truncated. Disposal (revoke / `pair --reset` / `enclave_revoke`) does NOT
//! clear it (D-P4-5): a pending bag is user preference data, not a key
//! artifact (the policy-history precedent), and the consumed tombstone is
//! exactly what must outlive disposal (above).

use std::io;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ipc;

/// The on-disk pending-import store schema version. Bumped only on a
/// breaking-shape change; unknown-field parsing is fail-closed
/// (`deny_unknown_fields`) so a newer file is rejected rather than
/// misinterpreted by an older binary. `2` is the state-tagged sum (the
/// untagged version-1 shape never shipped, but a dev-build leftover must
/// fail as a version/shape mismatch, never be misread).
pub const PENDING_IMPORT_VERSION: u32 = 2;

/// Upper bound on the stored legacy bag (D-P4-4): the bag is the snapshot of
/// the extension's browser-local settings, kilobytes at most, so anything
/// larger is not a genuine receipt and is dropped rather than stored. Enforced
/// on write (an oversize receipt is dropped, never truncated) AND re-checked
/// on read, so a same-user process cannot plant an oversize bag that the store
/// would later slurp.
pub const LEGACY_BAG_MAX_BYTES: usize = 64 * 1024;

/// Upper bound on `pending-import.json` when reading it back: the bag cap plus
/// generous headroom for the state/version wrapper (the file is written
/// COMPACT - see [`encode`] - so the caps stay commensurable). A file over
/// this is refused without being slurped; the bag inside it is held to the
/// tighter [`LEGACY_BAG_MAX_BYTES`] separately.
pub const PENDING_IMPORT_MAX_BYTES: usize = 128 * 1024;

/// The persisted record (ADR-0032 decision 8): the written arm of the store's
/// state sum, internally tagged on `state` so each arm carries exactly its own
/// fields - a tombstone can never smuggle a bag, and a pending record can
/// never omit one. The bag is data the host records but never trusts for
/// enforcement - the app validates and the user confirms it before any of it
/// becomes signed policy - so it stays a free-form [`Value`] rather than a
/// typed shape that would drift from the extension's evolving legacy schema.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase", deny_unknown_fields)]
pub enum PendingImportRecord {
    /// A recorded receipt awaiting the app's first-run import.
    Pending {
        /// Schema version; see [`PENDING_IMPORT_VERSION`].
        version: u32,
        /// The snapshotted legacy settings bag, opaque JSON (never applied).
        bag: Value,
    },
    /// The durable consumed tombstone: the first signed baseline landed, the
    /// import window is closed for good, and no bag is retained.
    Consumed {
        /// Schema version; see [`PENDING_IMPORT_VERSION`].
        version: u32,
    },
}

/// The store's full state: the two written [`PendingImportRecord`] arms plus
/// the no-file state. An unreadable file is deliberately NOT a state here -
/// it is the `Err` arm of [`load`], so no caller can match it as if it were a
/// readable answer (fail closed).
#[derive(Debug, Clone, PartialEq)]
pub enum StoreState {
    /// No pending-import file exists.
    Absent,
    /// A pending receipt is recorded and readable.
    Pending {
        /// The recorded legacy settings bag.
        bag: Value,
    },
    /// The consumed tombstone: the import happened; the window is closed.
    Consumed,
}

/// Path of the pending-import store in the 0700 per-user runtime directory.
pub fn path() -> std::path::PathBuf {
    ipc::runtime_dir().join("pending-import.json")
}

/// Parse and validate one candidate on-disk record: the file-size cap, the
/// state-tagged shape (`deny_unknown_fields`), the version pin, and the bag
/// cap, in that order, all fail-closed. Split out of [`load`] so the
/// `pending_import` fuzz target can drive the whole validation chain with
/// arbitrary bytes (no I/O in the hot path).
pub fn parse_record(bytes: &[u8]) -> io::Result<PendingImportRecord> {
    if bytes.len() > PENDING_IMPORT_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "pending import is {} bytes, over the {PENDING_IMPORT_MAX_BYTES}-byte cap",
                bytes.len()
            ),
        ));
    }
    let record: PendingImportRecord = serde_json::from_slice(bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("pending import: {e}")))?;
    let version = match &record {
        PendingImportRecord::Pending { version, .. } => *version,
        PendingImportRecord::Consumed { version } => *version,
    };
    if version != PENDING_IMPORT_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "pending import version {version} is not supported (this binary understands {PENDING_IMPORT_VERSION})"
            ),
        ));
    }
    if let PendingImportRecord::Pending { bag, .. } = &record {
        if bag_over_cap(bag)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("pending import bag exceeds the {LEGACY_BAG_MAX_BYTES}-byte cap"),
            ));
        }
    }
    Ok(record)
}

/// Read the store's state. A present-but-corrupt, oversized, wrong-version,
/// or over-cap-bag file is an error, NOT a silent default: a damaged receipt
/// fails closed (writers refuse, the report says unreadable) rather than
/// fabricating a state the file does not prove.
pub fn load() -> io::Result<StoreState> {
    let Some(bytes) = ipc::read_capped(&path(), PENDING_IMPORT_MAX_BYTES)? else {
        return Ok(StoreState::Absent);
    };
    Ok(match parse_record(&bytes)? {
        PendingImportRecord::Pending { bag, .. } => StoreState::Pending { bag },
        PendingImportRecord::Consumed { .. } => StoreState::Consumed,
    })
}

/// Serialize a record for the store file: COMPACT (`to_vec`), the same
/// encoding both caps measure. A pretty-printed near-cap bag would inflate
/// past the file cap and turn the modeled Oversize drop into a write error,
/// silently losing a legitimate migration; the file is machine-read, so
/// nothing wants the whitespace. Refuses to encode what [`load`] could not
/// read back.
fn encode(record: &PendingImportRecord) -> io::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(record)?;
    if bytes.len() > PENDING_IMPORT_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "pending import would serialize to {} bytes, over the {PENDING_IMPORT_MAX_BYTES}-byte read cap",
                bytes.len()
            ),
        ));
    }
    Ok(bytes)
}

/// Write the `Pending` record CREATE-NEW: a same-directory temp file (0600,
/// created exclusively) hard-linked to the final name, which fails on ANY
/// existing entry instead of replacing it. `Absent -> Pending` is the only
/// transition allowed to create the file, so even a write racing an
/// out-of-band change can never replace a recorded bag or the consumed
/// tombstone with a new `Pending` record. No new claim against a hostile
/// same-user process (it can write the path directly; the documented
/// residual stands) - this only removes the replace capability from OUR
/// writer. The [`ipc::RuntimeLockToken`] proves the caller holds the runtime
/// lock, so a lock-free write does not compile (the `Allowlist::write` /
/// policy-store pattern).
fn write_pending_new(
    record: &PendingImportRecord,
    _lock: &ipc::RuntimeLockToken,
) -> io::Result<()> {
    use std::io::Write;
    let bytes = encode(record)?;
    let path = path();
    let mut tmp = path.clone();
    tmp.set_extension("new.tmp");
    // Like ipc::write_private_atomic: never reuse a pre-planted temp file
    // (a looser mode must not carry over); a re-plant race fails closed on
    // the exclusive create.
    let _ = std::fs::remove_file(&tmp);
    // Write into the temp, cleaning it up on ANY failure (a create, write,
    // or flush error) so a partial 0600 .new.tmp carrying bag bytes never
    // lingers in the private dir. A closure keeps the single cleanup path.
    let write_tmp = || -> io::Result<()> {
        #[cfg(unix)]
        let mut f = crate::fsguard::create_private_excl(&tmp)?;
        #[cfg(windows)]
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(&bytes)?;
        f.flush()
    };
    if let Err(e) = write_tmp() {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    // hard_link is atomic and refuses an existing destination - the
    // no-replace analogue of write_private_atomic's rename-over.
    let linked = std::fs::hard_link(&tmp, &path);
    let _ = std::fs::remove_file(&tmp);
    linked
}

/// Write the `Consumed` tombstone: atomic rename-over (it legitimately
/// supersedes a `Pending` record), then fsync the file and, on Unix, its
/// parent directory. Durability is the tombstone's entire purpose - a crash
/// right after a reported-successful consume must not roll the store back
/// and reopen the import window - so only THIS write pays the fsync cost:
/// losing a `Pending` record to a crash loses only a receipt (first-bag-wins
/// then refuses a re-send, which fails closed), never a security boundary.
fn write_consumed_durable(_lock: &ipc::RuntimeLockToken) -> io::Result<()> {
    let bytes = encode(&PendingImportRecord::Consumed {
        version: PENDING_IMPORT_VERSION,
    })?;
    let path = path();
    ipc::write_private_atomic(&path, &bytes)?;
    // Reopen with WRITE access to sync: on Windows sync_all -> FlushFileBuffers
    // requires a writable handle, so a read-only File::open handle fails with
    // access denied (os error 5). The owner can always open its own 0600 file
    // for write on Unix, so this is portable.
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)?
        .sync_all()?;
    // Persist the rename itself. std cannot open a directory handle on
    // Windows; the file sync above is the best std offers there.
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// Whether the bag's compact serialization exceeds [`LEGACY_BAG_MAX_BYTES`].
fn bag_over_cap(bag: &Value) -> io::Result<bool> {
    Ok(serde_json::to_vec(bag)?.len() > LEGACY_BAG_MAX_BYTES)
}

/// What a `legacy_settings` receipt turned into.
#[derive(Debug, PartialEq, Eq)]
pub enum RecordOutcome {
    /// The bag was recorded (the store was absent).
    Recorded,
    /// First-bag-wins (D-P4-4): a pending import already exists, so this
    /// later receipt is dropped - the stored bag stands.
    AlreadyPresent,
    /// The consumed tombstone exists: the one import this host will ever run
    /// already happened, so the receipt is dropped - the window stays closed
    /// even after key disposal (which keeps this file, D-P4-5).
    AlreadyConsumed,
    /// The bag exceeded [`LEGACY_BAG_MAX_BYTES`] and was dropped whole, never
    /// truncated. `bytes` is its measured compact size.
    Oversize { bytes: usize },
}

/// Record `bag` as the pending import, first-bag-wins (ADR-0032 decision 8,
/// D-P4-4): written only when the store is absent. An oversize bag is dropped
/// before the lock is taken (never truncated, never stored). A present file -
/// pending, consumed, or unreadable - is left untouched: a later (possibly
/// compromised) extension must not overwrite the user's real legacy bag or
/// reopen a consumed import, and an unreadable file is not proof of absence,
/// so it fails closed by propagating the read error rather than clobbering it.
pub fn record_if_absent(bag: Value) -> io::Result<RecordOutcome> {
    let bytes = serde_json::to_vec(&bag)?;
    if bytes.len() > LEGACY_BAG_MAX_BYTES {
        return Ok(RecordOutcome::Oversize { bytes: bytes.len() });
    }
    ipc::with_runtime_lock(|lock| record_if_absent_locked(lock, bag))
}

fn record_if_absent_locked(lock: &ipc::RuntimeLockToken, bag: Value) -> io::Result<RecordOutcome> {
    match load()? {
        StoreState::Pending { .. } => Ok(RecordOutcome::AlreadyPresent),
        StoreState::Consumed => Ok(RecordOutcome::AlreadyConsumed),
        StoreState::Absent => {
            let record = PendingImportRecord::Pending {
                version: PENDING_IMPORT_VERSION,
                bag,
            };
            write_pending_new(&record, lock)?;
            Ok(RecordOutcome::Recorded)
        }
    }
}

/// Consume the pending import inside the caller's runtime-lock hold: the seam
/// the first signed baseline (revision 1) fires, BEFORE that baseline commits
/// (the policy store refuses the whole signed write if this fails). Writes
/// the durable [`PendingImportRecord::Consumed`] tombstone (versioned, 0600,
/// atomic, fsynced - see [`write_consumed_durable`]) instead of deleting the
/// file: deletion would let a compromised extension re-plant a forged bag
/// after key disposal clears the baseline (see the module doc). The tombstone
/// is written from `Absent` too - the first baseline closes the import window
/// for good, receipt or no receipt. Returns whether a pending bag was
/// consumed; idempotent on an already-consumed store (returns `Ok(false)`).
/// An unreadable store is an error, never overwritten: the damaged receipt is
/// evidence, and writers stay refused until someone looks (fail closed).
///
/// Durability retry (P4G-1): the tombstone is (re)written and fsynced on
/// EVERY call, including the already-`Consumed` arm. A prior call may have
/// landed the rename but died on the following `sync_all` - a VISIBLE but
/// UNSYNCED tombstone - and then refused the signed write, so the user
/// re-taps; short-circuiting on `Consumed` without re-fsyncing would let
/// revision 1 land over a tombstone a crash could still roll back, reopening
/// the window the tombstone exists to close. The rename-over of an identical
/// tombstone is harmless and idempotent, so paying the sync again is the
/// simple, correct fix; only the return value distinguishes the arms.
pub fn consume_locked(lock: &ipc::RuntimeLockToken) -> io::Result<bool> {
    let had_pending = match load()? {
        StoreState::Consumed => false,
        StoreState::Pending { .. } => true,
        StoreState::Absent => false,
    };
    // Always re-run the durable write, even when already Consumed: it may
    // be visible-but-unsynced from a call that died mid-fsync (see above).
    write_consumed_durable(lock)?;
    Ok(had_pending)
}

/// Consume the pending import, taking the runtime lock (the standalone seam
/// for a surface that is not already inside a critical section). Returns
/// whether a pending bag was consumed.
pub fn consume() -> io::Result<bool> {
    ipc::with_runtime_lock(consume_locked)
}

// ---- The app read surface (ADR-0032 decision 8) -----------------------------

/// Schema version of [`PendingImportReport`]. A reader must refuse a newer
/// value before reading any other field (fail closed).
pub const PENDING_IMPORT_REPORT_VERSION: u32 = 1;

/// The typed, versioned pending-import status for the desktop app's first-run
/// import screen (ADR-0032 decision 8), gathered fail-closed from the store -
/// the same read discipline as [`crate::policy::gather_policy_status`], and
/// the exact object `chromium-bridge policy pending-import --json` prints
/// (the [`crate::policy::PolicyStatusReport`] pattern: one Rust definition,
/// ts_rs-exported, emitted by the host and parsed back by the app). A
/// tagged sum like the on-disk record, so an impossible combination (a
/// `consumed` answer smuggling a bag, an `error` with no detail) cannot even
/// deserialize: `none` is the ordinary no-receipt state (healthy), `present`
/// is the only arm that carries the recorded bag, `consumed` is the
/// post-import tombstone (structurally bagless), `error` is a
/// present-but-unreadable receipt (fail closed).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(tag = "state", rename_all = "lowercase", deny_unknown_fields)]
pub enum PendingImportReport {
    /// No pending import recorded.
    None {
        /// Schema version; see [`PENDING_IMPORT_REPORT_VERSION`].
        v: u32,
    },
    /// A pending import is recorded and readable.
    Present {
        /// Schema version; see [`PENDING_IMPORT_REPORT_VERSION`].
        v: u32,
        /// The recorded legacy settings bag. Untrusted free-form JSON
        /// (`unknown` on the TS side): a suggestion the user reviews, never
        /// applied as policy.
        #[cfg_attr(feature = "ts-export", ts(type = "unknown"))]
        bag: Value,
    },
    /// The consumed tombstone: the import already happened; the window is
    /// closed and no bag is retained.
    Consumed {
        /// Schema version; see [`PENDING_IMPORT_REPORT_VERSION`].
        v: u32,
    },
    /// A pending import file exists but is unreadable (corrupt, oversized,
    /// wrong version, or an over-cap bag): fail closed.
    Error {
        /// Schema version; see [`PENDING_IMPORT_REPORT_VERSION`].
        v: u32,
        /// Human detail of the read failure.
        detail: String,
    },
}

/// The current pending-import status, read fail-closed from the store.
/// Infallible: an unreadable receipt becomes the `error` state, never a panic
/// or a silent default. Two read surfaces consume exactly this state:
/// `chromium-bridge policy pending-import [--json]` (the subprocess the
/// desktop app shells out to) and the app's first-run import screen behind
/// it. READ-ONLY by construction - it calls [`load`], never a writer.
pub fn gather_pending_import() -> PendingImportReport {
    const V: u32 = PENDING_IMPORT_REPORT_VERSION;
    match load() {
        Ok(StoreState::Absent) => PendingImportReport::None { v: V },
        Ok(StoreState::Pending { bag }) => PendingImportReport::Present { v: V, bag },
        Ok(StoreState::Consumed) => PendingImportReport::Consumed { v: V },
        Err(e) => PendingImportReport::Error {
            v: V,
            detail: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use serde_json::json;

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
    /// policy/lang store pattern), so no test reads or writes the user's real
    /// runtime state.
    struct RuntimeDirGuard {
        _serial: MutexGuard<'static, ()>,
        dir: PathBuf,
        prev: Option<std::ffi::OsString>,
    }

    impl RuntimeDirGuard {
        fn new(test: &str) -> Self {
            let serial = env_lock().lock().unwrap_or_else(|e| e.into_inner());
            let dir = std::env::temp_dir().join(format!(
                "chromium-bridge-pending-import-test-{}-{test}",
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

    #[test]
    fn absent_store_reads_as_absent() {
        let _dir = RuntimeDirGuard::new("absent-none");
        assert_eq!(load().unwrap(), StoreState::Absent);
        assert_eq!(
            gather_pending_import(),
            PendingImportReport::None {
                v: PENDING_IMPORT_REPORT_VERSION
            }
        );
    }

    #[test]
    fn record_round_trips_the_exact_bag() {
        let _dir = RuntimeDirGuard::new("round-trip");
        let bag = json!({ "fileUploadEnabled": true, "disabledTools": ["page_eval"] });
        assert_eq!(
            record_if_absent(bag.clone()).unwrap(),
            RecordOutcome::Recorded
        );
        assert_eq!(load().unwrap(), StoreState::Pending { bag: bag.clone() });
        assert_eq!(
            gather_pending_import(),
            PendingImportReport::Present {
                v: PENDING_IMPORT_REPORT_VERSION,
                bag
            }
        );
    }

    #[test]
    fn a_bag_near_the_compact_cap_records_and_reads_back() {
        // P4F-1: the store writes COMPACT, the same encoding both caps
        // measure - a legitimate near-cap bag must round-trip, not blow past
        // the file cap on a pretty-print and be lost to a write error.
        let _dir = RuntimeDirGuard::new("near-cap");
        let bag = json!({ "blob": "x".repeat(LEGACY_BAG_MAX_BYTES - 32) });
        assert!(serde_json::to_vec(&bag).unwrap().len() <= LEGACY_BAG_MAX_BYTES);
        assert_eq!(
            record_if_absent(bag.clone()).unwrap(),
            RecordOutcome::Recorded
        );
        assert_eq!(load().unwrap(), StoreState::Pending { bag });
    }

    #[test]
    fn first_bag_wins_a_later_receipt_is_dropped() {
        let _dir = RuntimeDirGuard::new("first-bag-wins");
        let first = json!({ "pageEvalEnabled": true });
        let second = json!({ "pageEvalEnabled": false, "attacker": "controlled" });
        assert_eq!(
            record_if_absent(first.clone()).unwrap(),
            RecordOutcome::Recorded
        );
        // A later (possibly compromised) receipt is dropped; the first survives.
        assert_eq!(
            record_if_absent(second).unwrap(),
            RecordOutcome::AlreadyPresent
        );
        assert_eq!(load().unwrap(), StoreState::Pending { bag: first });
    }

    #[test]
    fn an_oversize_bag_is_dropped_never_stored() {
        let _dir = RuntimeDirGuard::new("oversize");
        let huge = "x".repeat(LEGACY_BAG_MAX_BYTES + 1);
        let bag = json!({ "blob": huge });
        match record_if_absent(bag).unwrap() {
            RecordOutcome::Oversize { bytes } => assert!(bytes > LEGACY_BAG_MAX_BYTES),
            other => panic!("expected Oversize, got {other:?}"),
        }
        // Nothing was written: the store stays absent, never a truncated bag.
        assert_eq!(load().unwrap(), StoreState::Absent);
    }

    #[test]
    fn load_is_fail_closed_on_shape_version_and_oversize_bag() {
        let _dir = RuntimeDirGuard::new("load-fail-closed");
        // Unknown field refused, on both record arms.
        fs::write(
            path(),
            br#"{"state":"pending","version":2,"bag":{},"surprise":true}"#,
        )
        .unwrap();
        assert!(load().is_err());
        fs::write(path(), br#"{"state":"consumed","version":2,"bag":{}}"#).unwrap();
        assert!(load().is_err());
        // A state outside the sum refused.
        fs::write(path(), br#"{"state":"replayed","version":2,"bag":{}}"#).unwrap();
        assert!(load().is_err());
        // The pre-tombstone (untagged, version-1) shape refused: no silent
        // misread of a dev-build leftover.
        fs::write(path(), br#"{"version":1,"bag":{}}"#).unwrap();
        assert!(load().is_err());
        // Wrong version refused, on both record arms - including a tagged
        // version-1 file (P4F-3: the shape change rode a version bump).
        fs::write(path(), br#"{"state":"pending","version":1,"bag":{}}"#).unwrap();
        assert!(load().is_err());
        fs::write(path(), br#"{"state":"pending","version":99,"bag":{}}"#).unwrap();
        assert!(load().is_err());
        fs::write(path(), br#"{"state":"consumed","version":99}"#).unwrap();
        assert!(load().is_err());
        // A planted over-cap bag (under the file cap, over the bag cap) refused.
        let huge = "y".repeat(LEGACY_BAG_MAX_BYTES + 1);
        let planted = serde_json::to_vec(
            &json!({ "state": "pending", "version": 2, "bag": { "blob": huge } }),
        )
        .unwrap();
        fs::write(path(), &planted).unwrap();
        assert!(load().is_err());
        // gather surfaces the failure as the error state, never a default.
        assert!(matches!(
            gather_pending_import(),
            PendingImportReport::Error { .. }
        ));
    }

    #[test]
    fn a_corrupt_existing_file_refuses_both_writers() {
        let _dir = RuntimeDirGuard::new("corrupt-existing");
        fs::write(path(), b"{ not json").unwrap();
        // First-bag-wins fails closed on an unreadable existing file: it
        // propagates the error rather than overwriting a receipt it could not
        // read (which might be the user's real bag).
        assert!(record_if_absent(json!({ "x": 1 })).is_err());
        // Consume refuses too: the damaged receipt is evidence, never
        // silently replaced by a tombstone.
        assert!(consume().is_err());
        assert!(matches!(
            gather_pending_import(),
            PendingImportReport::Error { .. }
        ));
    }

    #[test]
    fn the_pending_writer_never_replaces_an_existing_file() {
        // P4F-8: the Absent -> Pending transition creates the file
        // exclusively (temp + hard_link, no rename-over), so even if the
        // absence check were raced, OUR writer cannot replace a tombstone
        // (or an existing bag) with a new Pending record. Drive the writer
        // directly, past record_if_absent's own state check.
        let _dir = RuntimeDirGuard::new("create-new");
        fs::write(path(), br#"{"state":"consumed","version":2}"#).unwrap();
        let record = PendingImportRecord::Pending {
            version: PENDING_IMPORT_VERSION,
            bag: json!({ "forged": true }),
        };
        let denied = ipc::with_runtime_lock(|lock| write_pending_new(&record, lock));
        assert!(denied.is_err(), "create-new must refuse an existing file");
        assert_eq!(
            load().unwrap(),
            StoreState::Consumed,
            "the tombstone stands"
        );
        // The temp file does not linger.
        assert!(!path().with_extension("new.tmp").exists());
    }

    #[test]
    fn consume_writes_the_tombstone_and_is_idempotent() {
        let _dir = RuntimeDirGuard::new("consume");
        record_if_absent(json!({ "a": 1 })).unwrap();
        assert!(consume().unwrap(), "a recorded import existed");
        assert_eq!(load().unwrap(), StoreState::Consumed);
        // The tombstone is on disk (not just an in-memory answer)...
        assert_eq!(
            parse_record(&fs::read(path()).unwrap()).unwrap(),
            PendingImportRecord::Consumed {
                version: PENDING_IMPORT_VERSION
            }
        );
        // ...and consuming again is Ok(false), not an error.
        assert!(!consume().unwrap());
        assert_eq!(load().unwrap(), StoreState::Consumed);
    }

    #[test]
    fn consume_re_runs_the_durable_write_on_an_already_consumed_store() {
        // P4G-1: the already-Consumed arm must still (re)write and fsync the
        // tombstone, because a prior call may have landed the rename but died
        // on the sync (visible-but-unsynced). fsync is not observable, so we
        // observe that the DURABLE WRITE re-runs at all: plant a valid but
        // NON-canonical tombstone (reordered fields, extra whitespace) that
        // load() still reads as Consumed; a short-circuit Ok(false) would
        // leave those exact bytes, while re-running the durable write
        // overwrites them with the canonical compact encoding.
        let _dir = RuntimeDirGuard::new("consume-resync");
        let planted = br#"{ "version": 2, "state": "consumed" }"#;
        fs::write(path(), planted).unwrap();
        assert_eq!(load().unwrap(), StoreState::Consumed);
        assert!(!consume().unwrap(), "already consumed: no pending bag");
        let canonical = serde_json::to_vec(&PendingImportRecord::Consumed {
            version: PENDING_IMPORT_VERSION,
        })
        .unwrap();
        assert_eq!(
            fs::read(path()).unwrap(),
            canonical,
            "the already-Consumed arm must re-run the durable write, not short-circuit"
        );
        assert_ne!(
            &fs::read(path()).unwrap(),
            &planted.to_vec(),
            "sanity: the planted bytes were non-canonical to begin with"
        );
    }

    #[test]
    fn consume_from_absent_still_closes_the_window() {
        // The first baseline can land before any legacy receipt (a fresh
        // machine): the window closes anyway, so a compromised extension
        // cannot start the import dance after the user is already on signed
        // policy.
        let _dir = RuntimeDirGuard::new("consume-absent");
        assert!(!consume().unwrap(), "no pending bag existed");
        assert_eq!(load().unwrap(), StoreState::Consumed);
        assert_eq!(
            record_if_absent(json!({ "forged": true })).unwrap(),
            RecordOutcome::AlreadyConsumed
        );
    }

    #[test]
    fn a_post_consume_plant_is_refused_and_never_stored() {
        // P4H-1, the attack the tombstone exists for: after the real import
        // is consumed, a compromised extension re-sends legacy_settings.
        let _dir = RuntimeDirGuard::new("post-consume-plant");
        record_if_absent(json!({ "real": true })).unwrap();
        consume().unwrap();
        assert_eq!(
            record_if_absent(json!({ "forged": true })).unwrap(),
            RecordOutcome::AlreadyConsumed
        );
        assert_eq!(load().unwrap(), StoreState::Consumed);
        // The read surface answers consumed - structurally bagless, so a
        // forgery cannot even be represented.
        assert_eq!(
            gather_pending_import(),
            PendingImportReport::Consumed {
                v: PENDING_IMPORT_REPORT_VERSION
            }
        );
    }

    #[test]
    fn the_report_sum_cannot_deserialize_an_impossible_mixture() {
        // P4F-10: the report is a tagged sum like the on-disk record; a
        // consumed answer smuggling a bag is a parse error, not a value.
        assert!(serde_json::from_str::<PendingImportReport>(
            r#"{"state":"consumed","v":1,"bag":{"forged":true}}"#
        )
        .is_err());
        assert!(
            serde_json::from_str::<PendingImportReport>(r#"{"state":"consumed","v":1}"#).is_ok()
        );
    }

    #[test]
    fn the_report_wire_form_is_the_frozen_tagged_shape() {
        // The exact object `policy pending-import --json` prints (the app
        // version-gates `v`, then strict-parses): the `state` tag plus each
        // arm's own fields, nothing else.
        let present = serde_json::to_value(PendingImportReport::Present {
            v: PENDING_IMPORT_REPORT_VERSION,
            bag: json!({ "pageEvalEnabled": true }),
        })
        .unwrap();
        assert_eq!(
            present,
            json!({ "state": "present", "v": 1, "bag": { "pageEvalEnabled": true } })
        );
        let error = serde_json::to_value(PendingImportReport::Error {
            v: PENDING_IMPORT_REPORT_VERSION,
            detail: "boom".into(),
        })
        .unwrap();
        assert_eq!(error, json!({ "state": "error", "v": 1, "detail": "boom" }));
        assert_eq!(
            serde_json::to_value(PendingImportReport::Consumed { v: 1 }).unwrap(),
            json!({ "state": "consumed", "v": 1 })
        );
        assert_eq!(
            serde_json::to_value(PendingImportReport::None { v: 1 }).unwrap(),
            json!({ "state": "none", "v": 1 })
        );
    }

    #[test]
    fn gather_never_writes_whatever_the_store_holds() {
        // The read command's contract: gathering is READ-ONLY in every state,
        // including the fail-closed error arm (a damaged receipt is evidence
        // and must not be "repaired" by a read).
        let _dir = RuntimeDirGuard::new("gather-read-only");
        // Absent: gathering must not create the file.
        assert_eq!(gather_pending_import(), PendingImportReport::None { v: 1 });
        assert!(!path().exists());
        // Pending, consumed, and corrupt: the exact bytes survive the read.
        for planted in [
            br#"{"state":"pending","version":2,"bag":{"a":1}}"#.as_slice(),
            br#"{"state":"consumed","version":2}"#.as_slice(),
            b"{ not json".as_slice(),
        ] {
            fs::write(path(), planted).unwrap();
            let _ = gather_pending_import();
            assert_eq!(
                fs::read(path()).unwrap(),
                planted.to_vec(),
                "gather_pending_import must not rewrite the store"
            );
        }
    }

    #[test]
    fn path_has_expected_filename() {
        assert_eq!(path().file_name().unwrap(), "pending-import.json");
    }
}
