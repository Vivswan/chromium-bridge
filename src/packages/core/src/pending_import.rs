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
//! - `Absent` or `Pending` -> `Consuming`/`Consumed` via the two-phase
//!   consume ([`begin_consume_locked`] / [`finalize_consume_locked`]; tests
//!   additionally have a one-shot `consume_locked`, sealed behind
//!   `cfg(test)` because it disposes without the durability proof);
//! - `Consuming` is the mid-consume state (P4G-4): the import window is
//!   durably CLOSED - plants are refused exactly like `Consumed` - but the
//!   recorded bag is RETAINED, so a crash between the window-close and the
//!   revision 1 baseline commit no longer loses the user's bag;
//! - `Consumed` is terminal: no transition leaves it.
//!
//! First-bag-wins (D-P4-4): [`record_if_absent`] writes only when the file is
//! absent in EVERY sense - a later `legacy_settings` receipt is logged and
//! DROPPED whether the store holds a pending bag, a mid-consume record, the
//! consumed tombstone, or an unreadable file (not proof of absence; left
//! untouched, fail closed) - so a later-compromised extension cannot replace
//! or re-plant the user's real legacy bag.
//!
//! Consuming WRITES `Consuming`/`Consumed` records rather than deleting the
//! file: deletion would return the store to `Absent`, and since key disposal
//! keeps this file while clearing the signed baseline (D-P4-5), a compromised
//! extension could then plant a forged bag for the NEXT first-run import.
//! The durable records close the import window for the lifetime of the
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
    /// The mid-consume state (P4G-4): a first-baseline write durably closed
    /// the import window BEFORE committing its baseline, and the bag is
    /// retained until the commit lands. For the window this is `Consumed`
    /// (plants are refused); for the app the bag is still readable, so a
    /// crash between the window-close and the baseline commit preserves it
    /// instead of losing it.
    Consuming {
        /// Schema version; see [`PENDING_IMPORT_VERSION`].
        version: u32,
        /// The retained legacy settings bag, opaque JSON (never applied).
        bag: Value,
    },
    /// The durable consumed tombstone: the first signed baseline landed, the
    /// import window is closed for good, and no bag is retained.
    Consumed {
        /// Schema version; see [`PENDING_IMPORT_VERSION`].
        version: u32,
    },
}

/// The store's full state: the three written [`PendingImportRecord`] arms
/// plus the no-file state. An unreadable file is deliberately NOT a state
/// here - it is the `Err` arm of [`load`], so no caller can match it as if it
/// were a readable answer (fail closed).
#[derive(Debug, Clone, PartialEq)]
pub enum StoreState {
    /// No pending-import file exists.
    Absent,
    /// A pending receipt is recorded and readable.
    Pending {
        /// The recorded legacy settings bag.
        bag: Value,
    },
    /// Mid-consume (P4G-4): the import window is closed like `Consumed`, but
    /// the bag is retained for the app to recover.
    Consuming {
        /// The retained legacy settings bag.
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
        PendingImportRecord::Pending { version, .. }
        | PendingImportRecord::Consuming { version, .. }
        | PendingImportRecord::Consumed { version } => *version,
    };
    if version != PENDING_IMPORT_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "pending import version {version} is not supported (this binary understands {PENDING_IMPORT_VERSION})"
            ),
        ));
    }
    if let PendingImportRecord::Pending { bag, .. } | PendingImportRecord::Consuming { bag, .. } =
        &record
    {
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
        PendingImportRecord::Consuming { bag, .. } => StoreState::Consuming { bag },
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

/// Write a consume-lifecycle record (`Consuming` or `Consumed`) durably:
/// atomic rename-over (it legitimately supersedes a `Pending` record), then
/// fsync the file and, on Unix, its parent directory. Durability is these
/// records' entire purpose - a crash right after a reported-successful
/// window-close must not roll the store back and reopen the import window -
/// so only THESE writes pay the fsync cost: losing a `Pending` record to a
/// crash loses only a receipt (first-bag-wins then refuses a re-send, which
/// fails closed), never a security boundary.
fn write_consume_durable(
    record: &PendingImportRecord,
    _lock: &ipc::RuntimeLockToken,
) -> io::Result<()> {
    let bytes = encode(record)?;
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
    /// The consumed tombstone (or the mid-consume `Consuming` record)
    /// exists: the one import this host will ever run already happened or is
    /// underway, so the receipt is dropped - the window stays closed even
    /// after key disposal (which keeps this file, D-P4-5).
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
/// A successful recording also bumps [`crate::revocation::Scope::Policy`]
/// (best-effort) so an already-running app re-probes and surfaces the arrival
/// (its import nav entry appears and the first-baseline dialog warns) instead
/// of the bag waiting, unseen, to be consumed by revision 1.
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
        // Consuming closes the window exactly like the tombstone (P4G-4): a
        // first-baseline write already began consuming, so a receipt arriving
        // now is a late plant and is dropped.
        StoreState::Consuming { .. } | StoreState::Consumed => Ok(RecordOutcome::AlreadyConsumed),
        StoreState::Absent => {
            let record = PendingImportRecord::Pending {
                version: PENDING_IMPORT_VERSION,
                bag,
            };
            write_pending_new(&record, lock)?;
            // A recorded receipt is a policy-adjacent state change the app
            // must notice NOW: the app re-probes the pending-import store on
            // every policy-epoch notice (its App-level listener keeps the
            // import nav entry tracking live state), so without this bump a
            // bag arriving while the app is open stays invisible until the
            // user signs a baseline - which consumes the tombstone and loses
            // the bag for good. Best-effort, same contract as the policy
            // store's bump_policy_epoch_locked: the epoch is an availability
            // signal (a change notice), not integrity - the receipt just
            // written is the authority - so a failed bump is logged and must
            // NEVER fail the recording it trails.
            if let Err(e) = crate::revocation::bump_locked(lock, crate::revocation::Scope::Policy) {
                log_warn!(
                    "pending-import",
                    "legacy bag recorded but the policy epoch bump failed ({e}); the app \
                     notices the pending import only at its next launch"
                );
            }
            Ok(RecordOutcome::Recorded)
        }
    }
}

/// Phase 1 of consuming (P4G-4): durably CLOSE the import window inside the
/// caller's runtime-lock hold, BEFORE the first signed baseline (revision 1)
/// commits - the policy store refuses the whole signed write if this fails.
/// A recorded bag moves to the [`PendingImportRecord::Consuming`] arm (window
/// closed, bag RETAINED), so a crash between this write and the baseline
/// commit no longer loses the bag: the app can still read it and the user's
/// re-tap resumes from here. With no bag to retain (`Absent`, or already
/// `Consumed`) the bagless tombstone is written directly - the first baseline
/// closes the import window for good, receipt or no receipt.
///
/// Durability retry (P4G-1): the record is (re)written and fsynced on EVERY
/// call, including the already-`Consuming`/`Consumed` arms. A prior call may
/// have landed the rename but died on the following `sync_all` - a VISIBLE
/// but UNSYNCED record - and then refused the signed write, so the user
/// re-taps; short-circuiting without re-fsyncing would let revision 1 land
/// over a window-close a crash could still roll back. The rename-over of an
/// identical record is harmless and idempotent, so paying the sync again is
/// the simple, correct fix.
///
/// An unreadable store is an error, never overwritten: the damaged receipt is
/// evidence, and writers stay refused until someone looks (fail closed).
pub fn begin_consume_locked(lock: &ipc::RuntimeLockToken) -> io::Result<()> {
    let record = match load()? {
        StoreState::Pending { bag } | StoreState::Consuming { bag } => {
            PendingImportRecord::Consuming {
                version: PENDING_IMPORT_VERSION,
                bag,
            }
        }
        StoreState::Absent | StoreState::Consumed => PendingImportRecord::Consumed {
            version: PENDING_IMPORT_VERSION,
        },
    };
    write_consume_durable(&record, lock)
}

/// Typestate proof that a signed policy baseline is DURABLY on disk: the
/// data blocks fsynced through a writable handle and, on Unix, the parent
/// directory synced too. [`finalize_consume_locked`] - the only writer that
/// DISPOSES a retained bag on the strength of "the baseline landed" -
/// requires one, and the only mint is [`attest_baseline_durable`], so
/// "finalize over a baseline a power loss could still take back" is a
/// compile error, not a review obligation. The field is private on purpose:
/// no other module can construct the proof.
pub struct DurablyCommittedBaseline(());

/// Fsync the policy store file (writable handle - Windows FlushFileBuffers
/// refuses a read-only one) and, on Unix, its parent directory, and mint the
/// [`DurablyCommittedBaseline`] proof. Refuses when no policy store file
/// exists (nothing to attest): the token is unobtainable exactly when
/// finalizing would be wrong. The atomic-rename write path
/// (`ipc::write_private_atomic`) deliberately does NOT fsync - ordinary
/// runtime files accept the crash window - so the first-baseline commit and
/// the reconcile heal call this to upgrade the one write whose durability a
/// bag disposal is about to rely on.
pub fn attest_baseline_durable(
    _lock: &ipc::RuntimeLockToken,
) -> io::Result<DurablyCommittedBaseline> {
    let path = crate::policy::PolicyStore::path();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)?
        .sync_all()?;
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(DurablyCommittedBaseline(()))
}

/// Phase 2 of consuming (P4G-4): the baseline committed DURABLY (the
/// [`DurablyCommittedBaseline`] token is the proof, and the type system is
/// what demands it), so finalize to the bagless
/// [`PendingImportRecord::Consumed`] tombstone (durable, same fsync
/// discipline), disposing of the retained bag. Without the ordering the
/// token enforces, a power loss after this write could keep the durable
/// tombstone while taking back the un-fsynced baseline rename - Consumed
/// plus no baseline plus no bag, exactly the loss class P4G-4 closes.
/// Unconditional by the same P4G-1 reasoning as [`begin_consume_locked`]:
/// re-running the durable write over an existing tombstone is idempotent
/// and re-establishes durability. The window was already closed by phase 1,
/// so a failure here leaves the fail-closed `Consuming` record standing -
/// closed window, bag retained - never a reopened window.
pub fn finalize_consume_locked(
    lock: &ipc::RuntimeLockToken,
    _baseline: DurablyCommittedBaseline,
) -> io::Result<()> {
    write_consume_durable(
        &PendingImportRecord::Consumed {
            version: PENDING_IMPORT_VERSION,
        },
        lock,
    )
}

/// The one-shot consume, for a caller with no baseline write to interleave:
/// close the window and dispose of any recorded bag in one durable tombstone
/// write inside the caller's runtime-lock hold. Deliberately NOT gated on
/// the baseline proof - closing the window is legitimate with no baseline at
/// all (consume-from-absent) - which is why this writes the tombstone
/// directly instead of going through [`finalize_consume_locked`]. TEST-ONLY
/// BY CONSTRUCTION (`cfg(test)`): that direct write is an un-proofed bag
/// disposal, exactly the escape hatch the [`DurablyCommittedBaseline`]
/// typestate exists to close, so production code cannot reach it at all -
/// the first-baseline path goes begin/attest/finalize. Returns whether a
/// recorded bag (pending or retained mid-consume) was consumed; idempotent
/// on an already-consumed store (returns `Ok(false)`).
#[cfg(test)]
pub fn consume_locked(lock: &ipc::RuntimeLockToken) -> io::Result<bool> {
    let had_bag = matches!(
        load()?,
        StoreState::Pending { .. } | StoreState::Consuming { .. }
    );
    write_consume_durable(
        &PendingImportRecord::Consumed {
            version: PENDING_IMPORT_VERSION,
        },
        lock,
    )?;
    Ok(had_bag)
}

/// [`consume_locked`], taking the runtime lock itself. Test-only, like it.
#[cfg(test)]
pub fn consume() -> io::Result<bool> {
    ipc::with_runtime_lock(consume_locked)
}

/// Self-heal a STRANDED mid-consume record (the P4G-4 follow-up): a
/// `Consuming` record whose baseline DID land - the finalize crashed or its
/// fsync failed after the baseline write, and revision-2+ writes never
/// revisit the pending-import store - would otherwise persist forever,
/// re-offering an import the app can only refuse (its adopt gate refuses
/// once a baseline exists) and retaining a bag disposal was meant to shed.
/// Once the baseline is present AND USABLE, finalizing is unambiguously
/// correct, so this runs idempotently at two host-side seams: native-host
/// startup, and the `policy pending-import` read command (the desktop app's
/// own probe, so a running host heals on the next look). A `Consuming`
/// record with NO baseline is left strictly alone - that is the legitimate
/// crash-before-baseline state the app SHOULD re-offer. An unreadable
/// policy store refuses the heal (error, fail closed), and a
/// present-but-UNUSABLE baseline (valid envelope, damaged or tampered
/// content - `PolicyStore::load` checks only the envelope) also leaves the
/// record untouched: a store that enforces nothing must not cost the user
/// the recoverable import on top of the policy. Returns whether a heal
/// happened.
pub fn reconcile_consuming() -> io::Result<bool> {
    ipc::with_runtime_lock(reconcile_consuming_locked)
}

fn reconcile_consuming_locked(lock: &ipc::RuntimeLockToken) -> io::Result<bool> {
    if !matches!(load()?, StoreState::Consuming { .. }) {
        return Ok(false);
    }
    match crate::policy::PolicyStore::load()? {
        // Mid-consume with no baseline: the re-offer state, not a strand.
        None => return Ok(false),
        // The heal must stand on a USABLE baseline, not a merely present
        // file: the envelope check above says nothing about the baseline
        // bytes, which decode/parse/validate in baseline_doc() and
        // direction-check in effective(). A valid envelope around a damaged
        // baseline enforces nothing, and disposing the bag over it would
        // cost the user BOTH the enforceable policy AND the recoverable
        // import - leave the fail-closed Consuming record untouched instead.
        Some(store) => {
            if let Err(e) = store.effective() {
                log_warn!(
                    "pending-import",
                    "not finalizing the mid-consume record: the policy store is present \
                     but its baseline is unusable ({e}); the retained bag is preserved"
                );
                return Ok(false);
            }
        }
    }
    // The heal disposes the bag on the strength of "the baseline landed", so
    // it carries the same durability obligation as the first-baseline commit:
    // fsync the baseline (minting the proof finalize demands) BEFORE the
    // durable tombstone. A crash of THIS binary landed the rename; only the
    // fsync makes it power-loss-proof too.
    let baseline = attest_baseline_durable(lock)?;
    finalize_consume_locked(lock, baseline)?;
    log_info!(
        "pending-import",
        "finalized a stranded mid-consume record (its baseline had already \
         landed); the retained bag is disposed and the import window stays closed"
    );
    Ok(true)
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
/// and `consuming` are the only arms that carry a recorded bag (`consuming`
/// with the window already closed, P4G-4), `consumed` is the post-import
/// tombstone (structurally bagless), `error` is a present-but-unreadable
/// receipt (fail closed).
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
    /// Mid-consume (P4G-4): a first-baseline write durably closed the import
    /// window but its baseline commit has not been observed to finish. New
    /// bags are refused exactly like `consumed`, and the retained bag is
    /// still readable - the app re-offers it for review, so a crash between
    /// the window-close and the baseline commit preserves the import instead
    /// of losing it.
    Consuming {
        /// Schema version; see [`PENDING_IMPORT_REPORT_VERSION`].
        v: u32,
        /// The retained legacy settings bag, same trust posture as
        /// `present`'s.
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
        Ok(StoreState::Consuming { bag }) => PendingImportReport::Consuming { v: V, bag },
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

    use serde_json::json;

    use super::*;
    use crate::test_support::scratch_runtime_dir;

    #[test]
    fn absent_store_reads_as_absent() {
        let _dir = scratch_runtime_dir("pending-import-absent-none");
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
        let _dir = scratch_runtime_dir("pending-import-round-trip");
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
        let _dir = scratch_runtime_dir("pending-import-near-cap");
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
        let _dir = scratch_runtime_dir("pending-import-first-bag-wins");
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
        let _dir = scratch_runtime_dir("pending-import-oversize");
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
        let _dir = scratch_runtime_dir("pending-import-load-fail-closed");
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
        // A planted over-cap bag (under the file cap, over the bag cap) refused,
        // on both bag-carrying arms.
        let huge = "y".repeat(LEGACY_BAG_MAX_BYTES + 1);
        let planted = serde_json::to_vec(
            &json!({ "state": "pending", "version": 2, "bag": { "blob": huge } }),
        )
        .unwrap();
        fs::write(path(), &planted).unwrap();
        assert!(load().is_err());
        let planted = serde_json::to_vec(
            &json!({ "state": "consuming", "version": 2, "bag": { "blob": huge } }),
        )
        .unwrap();
        fs::write(path(), &planted).unwrap();
        assert!(load().is_err());
        // The consuming arm is held to the same shape and version pins.
        fs::write(
            path(),
            br#"{"state":"consuming","version":2,"bag":{},"surprise":true}"#,
        )
        .unwrap();
        assert!(load().is_err());
        fs::write(path(), br#"{"state":"consuming","version":1,"bag":{}}"#).unwrap();
        assert!(load().is_err());
        // A consuming record cannot omit its bag: each arm carries exactly
        // its own fields.
        fs::write(path(), br#"{"state":"consuming","version":2}"#).unwrap();
        assert!(load().is_err());
        // gather surfaces the failure as the error state, never a default.
        assert!(matches!(
            gather_pending_import(),
            PendingImportReport::Error { .. }
        ));
    }

    #[test]
    fn a_corrupt_existing_file_refuses_both_writers() {
        let _dir = scratch_runtime_dir("pending-import-corrupt-existing");
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
        let _dir = scratch_runtime_dir("pending-import-create-new");
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
        let _dir = scratch_runtime_dir("pending-import-consume");
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
        let _dir = scratch_runtime_dir("pending-import-consume-resync");
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
    fn begin_consume_retains_the_bag_and_closes_the_window() {
        // P4G-4 phase 1: Pending -> Consuming keeps the bag on disk, and the
        // window is closed to plants exactly like the tombstone.
        let _dir = scratch_runtime_dir("pending-import-begin-consume");
        let bag = json!({ "pageEvalEnabled": true });
        record_if_absent(bag.clone()).unwrap();
        ipc::with_runtime_lock(begin_consume_locked).unwrap();
        assert_eq!(load().unwrap(), StoreState::Consuming { bag: bag.clone() });
        assert_eq!(
            record_if_absent(json!({ "forged": true })).unwrap(),
            RecordOutcome::AlreadyConsumed,
            "the mid-consume window refuses plants like the tombstone"
        );
        assert_eq!(
            gather_pending_import(),
            PendingImportReport::Consuming {
                v: PENDING_IMPORT_REPORT_VERSION,
                bag: bag.clone()
            },
            "the read surface reports the retained bag for the app"
        );
        // Idempotent re-run (P4G-1, the re-tap): the bag survives, and the
        // durable write re-runs to canonical bytes - plant a valid but
        // non-canonical Consuming record and watch it re-canonicalize.
        let planted = br#"{ "version": 2, "state": "consuming", "bag": {"pageEvalEnabled":true} }"#;
        fs::write(path(), planted).unwrap();
        assert_eq!(load().unwrap(), StoreState::Consuming { bag: bag.clone() });
        ipc::with_runtime_lock(begin_consume_locked).unwrap();
        let canonical = serde_json::to_vec(&PendingImportRecord::Consuming {
            version: PENDING_IMPORT_VERSION,
            bag: bag.clone(),
        })
        .unwrap();
        assert_eq!(
            fs::read(path()).unwrap(),
            canonical,
            "begin_consume must re-run the durable write, not short-circuit"
        );
        // Disposal from here is the one-shot collapse (the production phase 2
        // demands the durable-baseline proof; the store's seam tests cover it).
        assert!(ipc::with_runtime_lock(consume_locked).unwrap());
        assert_eq!(load().unwrap(), StoreState::Consumed);
    }

    #[test]
    fn attest_refuses_when_no_baseline_exists() {
        // The DurablyCommittedBaseline proof is unobtainable exactly when
        // finalizing a retained bag would be wrong: no policy store file, no
        // token - so the compile-time demand finalize_consume_locked makes is
        // backed by a runtime refusal at the only mint.
        let _dir = scratch_runtime_dir("pending-import-attest-no-baseline");
        assert!(ipc::with_runtime_lock(|lock| attest_baseline_durable(lock).map(|_| ())).is_err());
    }

    #[test]
    fn reconcile_leaves_a_no_baseline_consuming_record_alone() {
        // Consuming with NO baseline is the legitimate crash-before-baseline
        // state the app re-offers - the reconcile must not touch it.
        let _dir = scratch_runtime_dir("pending-import-reconcile-no-baseline");
        let bag = json!({ "keep": true });
        record_if_absent(bag.clone()).unwrap();
        ipc::with_runtime_lock(begin_consume_locked).unwrap();
        assert!(!reconcile_consuming().unwrap(), "nothing to heal");
        assert_eq!(load().unwrap(), StoreState::Consuming { bag });
    }

    #[test]
    fn begin_consume_without_a_bag_writes_the_tombstone_directly() {
        // No bag to retain: Absent and Consumed both land on the bagless
        // tombstone - the first baseline closes the window, receipt or not.
        let _dir = scratch_runtime_dir("pending-import-begin-consume-bagless");
        ipc::with_runtime_lock(begin_consume_locked).unwrap();
        assert_eq!(load().unwrap(), StoreState::Consumed);
        ipc::with_runtime_lock(begin_consume_locked).unwrap();
        assert_eq!(load().unwrap(), StoreState::Consumed);
    }

    #[test]
    fn begin_consume_refuses_an_unreadable_store() {
        // The damaged receipt is evidence: phase 1 propagates the read error
        // instead of overwriting it, which is what refuses the whole first
        // signed write upstream.
        let _dir = scratch_runtime_dir("pending-import-begin-consume-corrupt");
        fs::write(path(), b"{ not json").unwrap();
        assert!(ipc::with_runtime_lock(begin_consume_locked).is_err());
        assert!(load().is_err(), "the evidence is untouched");
    }

    #[test]
    fn consume_counts_a_retained_mid_consume_bag() {
        // The one-shot collapse treats a Consuming record as "a bag was
        // consumed": it existed and this call disposed of it.
        let _dir = scratch_runtime_dir("pending-import-consume-counts-consuming");
        record_if_absent(json!({ "a": 1 })).unwrap();
        ipc::with_runtime_lock(begin_consume_locked).unwrap();
        assert!(consume().unwrap());
        assert_eq!(load().unwrap(), StoreState::Consumed);
    }

    #[test]
    fn consume_from_absent_still_closes_the_window() {
        // The first baseline can land before any legacy receipt (a fresh
        // machine): the window closes anyway, so a compromised extension
        // cannot start the import dance after the user is already on signed
        // policy.
        let _dir = scratch_runtime_dir("pending-import-consume-absent");
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
        let _dir = scratch_runtime_dir("pending-import-post-consume-plant");
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
        let consuming = serde_json::to_value(PendingImportReport::Consuming {
            v: PENDING_IMPORT_REPORT_VERSION,
            bag: json!({ "pageEvalEnabled": true }),
        })
        .unwrap();
        assert_eq!(
            consuming,
            json!({ "state": "consuming", "v": 1, "bag": { "pageEvalEnabled": true } })
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
        let _dir = scratch_runtime_dir("pending-import-gather-read-only");
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

    fn policy_epoch() -> u64 {
        crate::revocation::Revocation::current()
            .unwrap()
            .policy_epoch
    }

    #[test]
    fn recording_bumps_the_policy_epoch_and_drops_do_not() {
        // Finding 2 (silent data loss): the app's import probe re-reads only
        // on a policy-epoch notice, so the Recorded arm - and ONLY that arm -
        // must bump Scope::Policy; the dropped arms change no state worth
        // announcing.
        let _dir = scratch_runtime_dir("pending-import-epoch-bump");
        assert_eq!(policy_epoch(), 0);
        assert_eq!(
            record_if_absent(json!({ "a": 1 })).unwrap(),
            RecordOutcome::Recorded
        );
        let after_record = policy_epoch();
        assert!(after_record > 0, "a recorded receipt must bump the epoch");
        assert_eq!(
            record_if_absent(json!({ "b": 2 })).unwrap(),
            RecordOutcome::AlreadyPresent
        );
        assert_eq!(
            policy_epoch(),
            after_record,
            "a first-bag-wins drop must not bump"
        );
        let oversize = json!({ "blob": "x".repeat(LEGACY_BAG_MAX_BYTES + 1) });
        assert!(matches!(
            record_if_absent(oversize).unwrap(),
            RecordOutcome::Oversize { .. }
        ));
        assert_eq!(
            policy_epoch(),
            after_record,
            "an oversize drop must not bump"
        );
        consume().unwrap();
        let after_consume = policy_epoch();
        assert_eq!(
            record_if_absent(json!({ "c": 3 })).unwrap(),
            RecordOutcome::AlreadyConsumed
        );
        assert_eq!(
            policy_epoch(),
            after_consume,
            "a post-consume drop must not bump"
        );
    }

    #[test]
    fn a_failed_epoch_bump_does_not_fail_the_recording() {
        // The bump is an availability signal, not integrity: a corrupt
        // revocation record makes bump_locked fail, and the recording must
        // land anyway (the receipt is the authority; the app still finds it
        // at its next launch probe).
        let _dir = scratch_runtime_dir("pending-import-epoch-bump-fails");
        fs::write(crate::revocation::Revocation::path(), b"{ not json").unwrap();
        let bag = json!({ "kept": true });
        assert_eq!(
            record_if_absent(bag.clone()).unwrap(),
            RecordOutcome::Recorded,
            "a failed epoch bump must not fail the receipt recording"
        );
        assert_eq!(load().unwrap(), StoreState::Pending { bag });
    }
}
