//! The audit trail: one structured record per security-relevant decision, recorded AFTER the decision
//! is applied, so [`record`] never fails and a full disk or an unwritable file cannot become a denial of service
//! against enforcement itself. Never call [`record`] while holding the runtime lock: audit I/O stays outside
//! every critical section.
//!
//! ```text
//! stderr via log::audit             -> hidden below BB_LOG=info; the FILE is the audit surface, not a diagnostic
//! runtime_dir()/audit.log, 0600     -> one JSON line per record regardless of BB_LOG, rotated once to audit.log.1,
//!                                      read back by [`read`] (behind `chromium-bridge audit`)
//! failed write                      -> bumps a process-local counter; the next written record carries dropped: n
//! rotation                          -> its own NON-BLOCKING sidecar lock (audit.log.lock, see append_at), so it can
//!                                      never entangle with the runtime lock
//! read-back                         -> deny_unknown_fields plus a version check; [`read`] keeps a line that does not
//!                                      parse as an explicit unrecognized entry in its position
//! ```

use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::ipc;

/// Current record schema version; unknown versions are surfaced as
/// unrecognized by the reader, never guessed at. Public so every reading
/// surface applies the same strict check.
pub const AUDIT_VERSION: u32 = 1;

/// Size cap for the live audit file. When an append would exceed it, the live
/// file rotates to `audit.log.1` (replacing any previous rotation), so the
/// trail is bounded to roughly twice this figure plus one record.
const AUDIT_MAX_BYTES: u64 = 256 * 1024;

/// How many records `audit` prints when `--limit` is not given. Public so the
/// `--help` text interpolates the same value the handler applies.
pub const DEFAULT_AUDIT_LIMIT: usize = 200;

/// Per-field length bound. Audit fields are labels, codes, and short reasons;
/// anything longer is truncated at write time so one pathological value
/// cannot burn the whole size budget.
const AUDIT_MAX_FIELD: usize = 512;

/// Events recorded (and thus parsed back) by this binary. `snake_case` on the
/// wire. The `confirm_*` and `enroll_*` kinds originate in the extension and
/// arrive over the `audit_event` control frame; everything else is
/// recorded by the host-side surface that made the decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    /// One MCP tool invocation (outcome + taxonomy code).
    ToolCall,
    /// A harness was admitted (own stdio harness, or a relay at the broker).
    HarnessAdmit,
    /// A harness was refused (not allowlisted, unmeasurable, or state
    /// unreadable).
    HarnessRefuse,
    /// A bridge-socket peer was refused before it declared a role (peer-UID
    /// mismatch, failed attestation, failed handshake).
    AttachRefuse,
    /// A browser native host attached to the broker.
    BrowserAttach,
    /// A browser native host was refused (kill switch engaged, or state
    /// unreadable).
    BrowserRefuse,
    /// A trusted client was paired into the allowlist.
    PairClient,
    /// A trusted client was revoked.
    RevokeClient,
    /// The enclave enrollment key was revoked.
    HostKeyRevoke,
    /// The global kill switch was engaged.
    KillEngage,
    /// The global kill switch was released.
    KillRelease,
    /// Host: one per-action user-presence signing round - the
    /// Secure Enclave signature behind a `page_eval`/`page_upload`
    /// confirmation. `ok` means the user tapped and the proof was returned;
    /// `refused` covers everything else (cancelled prompt, keychain refusal,
    /// kill switch, busy). Host-recorded only: the extension cannot forge it
    /// through the `audit_event` frame.
    PresenceSign,
    /// Host: one policy write through `policy::set_signed` / `policy::restrict`:
    /// `ok` names the presence rung that authorized a grant
    /// (`auth=none` for a free restriction) and the touched fields; `refused`
    /// is a signing refusal or a keyless signature-only surface. Host-recorded
    /// only, NOT in [`EXTENSION_AUDIT_KINDS`]: the browser leg must not be
    /// able to plant policy-transition records.
    PolicyWrite,
    /// Extension: a confirmation surface was shown to the user.
    ConfirmShown,
    /// Extension: the user approved a confirmation.
    ConfirmAllowed,
    /// Extension: the user denied a confirmation (or it timed out).
    ConfirmDenied,
    /// Extension: a pairing fingerprint was approved.
    EnrollApproved,
    /// Extension: a pairing fingerprint was rejected.
    EnrollRejected,
    /// Extension: the enrollment pin was revoked.
    EnrollRevoked,
}

/// Which trusted surface performed the recorded act.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    Cli,
    Extension,
    Broker,
    Host,
    /// The library API, called in-process rather than through the CLI or a
    /// frame.
    Core,
}

/// One audit record: one line of `audit.log`. Every field beyond the first
/// three is optional so one flat shape covers every kind without inventing a
/// nested schema per event; `deny_unknown_fields` keeps reads strict. The
/// record matrix in runtime_record.rs refuses a reader-side compat attribute
/// here as in every module outside the migration ladders.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    /// Schema version; see [`AUDIT_VERSION`]. Stamped by [`record`].
    pub v: u32,
    /// Milliseconds since the Unix epoch. Stamped by [`record`].
    pub ts_ms: u64,
    /// Named `event_kind` on the wire: the stderr JSON line wraps this record in log.rs's
    /// `"kind":"audit"` envelope, and a field named `kind` here would be shadowed by it.
    pub event_kind: AuditKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub surface: Option<Surface>,
    /// Short outcome word: `ok`, `refused`, `error`, `unenrolled`, ...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    /// Tool name, for [`AuditKind::ToolCall`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Stable taxonomy code (`ERROR_SPECS` in error.rs), when the event has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// The client name / browser label the event concerns.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Bounded free-text detail (a reason, an anchor kind).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Confirmation-correlation id for the extension `confirm_*` kinds: minted once per confirmation and
    /// stamped on the `confirm_shown` record AND its later verdict, so a reader joins a
    /// verdict to exactly its own shown row instead of guessing by tool/origin. Distinct from `req`, the host-side
    /// per-tool-call `u64`.
    ///
    /// ```text
    /// denial that never reached a surface -> a fresh cid matching no confirm_shown row
    /// cid-less denial                     -> would fall to the subject fallback and could close an unrelated row
    /// ```
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    /// Per-call request id, for [`AuditKind::ToolCall`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub req: Option<u64>,
    /// Browser-connection generation, for [`AuditKind::ToolCall`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conn: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dur_ms: Option<u64>,
    /// How many records were dropped (write failures) since the previous
    /// successfully written record in this process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dropped: Option<u64>,
}

impl AuditRecord {
    /// A record with only the kind set; callers fill the relevant fields.
    /// `v` and `ts_ms` are stamped by [`record`].
    pub fn new(event_kind: AuditKind) -> Self {
        AuditRecord {
            v: 0,
            ts_ms: 0,
            event_kind,
            surface: None,
            outcome: None,
            tool: None,
            code: None,
            name: None,
            detail: None,
            cid: None,
            req: None,
            conn: None,
            dur_ms: None,
            dropped: None,
        }
    }

    pub fn surface(mut self, s: Surface) -> Self {
        self.surface = Some(s);
        self
    }

    pub fn outcome(mut self, o: &str) -> Self {
        self.outcome = Some(o.to_string());
        self
    }

    pub fn name(mut self, n: &str) -> Self {
        self.name = Some(n.to_string());
        self
    }

    pub fn detail(mut self, d: &str) -> Self {
        self.detail = Some(d.to_string());
        self
    }

    fn truncate_fields(&mut self) {
        for f in [
            &mut self.outcome,
            &mut self.tool,
            &mut self.code,
            &mut self.name,
            &mut self.detail,
            &mut self.cid,
        ] {
            if let Some(s) = f.as_mut() {
                if s.len() > AUDIT_MAX_FIELD {
                    // Truncate on a char boundary so the value stays UTF-8;
                    // index 0 is always a boundary, so the search cannot miss.
                    let cut = (0..=AUDIT_MAX_FIELD)
                        .rev()
                        .find(|&i| s.is_char_boundary(i))
                        .unwrap_or(0);
                    s.truncate(cut);
                }
            }
        }
    }
}

/// Path of the live audit file in the 0700 per-user runtime directory.
pub fn audit_path() -> PathBuf {
    ipc::runtime_dir().join("audit.log")
}

/// Path of the single rotated file.
fn rotated_path(live: &Path) -> PathBuf {
    let mut s = live.as_os_str().to_owned();
    s.push(".1");
    PathBuf::from(s)
}

/// Records that failed to reach the file since the last success, so the trail
/// shows the gap instead of hiding it. Process-local by nature: each process
/// only knows about its own failures.
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// Record one audit event: emit it on stderr and append it to the audit file.
/// Infallible by contract (see the module docs): a failed file write is
/// counted and surfaced on the next successful record, never propagated.
pub fn record(mut rec: AuditRecord) {
    rec.v = AUDIT_VERSION;
    rec.ts_ms = now_ms();
    rec.truncate_fields();
    let dropped = DROPPED.swap(0, Ordering::Relaxed);
    if dropped > 0 {
        rec.dropped = Some(dropped);
    }

    crate::log::audit(&rec);

    let outcome = serde_json::to_vec(&rec).map(|mut line| {
        line.push(b'\n');
        append_at(&audit_path(), &line, AUDIT_MAX_BYTES)
    });
    if !matches!(outcome, Ok(Ok(()))) {
        // Re-arm the count we optimistically claimed, plus this record.
        DROPPED.fetch_add(dropped.saturating_add(1), Ordering::Relaxed);
        log_warn!(
            "audit",
            "audit file write failed; the event was recorded on stderr only \
             (the decision it describes is unaffected)"
        );
    }
}

/// Append one line to `path`, rotating first when the append would push the file past `max` bytes.
///
/// Rotation runs under a NON-BLOCKING exclusive lock on a sidecar `audit.log.lock` (deliberately separate from the
/// runtime lock, see the module docs) and re-checks the size once the lock is held: without both, a writer acting on
/// a stale size check can rename a fresh rotation over the previous one and silently discard a whole file of history.
/// A writer that loses the race just appends, so audit I/O never blocks against a caller's critical section: the file
/// grows past the cap by one record per losing writer until the next uncontended append rotates it.
fn append_at(path: &Path, line: &[u8], max: u64) -> io::Result<()> {
    if needs_rotation(path, line.len(), max) {
        rotate_locked(path, line.len(), max);
    }
    // fsguard refuses a pre-planted symlink at the audit path (the trail must
    // not be redirectable to, or chmod, another file) and re-asserts 0600 so
    // a pre-planted looser file cannot keep group/other bits. A failed open
    // is counted as a dropped record, never fatal.
    let mut f = crate::fsguard::open_private_append(path)?;
    f.write_all(line)?;
    f.flush()
}

/// Whether appending `add` bytes to `path` would exceed `max`. A missing or
/// unreadable file needs no rotation.
fn needs_rotation(path: &Path, add: usize, max: u64) -> bool {
    // A length that cannot even convert to u64 is certainly over the cap.
    let Ok(add) = u64::try_from(add) else {
        return true;
    };
    fs::metadata(path).is_ok_and(|m| m.len().saturating_add(add) > max)
}

/// Rotate `path` to its `.1` sibling, under the sidecar lock. Best-effort by
/// audit's contract: losing the lock race, or any I/O failure here, only
/// delays or skips a rotation, never the append.
fn rotate_locked(path: &Path, add: usize, max: u64) {
    let mut lock_name = path.as_os_str().to_owned();
    lock_name.push(".lock");
    let Ok(lock) = crate::fsguard::open_private_rw(&PathBuf::from(lock_name)) else {
        return;
    };
    if lock.try_lock().is_err() {
        // Another writer is rotating right now; skip.
        return;
    }
    // Re-check under the lock: the caller's size check may be stale, and
    // rotating on a stale check would clobber the rotation that just won.
    if needs_rotation(path, add, max) {
        let old = rotated_path(path);
        let _ = fs::rename(path, &old);
    }
    // Dropping `lock` releases it.
}

/// A serde-renamed variant's wire name (e.g. `tool_call`), obtained by
/// serializing the value. Falls back to `?` if serialization somehow fails
/// (it cannot for these unit enums, but audit code never panics).
fn serde_variant_name<T: Serialize>(v: &T) -> String {
    match serde_json::to_value(v) {
        Ok(serde_json::Value::String(s)) => s,
        _ => "?".to_string(),
    }
}

/// The audit kinds an extension-forwarded `audit_event` frame may carry.
/// Everything else is host-side and must not be forgeable from
/// the browser leg: the extension reports its own user-facing decisions, not
/// admissions or revocations the host already records itself.
///
/// This list is the single source for both sides of the forwarding boundary:
/// the host's [`extension_kind`] whitelist derives from it, and the contract
/// emitter (`emit_contract`) carries its wire names into the generated TS
/// (src/packages/shared/src/audit.gen.ts) that the extension's forwarding
/// set and audit-ring vocabulary build on.
pub const EXTENSION_AUDIT_KINDS: &[AuditKind] = &[
    AuditKind::ConfirmShown,
    AuditKind::ConfirmAllowed,
    AuditKind::ConfirmDenied,
    AuditKind::EnrollApproved,
    AuditKind::EnrollRejected,
    AuditKind::EnrollRevoked,
];

/// The serde wire names (`snake_case`) of [`EXTENSION_AUDIT_KINDS`], in list
/// order, for the contract emitter.
pub fn extension_kind_wire_names() -> Vec<String> {
    EXTENSION_AUDIT_KINDS
        .iter()
        .map(serde_variant_name)
        .collect()
}

/// Resolve `kind` against [`EXTENSION_AUDIT_KINDS`]. Matching goes through
/// serde's own wire names, so the whitelist cannot drift from the
/// `snake_case` renames on [`AuditKind`].
pub(crate) fn extension_kind(kind: &str) -> Option<AuditKind> {
    EXTENSION_AUDIT_KINDS
        .iter()
        .copied()
        .find(|k| serde_variant_name(k) == kind)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

// ---- Reading the trail, and the `chromium-bridge audit` CLI over it -------

/// The newest records of the on-disk trail, rotated file included, as read
/// back for the `audit` subcommand and any other reader of the trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditPage {
    /// The live file; the rotated sibling is read before it.
    #[serde(serialize_with = "serialize_path_lossy")]
    pub path: PathBuf,
    /// Newest first. Every line of the trail is one entry, parsed or not.
    pub entries: Vec<AuditEntry>,
    /// Lines of the trail older than the page, excluded from it.
    pub older: usize,
}

/// A path as display text, lossy for non-UTF-8 bytes. serde's own `PathBuf` serializer refuses those
/// outright, and a runtime dir taken from `XDG_RUNTIME_DIR` can hold them, so a report over such a
/// path would otherwise fail to serialize as a whole.
pub(crate) fn serialize_path_lossy<S: serde::Serializer>(
    path: &Path,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&path.to_string_lossy())
}

/// One line of the trail. A line that fails the strict parse (valid JSON, known fields only, supported
/// version) is reported as unrecognized in its position, never guessed at or skipped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "entry", rename_all = "snake_case")]
pub enum AuditEntry {
    Record(Box<AuditRecord>),
    /// Corrupt, tampered, or a newer schema.
    Unrecognized,
}

/// Read the newest `limit` lines of the trail. Only an unreadable file is an
/// error; a trail that does not exist yet is an empty page.
pub fn read(limit: usize) -> io::Result<AuditPage> {
    read_at(&audit_path(), limit)
}

fn read_at(live: &Path, limit: usize) -> io::Result<AuditPage> {
    let mut lines: Vec<String> = Vec::new();
    for path in [rotated_path(live), live.to_path_buf()] {
        match fs::read_to_string(&path) {
            Ok(text) => lines.extend(text.lines().map(str::to_string)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("cannot read {}: {e}", path.display()),
                ))
            }
        }
    }
    let older = lines.len().saturating_sub(limit);
    let entries = lines
        .iter()
        .skip(older)
        .rev()
        .map(|line| match parse_record(line) {
            Some(rec) => AuditEntry::Record(Box::new(rec)),
            None => AuditEntry::Unrecognized,
        })
        .collect();
    Ok(AuditPage {
        path: live.to_path_buf(),
        entries,
        older,
    })
}

/// `audit [--limit <n>]`: print the newest `limit` records of the on-disk
/// audit trail, oldest first, rotated file included. Read-only. Returns a
/// process exit code.
pub fn run_audit(limit: usize) -> i32 {
    let page = match read(limit) {
        Ok(page) => page,
        Err(e) => {
            eprintln!("audit: {e}");
            return 1;
        }
    };
    print!("{}", render(&page));
    let unrecognized = page
        .entries
        .iter()
        .filter(|e| **e == AuditEntry::Unrecognized)
        .count();
    if unrecognized > 0 {
        eprintln!(
            "audit: {unrecognized} record(s) could not be parsed; treat the trail as suspect"
        );
    }
    0
}

/// The page as the subcommand prints it: oldest first, one line per entry.
fn render(page: &AuditPage) -> String {
    if page.entries.is_empty() && page.older == 0 {
        return format!("no audit records yet (looked in {})\n", page.path.display());
    }
    let mut out = String::new();
    for entry in page.entries.iter().rev() {
        match entry {
            AuditEntry::Record(rec) => out.push_str(&format!("{rec}\n")),
            AuditEntry::Unrecognized => out.push_str(&format!(
                "{:<24} UNRECOGNIZED RECORD (corrupt, tampered, or newer schema)\n",
                "-"
            )),
        }
    }
    out
}

/// Parse one audit line, strictly: valid JSON, known fields only, supported
/// version. Anything else is `None` and shown as unrecognized.
fn parse_record(line: &str) -> Option<AuditRecord> {
    let rec: AuditRecord = serde_json::from_str(line).ok()?;
    (rec.v == AUDIT_VERSION).then_some(rec)
}

/// One human-facing line per record: UTC timestamp, kind, then the fields the record carries. The same
/// line serves the `audit` subcommand and the `BB_LOG_FORMAT=text` stderr line.
impl fmt::Display for AuditRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}  {:<15}",
            format_utc_ms(self.ts_ms),
            serde_variant_name(&self.event_kind)
        )?;
        if let Some(surface) = &self.surface {
            write!(f, " surface={}", serde_variant_name(surface))?;
        }
        if let Some(r) = self.req {
            write!(f, " req={r}")?;
        }
        if let Some(c) = self.conn {
            write!(f, " conn={c}")?;
        }
        if let Some(c) = &self.cid {
            write!(f, " cid={c}")?;
        }
        for (k, v) in [
            ("tool", &self.tool),
            ("name", &self.name),
            ("outcome", &self.outcome),
            ("code", &self.code),
            ("detail", &self.detail),
        ] {
            if let Some(v) = v.as_deref() {
                write!(f, " {k}={v}")?;
            }
        }
        if let Some(d) = self.dur_ms {
            write!(f, " dur_ms={d}")?;
        }
        if let Some(d) = self.dropped {
            write!(f, " dropped={d}")?;
        }
        Ok(())
    }
}

/// Format Unix milliseconds as `YYYY-MM-DD HH:MM:SS.mmm` UTC, without a date
/// dependency.
fn format_utc_ms(ts_ms: u64) -> String {
    let secs = ts_ms / 1000;
    let ms = ts_ms % 1000;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    match civil_from_days(secs / 86_400) {
        Some((year, month, day)) => {
            format!("{year:04}-{month:02}-{day:02} {h:02}:{m:02}:{s:02}.{ms:03}Z")
        }
        None => format!("ts_ms={ts_ms}"),
    }
}

/// Civil `(year, month, day)` for a day count since 1970-01-01, per Howard
/// Hinnant's civil-from-days algorithm. Day counts derived from u64
/// milliseconds are non-negative and small enough that every intermediate
/// fits u64, so no overflow is reachable; the checked ops are defense in
/// depth, turning any future slip into a `None` (rendered as raw `ts_ms`)
/// instead of a panic.
fn civil_from_days(days: u64) -> Option<(u64, u64, u64)> {
    let z = days.checked_add(719_468)?;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = doe
        .checked_sub(doe / 1460)?
        .checked_add(doe / 36_524)?
        .checked_sub(doe / 146_096)?
        / 365;
    let y = era.checked_mul(400)?.checked_add(yoe)?;
    let doy = doe.checked_sub(
        yoe.checked_mul(365)?
            .checked_add(yoe / 4)?
            .checked_sub(yoe / 100)?,
    )?;
    let mp = doy.checked_mul(5)?.checked_add(2)? / 153;
    let day = doy
        .checked_sub(mp.checked_mul(153)?.checked_add(2)? / 5)?
        .checked_add(1)?;
    let month = if mp < 10 {
        mp.checked_add(3)?
    } else {
        mp.checked_sub(9)?
    };
    let year = if month <= 2 { y.checked_add(1)? } else { y };
    Some((year, month, day))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch trail path; the guard removes the directory when the test ends.
    fn scratch_trail() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        (dir, path)
    }

    #[test]
    fn record_serde_roundtrips_and_rejects_unknown_fields() {
        let rec = AuditRecord::new(AuditKind::KillEngage)
            .surface(Surface::Cli)
            .outcome("ok");
        let mut stamped = rec.clone();
        stamped.v = AUDIT_VERSION;
        stamped.ts_ms = 42;
        let line = serde_json::to_string(&stamped).unwrap();
        let back: AuditRecord = serde_json::from_str(&line).unwrap();
        assert_eq!(back, stamped);

        // deny_unknown_fields: an extra field is refused, never skimmed over.
        let mut v: serde_json::Value = serde_json::from_str(&line).unwrap();
        v["surprise"] = serde_json::json!(true);
        assert!(serde_json::from_value::<AuditRecord>(v).is_err());
    }

    #[test]
    fn parse_record_reads_a_complete_line_or_nothing() {
        // A line without ts_ms once read back as a record at the epoch instead of an unrecognized
        // entry. Every stamped field must be present; an absent optional field is None, which is
        // what the writer's skip_serializing_if left out.
        let mut complete = AuditRecord::new(AuditKind::ToolCall);
        complete.v = AUDIT_VERSION;
        complete.ts_ms = 1;
        let cases: [(&str, &str, Option<AuditRecord>); 6] = [
            (
                "stamped fields only",
                r#"{"v":1,"ts_ms":1,"event_kind":"tool_call"}"#,
                Some(complete),
            ),
            ("ts_ms missing", r#"{"v":1,"event_kind":"tool_call"}"#, None),
            ("v missing", r#"{"ts_ms":1,"event_kind":"tool_call"}"#, None),
            (
                "newer version",
                r#"{"v":99,"ts_ms":1,"event_kind":"tool_call"}"#,
                None,
            ),
            (
                "unknown kind",
                r#"{"v":1,"ts_ms":1,"event_kind":"made_up_kind"}"#,
                None,
            ),
            ("not json", "not json", None),
        ];
        for (case, line, expected) in cases {
            assert_eq!(parse_record(line), expected, "{case}");
        }
    }

    #[test]
    fn append_rotates_at_the_cap_and_keeps_one_history_file() {
        let (_dir, path) = scratch_trail();
        let line = vec![b'x'; 100];
        // 100-byte lines with a 250-byte cap: rotation after every 2-3 lines.
        for _ in 0..10 {
            append_at(&path, &line, 250).unwrap();
        }
        let live = fs::metadata(&path).unwrap().len();
        let old = fs::metadata(rotated_path(&path)).unwrap().len();
        assert!(live <= 250, "live file exceeds the cap: {live}");
        assert!(old <= 300, "rotated file kept growing: {old}");
        // Exactly the live file, one rotation, and the rotation lock:
        // bounded history.
        let dir = path.parent().unwrap();
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["audit.log", "audit.log.1", "audit.log.lock"]);
    }

    #[cfg(unix)]
    #[test]
    fn a_preplanted_symlink_is_refused_not_followed() {
        // A symlink where the audit file should be must fail the append
        // (dropped record), never write through to the target.
        let (_dir, path) = scratch_trail();
        let target = path.with_file_name("target.log");
        fs::write(&target, b"").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(append_at(&path, b"{}\n", AUDIT_MAX_BYTES).is_err());
        assert_eq!(
            fs::read(&target).unwrap(),
            b"",
            "the symlink target must stay untouched"
        );
    }

    #[cfg(unix)]
    #[test]
    fn audit_file_is_private_even_when_preplanted_loose() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, path) = scratch_trail();
        fs::write(&path, b"planted\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        append_at(&path, b"{}\n", AUDIT_MAX_BYTES).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode & 0o077,
            0,
            "audit mode {mode:o} leaks group/other bits"
        );
    }

    #[test]
    fn truncation_bounds_every_text_field() {
        let mut rec = AuditRecord::new(AuditKind::ToolCall);
        rec.detail = Some("x".repeat(AUDIT_MAX_FIELD * 4));
        rec.truncate_fields();
        assert_eq!(rec.detail.as_ref().unwrap().len(), AUDIT_MAX_FIELD);
        // The extension-supplied cid is untrusted text like any other and is
        // bounded too (a hostile browser leg cannot bloat the trail with it).
        let mut rec = AuditRecord::new(AuditKind::ConfirmShown);
        rec.cid = Some("c".repeat(AUDIT_MAX_FIELD * 4));
        rec.truncate_fields();
        assert_eq!(rec.cid.as_ref().unwrap().len(), AUDIT_MAX_FIELD);
        // Truncation lands on a char boundary for multi-byte text.
        let mut rec = AuditRecord::new(AuditKind::ToolCall);
        rec.detail = Some("\u{4e2d}".repeat(AUDIT_MAX_FIELD));
        rec.truncate_fields();
        assert!(rec
            .detail
            .as_ref()
            .unwrap()
            .is_char_boundary(rec.detail.as_ref().unwrap().len()));
        assert!(rec.detail.as_ref().unwrap().len() <= AUDIT_MAX_FIELD);
    }

    #[test]
    fn confirm_record_carries_the_cid_through_serde() {
        // A confirm_* record round-trips its correlation id, so a reader
        // can join a verdict to its own shown row.
        let mut rec = AuditRecord::new(AuditKind::ConfirmShown).surface(Surface::Extension);
        rec.cid = Some("11111111-2222-3333-4444-555555555555".into());
        rec.v = AUDIT_VERSION;
        rec.ts_ms = 7;
        let line = serde_json::to_string(&rec).unwrap();
        let back: AuditRecord = serde_json::from_str(&line).unwrap();
        assert_eq!(back, rec);
        assert_eq!(
            back.cid.as_deref(),
            Some("11111111-2222-3333-4444-555555555555")
        );
    }

    #[test]
    fn extension_kinds_admit_only_extension_decisions() {
        // The full whitelist, wire name by wire name: extension_kind resolves
        // each, and the emitted wire-name list (what emit_contract carries
        // into audit.gen.ts) is exactly this set, in this order.
        let expected = [
            ("confirm_shown", AuditKind::ConfirmShown),
            ("confirm_allowed", AuditKind::ConfirmAllowed),
            ("confirm_denied", AuditKind::ConfirmDenied),
            ("enroll_approved", AuditKind::EnrollApproved),
            ("enroll_rejected", AuditKind::EnrollRejected),
            ("enroll_revoked", AuditKind::EnrollRevoked),
        ];
        for (wire, kind) in expected {
            assert_eq!(extension_kind(wire), Some(kind), "{wire}");
        }
        assert_eq!(
            extension_kind_wire_names(),
            expected.map(|(wire, _)| wire.to_string())
        );
        // The forgeable-from-the-browser kinds are refused.
        for host_only in [
            "harness_admit",
            "kill_engage",
            "kill_release",
            "revoke_client",
            "tool_call",
            "presence_sign",
            "policy_write",
        ] {
            assert_eq!(extension_kind(host_only), None, "{host_only}");
        }
    }

    #[test]
    fn utc_formatting_is_correct() {
        assert_eq!(format_utc_ms(0), "1970-01-01 00:00:00.000Z");
        // 2026-07-17 00:00:00 UTC = 1784246400s.
        assert_eq!(format_utc_ms(1_784_246_400_000), "2026-07-17 00:00:00.000Z");
        // Leap-year day: 2024-02-29 12:34:56.789 UTC = 1709210096s.
        assert_eq!(format_utc_ms(1_709_210_096_789), "2024-02-29 12:34:56.789Z");
    }

    #[test]
    fn stderr_json_line_has_one_kind_key_and_the_event_kind() {
        // Counted on the raw bytes: a JSON parser keeps only the last of two equal keys.
        let mut rec = AuditRecord::new(AuditKind::ToolCall).outcome("error");
        rec.v = AUDIT_VERSION;
        rec.ts_ms = 0;
        rec.req = Some(7);
        rec.conn = Some(3);
        rec.tool = Some("page_eval".into());
        rec.code = Some("BRIDGE_KILLED".into());
        rec.dur_ms = Some(8);
        let line = crate::log::render_audit(crate::log::Format::Json, &rec).unwrap();
        assert_eq!(line.matches("\"kind\":").count(), 1, "{line}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&line).unwrap(),
            serde_json::json!({
                "kind": "audit", "v": 1, "ts_ms": 0, "event_kind": "tool_call", "outcome": "error",
                "tool": "page_eval", "code": "BRIDGE_KILLED", "req": 7, "conn": 3, "dur_ms": 8,
            })
        );
        // The text line keeps the correlation ids (req, conn) a reader joins on.
        assert_eq!(
            crate::log::render_audit(crate::log::Format::Text, &rec).unwrap(),
            "[AUDIT] 1970-01-01 00:00:00.000Z  tool_call       req=7 conn=3 tool=page_eval outcome=error code=BRIDGE_KILLED dur_ms=8"
        );
    }

    #[test]
    fn read_pages_the_trail_newest_first_across_the_rotation() {
        // The reader must agree with the writer's layout (audit.log.1 holds the older half) and
        // keep an unparsable line in its position, so a tampered or truncated line shows up where
        // it sits instead of silently shrinking the page.
        let (_dir, live) = scratch_trail();
        let record = |ts_ms: u64, kind: &str| {
            format!("{{\"v\":1,\"ts_ms\":{ts_ms},\"event_kind\":\"{kind}\",\"surface\":\"cli\",\"outcome\":\"ok\"}}\n")
        };
        fs::write(
            rotated_path(&live),
            record(1_000, "kill_engage") + &record(2_000, "kill_release"),
        )
        .unwrap();
        fs::write(
            &live,
            "{not json\n".to_string() + &record(3_000, "pair_client"),
        )
        .unwrap();

        let page = read_at(&live, 3).unwrap();
        let mut release = AuditRecord::new(AuditKind::KillRelease)
            .surface(Surface::Cli)
            .outcome("ok");
        release.v = AUDIT_VERSION;
        release.ts_ms = 2_000;
        let mut pair = AuditRecord::new(AuditKind::PairClient)
            .surface(Surface::Cli)
            .outcome("ok");
        pair.v = AUDIT_VERSION;
        pair.ts_ms = 3_000;
        assert_eq!(
            page,
            AuditPage {
                path: live.clone(),
                entries: vec![
                    AuditEntry::Record(Box::new(pair)),
                    AuditEntry::Unrecognized,
                    AuditEntry::Record(Box::new(release)),
                ],
                older: 1,
            }
        );
        assert_eq!(
            serde_json::to_value(&page).unwrap(),
            serde_json::json!({
                "path": live.to_str().unwrap(),
                "entries": [
                    {"entry": "record", "v": 1, "ts_ms": 3000, "event_kind": "pair_client",
                     "surface": "cli", "outcome": "ok"},
                    {"entry": "unrecognized"},
                    {"entry": "record", "v": 1, "ts_ms": 2000, "event_kind": "kill_release",
                     "surface": "cli", "outcome": "ok"},
                ],
                "older": 1,
            })
        );
        assert_eq!(
            render(&page),
            "1970-01-01 00:00:02.000Z  kill_release    surface=cli outcome=ok\n\
             -                        UNRECOGNIZED RECORD (corrupt, tampered, or newer schema)\n\
             1970-01-01 00:00:03.000Z  pair_client     surface=cli outcome=ok\n"
        );

        let dir = live.parent().unwrap();
        fs::remove_dir_all(dir).unwrap();
        let empty = read_at(&live, 3).unwrap();
        assert_eq!(empty.entries, []);
        assert_eq!(empty.older, 0);
        assert_eq!(
            render(&empty),
            format!("no audit records yet (looked in {})\n", live.display())
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_non_utf8_trail_path_still_serializes() {
        // serde's own PathBuf serializer refuses non-UTF-8 bytes, which XDG_RUNTIME_DIR can carry.
        use std::os::unix::ffi::OsStrExt;
        let live = PathBuf::from(std::ffi::OsStr::from_bytes(b"/nonexistent/\xff/audit.log"));
        let page = read_at(&live, 3).unwrap();
        assert_eq!(
            serde_json::to_value(&page).unwrap(),
            serde_json::json!({
                "path": "/nonexistent/\u{fffd}/audit.log",
                "entries": [],
                "older": 0,
            })
        );
    }
}
