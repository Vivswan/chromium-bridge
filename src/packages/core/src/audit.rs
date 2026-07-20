//! The audit trail (ADR-0030): a structured record of every security-relevant
//! decision, written to two sinks.
//!
//! - **stderr**, through the existing `log::audit` rendering (text or JSON per
//!   `BB_LOG_FORMAT`, hidden below `BB_LOG=info`), so a harness or Chrome log
//!   captures the events alongside the other diagnostics.
//! - **an on-disk file**, `runtime_dir()/audit.log`: one JSON record per line,
//!   0600 in the 0700 runtime directory, size-capped with a single rotation
//!   (`audit.log` -> `audit.log.1`), so the trail survives the short-lived
//!   processes that produce it (the CLI, the native host, a relay) and is
//!   readable later via `chromium-bridge audit`. The file is written
//!   regardless of `BB_LOG`: it is the audit surface, not a diagnostic.
//!
//! ## Log-after-decide, and never fail the decision
//!
//! Recording is strictly observational. Every caller records AFTER the
//! decision it describes has been made and applied, and [`record`] never
//! returns an error: a full disk, an unwritable file, or a poisoned counter
//! must not turn into a denial of service against enforcement itself (an
//! attacker who could fill the disk would otherwise hold the bridge hostage
//! through its own audit trail). A failed write increments a process-local
//! dropped counter; the next successful record carries `dropped: n` so the
//! gap is visible in the trail rather than silent.
//!
//! Do not call [`record`] while holding the runtime lock: audit I/O stays
//! outside every critical section, which is what makes the
//! never-fail-the-decision rule easy to audit at the call sites. Rotation
//! uses its own sidecar lock (`audit.log.lock`, see [`append_at`]), acquired
//! non-blocking, precisely so it can never entangle with the runtime lock.
//!
//! ## Fail-closed reading
//!
//! Records parse with `deny_unknown_fields` and a version check. The reader
//! (`run_audit`) shows a line that fails to parse as an explicit
//! "unrecognized record" instead of guessing at it or crashing, and counts
//! them, so tampering or corruption is visible, never smoothed over.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::ipc;

/// Current record schema version; unknown versions are surfaced as
/// unrecognized by the reader, never guessed at. Public so co-equal reading
/// surfaces (the desktop app's audit panel) apply the same strict check.
pub const AUDIT_VERSION: u32 = 1;

/// Size cap for the live audit file. When an append would exceed it, the live
/// file rotates to `audit.log.1` (replacing any previous rotation), so the
/// trail is bounded to roughly twice this figure plus one record.
const AUDIT_MAX_BYTES: u64 = 256 * 1024;

/// Per-field length bound. Audit fields are labels, codes, and short reasons;
/// anything longer is truncated at write time so one pathological value
/// cannot burn the whole size budget.
const AUDIT_MAX_FIELD: usize = 512;

/// Events recorded (and thus parsed back) by this binary. `snake_case` on the
/// wire. The `confirm_*` and `enroll_*` kinds originate in the extension and
/// arrive over the ADR-0030 `audit_event` control frame; everything else is
/// recorded by the host-side surface that made the decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
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
    /// Host: one per-action user-presence signing round (ADR-0031) - the
    /// Secure Enclave signature behind a `page_eval`/`page_upload`
    /// confirmation. `ok` means the user tapped and the proof was returned;
    /// `refused` covers everything else (cancelled prompt, keychain refusal,
    /// kill switch, busy). Host-recorded only: the extension cannot forge it
    /// through the `audit_event` frame.
    PresenceSign,
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
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    Cli,
    Extension,
    Broker,
    Host,
    /// The library API (the future desktop app drives this).
    Core,
}

/// One audit record: one line of `audit.log`. Every field beyond the first
/// three is optional so one flat shape covers every kind without inventing a
/// nested schema per event; `deny_unknown_fields` keeps reads strict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(optional_fields))]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    /// Schema version; see [`AUDIT_VERSION`]. Stamped by [`record`].
    #[serde(default)]
    pub v: u32,
    /// Milliseconds since the Unix epoch. Stamped by [`record`].
    #[serde(default)]
    pub ts_ms: u64,
    pub kind: AuditKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface: Option<Surface>,
    /// Short outcome word: `ok`, `refused`, `error`, `unenrolled`, ...
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    /// Tool name, for [`AuditKind::ToolCall`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Stable taxonomy code (`ERROR_SPECS` in error.rs), when the event has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// The client name / browser label the event concerns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Bounded free-text detail (a reason, an anchor kind).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Confirmation-correlation id, for the extension `confirm_*` kinds
    /// (ADR-0030). The extension mints one opaque id per confirmation and
    /// stamps it on the `confirm_shown` record AND on that confirmation's
    /// later `confirm_allowed`/`confirm_denied` verdict, so a reader (the
    /// desktop audit panel) joins a verdict to exactly its own shown row
    /// instead of guessing by tool/origin. Pre-surface denials - the panic
    /// latch denying a confirmation that never reached a surface - carry
    /// their own fresh cid that matches no `confirm_shown` row, so they
    /// resolve none. (This is load-bearing: a cid-less denial would fall to
    /// the subject fallback and could close an unrelated legacy row.)
    /// Distinct from `req`: `req` is the host-side per-tool-call id (a
    /// `u64`), this is the browser-minted confirmation id (an opaque
    /// string), a different subsystem.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    /// Per-call request id, for [`AuditKind::ToolCall`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub req: Option<u64>,
    /// Browser-connection generation, for [`AuditKind::ToolCall`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conn: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dur_ms: Option<u64>,
    /// How many records were dropped (write failures) since the previous
    /// successfully written record in this process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dropped: Option<u64>,
}

impl AuditRecord {
    /// A record with only the kind set; callers fill the relevant fields.
    /// `v` and `ts_ms` are stamped by [`record`].
    pub fn new(kind: AuditKind) -> Self {
        AuditRecord {
            v: 0,
            ts_ms: 0,
            kind,
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
                    // Truncate on a char boundary so the value stays UTF-8.
                    let mut cut = AUDIT_MAX_FIELD;
                    while !s.is_char_boundary(cut) {
                        cut -= 1;
                    }
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

    emit_stderr(&rec);

    let outcome = serde_json::to_vec(&rec).map(|mut line| {
        line.push(b'\n');
        append_at(&audit_path(), &line, AUDIT_MAX_BYTES)
    });
    if !matches!(outcome, Ok(Ok(()))) {
        // Re-arm the count we optimistically claimed, plus this record.
        DROPPED.fetch_add(dropped + 1, Ordering::Relaxed);
        log_warn!(
            "audit",
            "audit file write failed; the event was recorded on stderr only \
             (the decision it describes is unaffected)"
        );
    }
}

/// Append one line to `path`, rotating first when the append would push the
/// file past `max` bytes.
///
/// Rotation runs under a NON-BLOCKING exclusive lock on a sidecar
/// `audit.log.lock`, with the size re-checked once the lock is held: without
/// both, a writer acting on a stale size check can rename a freshly rotated
/// file over the previous rotation and silently discard a whole file of
/// history. A writer that loses the lock race skips rotating (the winner is
/// doing it) and just appends, so audit I/O never blocks or deadlocks
/// against a caller's critical section; the worst case is one append past
/// the cap. The lock is its own file, deliberately separate from the runtime
/// lock (see the module docs).
fn append_at(path: &Path, line: &[u8], max: u64) -> io::Result<()> {
    if needs_rotation(path, line.len() as u64, max) {
        rotate_locked(path, line.len() as u64, max);
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
fn needs_rotation(path: &Path, add: u64, max: u64) -> bool {
    fs::metadata(path).is_ok_and(|m| m.len() + add > max)
}

/// Rotate `path` to its `.1` sibling, under the sidecar lock. Best-effort by
/// audit's contract: losing the lock race, or any I/O failure here, only
/// delays or skips a rotation, never the append.
fn rotate_locked(path: &Path, add: u64, max: u64) {
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

/// Render the record to stderr through the shared audit formatter (text or
/// JSON per `BB_LOG_FORMAT`, gated at the `info` threshold like every other
/// audit line).
fn emit_stderr(rec: &AuditRecord) {
    let mut owned: Vec<(&str, String)> = vec![("kind", serde_variant_name(&rec.kind))];
    if let Some(s) = &rec.surface {
        owned.push(("surface", serde_variant_name(s)));
    }
    if let Some(r) = rec.req {
        owned.push(("req", r.to_string()));
    }
    if let Some(c) = rec.conn {
        owned.push(("conn", c.to_string()));
    }
    if let Some(c) = &rec.cid {
        owned.push(("cid", c.to_string()));
    }
    for (k, v) in [
        ("tool", &rec.tool),
        ("name", &rec.name),
        ("outcome", &rec.outcome),
        ("code", &rec.code),
        ("detail", &rec.detail),
    ] {
        if let Some(v) = v.as_deref() {
            owned.push((k, v.to_string()));
        }
    }
    if let Some(d) = rec.dur_ms {
        owned.push(("dur_ms", d.to_string()));
    }
    if let Some(d) = rec.dropped {
        owned.push(("dropped", d.to_string()));
    }
    let fields: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
    crate::log::audit(&fields);
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

/// The audit kinds an extension-forwarded `audit_event` frame may carry
/// (ADR-0030). Everything else is host-side and must not be forgeable from
/// the browser leg: the extension reports its own user-facing decisions, not
/// admissions or revocations the host already records itself.
pub(crate) fn extension_kind(kind: &str) -> Option<AuditKind> {
    match kind {
        "confirm_shown" => Some(AuditKind::ConfirmShown),
        "confirm_allowed" => Some(AuditKind::ConfirmAllowed),
        "confirm_denied" => Some(AuditKind::ConfirmDenied),
        "enroll_approved" => Some(AuditKind::EnrollApproved),
        "enroll_rejected" => Some(AuditKind::EnrollRejected),
        "enroll_revoked" => Some(AuditKind::EnrollRevoked),
        _ => None,
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---- CLI: `chromium-bridge audit` -------------------------------------------

/// `audit [--limit <n>]`: print the on-disk audit trail, oldest first,
/// rotated file included. Read-only. Returns a process exit code.
pub fn run_audit(argv: &[String]) -> i32 {
    let limit = match audit_args(argv) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("audit: {e}");
            return 2;
        }
    };
    let live = audit_path();
    let mut lines: Vec<String> = Vec::new();
    for path in [rotated_path(&live), live.clone()] {
        match fs::read_to_string(&path) {
            Ok(text) => lines.extend(text.lines().map(str::to_string)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                eprintln!("audit: cannot read {}: {e}", path.display());
                return 1;
            }
        }
    }
    if lines.is_empty() {
        println!("no audit records yet (looked in {})", live.display());
        return 0;
    }
    let start = lines.len().saturating_sub(limit);
    let mut unrecognized = 0usize;
    for line in lines.iter().skip(start) {
        match parse_record(line) {
            Some(rec) => println!("{}", render_line(&rec)),
            None => {
                unrecognized += 1;
                println!(
                    "{:<24} UNRECOGNIZED RECORD (corrupt, tampered, or newer schema)",
                    "-"
                );
            }
        }
    }
    if unrecognized > 0 {
        eprintln!(
            "audit: {unrecognized} record(s) could not be parsed; treat the trail as suspect"
        );
    }
    0
}

/// Parse one audit line, strictly: valid JSON, known fields only, supported
/// version. Anything else is `None` and shown as unrecognized.
fn parse_record(line: &str) -> Option<AuditRecord> {
    let rec: AuditRecord = serde_json::from_str(line).ok()?;
    (rec.v == AUDIT_VERSION).then_some(rec)
}

/// One human-facing line per record: UTC timestamp, kind, then the fields the
/// record actually carries.
fn render_line(rec: &AuditRecord) -> String {
    let mut s = format!(
        "{}  {:<15}",
        format_utc_ms(rec.ts_ms),
        serde_variant_name(&rec.kind)
    );
    if let Some(surface) = &rec.surface {
        s.push_str(&format!(" surface={}", serde_variant_name(surface)));
    }
    for (k, v) in [
        ("tool", &rec.tool),
        ("name", &rec.name),
        ("outcome", &rec.outcome),
        ("code", &rec.code),
        ("detail", &rec.detail),
    ] {
        if let Some(v) = v.as_deref() {
            s.push_str(&format!(" {k}={v}"));
        }
    }
    if let Some(d) = rec.dur_ms {
        s.push_str(&format!(" dur_ms={d}"));
    }
    if let Some(d) = rec.dropped {
        s.push_str(&format!(" dropped={d}"));
    }
    s
}

/// The `--limit <n>` of `audit` (default 200), parsed with the same
/// strictness as the other subcommands.
fn audit_args(argv: &[String]) -> Result<usize, String> {
    let mut limit: Option<usize> = None;
    let mut it = argv.iter().skip(2);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--limit" => {
                if limit.is_some() {
                    return Err("--limit given more than once".into());
                }
                let v = it.next().ok_or("--limit requires a value")?;
                limit = Some(
                    v.parse::<usize>()
                        .map_err(|_| format!("--limit wants a number, got {v:?}"))?,
                );
            }
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }
    Ok(limit.unwrap_or(200))
}

/// Format Unix milliseconds as `YYYY-MM-DD HH:MM:SS.mmm` UTC, without a date
/// dependency. Uses Howard Hinnant's civil-from-days algorithm.
fn format_utc_ms(ts_ms: u64) -> String {
    let secs = ts_ms / 1000;
    let ms = ts_ms % 1000;
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    format!("{year:04}-{month:02}-{d:02} {h:02}:{m:02}:{s:02}.{ms:03}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "chromium-bridge-audit-test-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir.join("audit.log")
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
    fn parse_record_refuses_bad_versions_and_garbage() {
        assert!(parse_record("not json").is_none());
        assert!(parse_record(r#"{"v":99,"ts_ms":1,"kind":"tool_call"}"#).is_none());
        assert!(parse_record(r#"{"v":1,"ts_ms":1,"kind":"tool_call"}"#).is_some());
        assert!(
            parse_record(r#"{"v":1,"ts_ms":1,"kind":"made_up_kind"}"#).is_none(),
            "an unknown kind must not parse"
        );
    }

    #[test]
    fn append_rotates_at_the_cap_and_keeps_one_history_file() {
        let path = tmp("rotate");
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
        let path = tmp("symlink");
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
        let path = tmp("mode");
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
        // A confirm_* record round-trips its correlation id, so the desktop
        // panel can join a verdict to its own shown row.
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
        assert_eq!(
            extension_kind("confirm_shown"),
            Some(AuditKind::ConfirmShown)
        );
        assert_eq!(
            extension_kind("enroll_revoked"),
            Some(AuditKind::EnrollRevoked)
        );
        // The forgeable-from-the-browser kinds are refused.
        for host_only in [
            "harness_admit",
            "kill_engage",
            "kill_release",
            "revoke_client",
            "tool_call",
            "presence_sign",
        ] {
            assert_eq!(extension_kind(host_only), None, "{host_only}");
        }
    }

    #[test]
    fn audit_args_parse_and_reject() {
        let argv = |rest: &[&str]| -> Vec<String> {
            ["chromium-bridge", "audit"]
                .iter()
                .copied()
                .chain(rest.iter().copied())
                .map(String::from)
                .collect()
        };
        assert_eq!(audit_args(&argv(&[])), Ok(200));
        assert_eq!(audit_args(&argv(&["--limit", "5"])), Ok(5));
        assert!(audit_args(&argv(&["--limit"])).is_err());
        assert!(audit_args(&argv(&["--limit", "x"])).is_err());
        assert!(audit_args(&argv(&["--limit", "1", "--limit", "2"])).is_err());
        assert!(audit_args(&argv(&["extra"])).is_err());
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
    fn render_line_shows_the_carried_fields() {
        let mut rec = AuditRecord::new(AuditKind::ToolCall);
        rec.v = AUDIT_VERSION;
        rec.ts_ms = 0;
        rec.tool = Some("page_eval".into());
        rec.outcome = Some("error".into());
        rec.code = Some("BRIDGE_KILLED".into());
        let line = render_line(&rec);
        assert!(line.contains("tool_call"));
        assert!(line.contains("tool=page_eval"));
        assert!(line.contains("code=BRIDGE_KILLED"));
    }
}
