//! Minimal leveled logging to stderr, gated by the `BB_LOG` env var.
//!
//! Both binary modes speak framed / NDJSON protocols over *stdout*, so every
//! diagnostic must go to *stderr* (Chrome captures the native host's stderr in
//! its internal logs; the MCP client surfaces the MCP server's stderr). Levels let a
//! user raise verbosity with `BB_LOG=debug` at launch without recompiling. The
//! default threshold is `info`, so `debug` lines stay hidden unless requested.
//!
//! Prefer the `log_error!` / `log_warn!` / `log_info!` / `log_debug!` macros
//! over calling [`emit`] directly.

use std::fmt::Display;
use std::sync::OnceLock;

use serde::Serialize;

/// Severity, ordered least-verbose (`Error`) to most-verbose (`Debug`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
}

impl Level {
    fn label(self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
        }
    }
}

/// The active threshold, parsed once from `BB_LOG` (error|warn|info|debug).
/// Unrecognized or unset values fall back to `info`.
pub fn threshold() -> Level {
    static T: OnceLock<Level> = OnceLock::new();
    *T.get_or_init(|| match std::env::var("BB_LOG").ok().as_deref() {
        Some("error") | Some("ERROR") => Level::Error,
        Some("warn") | Some("WARN") => Level::Warn,
        Some("debug") | Some("DEBUG") => Level::Debug,
        _ => Level::Info,
    })
}

/// Whether a line at `level` would be printed under the current threshold.
pub fn enabled(level: Level) -> bool {
    level <= threshold()
}

/// Emit one stderr log line if `level` passes the threshold.
pub fn emit(level: Level, tag: &str, args: std::fmt::Arguments) {
    if enabled(level) {
        eprintln!("[{}] [{}] {}", level.label(), tag, args);
    }
}

/// Output format for audit lines, from `BB_LOG_FORMAT` (text|json). Default
/// `text` keeps the human-readable stderr style; `json` emits one JSON object
/// per line for machine ingestion.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    Text,
    Json,
}

/// The active audit format, parsed once from `BB_LOG_FORMAT`.
pub fn format() -> Format {
    static F: OnceLock<Format> = OnceLock::new();
    *F.get_or_init(|| match std::env::var("BB_LOG_FORMAT").ok().as_deref() {
        Some("json") | Some("JSON") => Format::Json,
        _ => Format::Text,
    })
}

/// One stderr audit line for `event`. The JSON form is the event's own fields under the `"kind":"audit"`
/// envelope log collectors key on, so an event names its own kind under another key ([`AuditRecord`]
/// uses `event_kind`). Pure, so both formats are unit-testable without touching stderr.
///
/// [`AuditRecord`]: crate::audit::AuditRecord
///
/// ```text
/// text  -> [AUDIT] <event's Display>
/// json  -> {"kind":"audit", ...event's own fields}
/// ```
pub fn render_audit<T: Display + Serialize>(fmt: Format, event: &T) -> serde_json::Result<String> {
    match fmt {
        Format::Text => Ok(format!("[AUDIT] {event}")),
        Format::Json => serde_json::to_string(&Envelope {
            kind: "audit",
            event,
        }),
    }
}

#[derive(Serialize)]
struct Envelope<'a, T: Serialize> {
    kind: &'static str,
    #[serde(flatten)]
    event: &'a T,
}

/// Emit one structured audit event to stderr. Gated at the `Info` threshold so
/// `BB_LOG=warn`/`error` silences it, but on by default.
pub fn audit<T: Display + Serialize>(event: &T) {
    if !enabled(Level::Info) {
        return;
    }
    match render_audit(format(), event) {
        Ok(line) => eprintln!("{line}"),
        Err(e) => crate::log_warn!("audit", "audit line could not be rendered: {e}"),
    }
}

#[macro_export]
macro_rules! log_error {
    ($tag:expr, $($a:tt)*) => {
        $crate::log::emit($crate::log::Level::Error, $tag, format_args!($($a)*))
    };
}

#[macro_export]
macro_rules! log_warn {
    ($tag:expr, $($a:tt)*) => {
        $crate::log::emit($crate::log::Level::Warn, $tag, format_args!($($a)*))
    };
}

#[macro_export]
macro_rules! log_info {
    ($tag:expr, $($a:tt)*) => {
        $crate::log::emit($crate::log::Level::Info, $tag, format_args!($($a)*))
    };
}

#[macro_export]
macro_rules! log_debug {
    ($tag:expr, $($a:tt)*) => {
        $crate::log::emit($crate::log::Level::Debug, $tag, format_args!($($a)*))
    };
}
