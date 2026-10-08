//! Minimal leveled logging to stderr, gated by the `GENKAN_LOG` env var.
//!
//! Both binary modes speak framed / NDJSON protocols over *stdout*, so every
//! diagnostic must go to *stderr* (Chrome captures the native host's stderr in
//! its internal logs; the MCP client surfaces the MCP server's stderr). Levels let a
//! user raise verbosity with `GENKAN_LOG=debug` at launch without recompiling. The
//! default threshold is `info`, so `debug` lines stay hidden unless requested.
//!
//! Prefer the `log_error!` / `log_warn!` / `log_info!` / `log_debug!` macros
//! over calling [`emit`] directly.

use std::fmt::Display;
use std::sync::OnceLock;

use serde::Serialize;

/// The env var that sets the stderr threshold: a [`Level::name`] in lower- or uppercase, anything else `info`.
pub const LEVEL_ENV: &str = "GENKAN_LOG";

/// The env var that picks the audit line format: a [`Format::name`] in lower- or uppercase, anything else `text`.
pub const FORMAT_ENV: &str = "GENKAN_LOG_FORMAT";

/// Severity, ordered least-verbose (`Error`) to most-verbose (`Debug`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
}

impl Level {
    /// Every level, least to most verbose: the accepted `GENKAN_LOG` values in the order the docs list them.
    pub const ALL: [Level; 4] = [Level::Error, Level::Warn, Level::Info, Level::Debug];

    /// The lowercase spelling `GENKAN_LOG` accepts; the docs state these through the generated contract.
    pub fn name(self) -> &'static str {
        match self {
            Level::Error => "error",
            Level::Warn => "warn",
            Level::Info => "info",
            Level::Debug => "debug",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
        }
    }
}

/// The active threshold, parsed once from [`LEVEL_ENV`].
pub fn threshold() -> Level {
    static T: OnceLock<Level> = OnceLock::new();
    *T.get_or_init(|| {
        let raw = std::env::var(LEVEL_ENV).ok();
        Level::ALL
            .into_iter()
            .find(|l| {
                raw.as_deref()
                    .is_some_and(|v| v == l.name() || v == l.label())
            })
            .unwrap_or(Level::Info)
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

/// Output format for audit lines. `Text` keeps the human-readable stderr style; `Json` emits one JSON
/// object per line for machine ingestion.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    Text,
    Json,
}

impl Format {
    /// Every format, the default first: the accepted `GENKAN_LOG_FORMAT` values in the order the docs list them.
    pub const ALL: [Format; 2] = [Format::Text, Format::Json];

    /// The lowercase spelling `GENKAN_LOG_FORMAT` accepts; the docs state these through the generated contract.
    pub fn name(self) -> &'static str {
        match self {
            Format::Text => "text",
            Format::Json => "json",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Format::Text => "TEXT",
            Format::Json => "JSON",
        }
    }
}

/// The active audit format, parsed once from [`FORMAT_ENV`].
pub fn format() -> Format {
    static F: OnceLock<Format> = OnceLock::new();
    *F.get_or_init(|| {
        let raw = std::env::var(FORMAT_ENV).ok();
        Format::ALL
            .into_iter()
            .find(|f| {
                raw.as_deref()
                    .is_some_and(|v| v == f.name() || v == f.label())
            })
            .unwrap_or(Format::Text)
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
/// `GENKAN_LOG=warn`/`error` silences it, but on by default.
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
