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

use std::sync::OnceLock;

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

/// Minimal JSON string escaping — enough for the small, controlled values we
/// put in audit fields (tool names, codes, numbers). Avoids pulling serde into
/// the hot path for one line.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Render one audit line from a timestamp and ordered key/value fields. Pure,
/// so both output formats are unit-testable without touching stderr or the
/// clock.
pub fn render_audit(fmt: Format, ts_ms: u128, fields: &[(&str, &str)]) -> String {
    match fmt {
        Format::Text => {
            let mut s = format!("[AUDIT] ts={ts_ms}");
            for (k, v) in fields {
                s.push_str(&format!(" {k}={v}"));
            }
            s
        }
        Format::Json => {
            let mut s = format!("{{\"kind\":\"audit\",\"ts\":{ts_ms}");
            for (k, v) in fields {
                s.push_str(&format!(",\"{}\":\"{}\"", json_escape(k), json_escape(v)));
            }
            s.push('}');
            s
        }
    }
}

/// Emit a structured audit event (one tool invocation) to stderr. Gated at the
/// `Info` threshold so `BB_LOG=warn`/`error` silences it, but on by default.
pub fn audit(fields: &[(&str, &str)]) {
    if !enabled(Level::Info) {
        return;
    }
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    eprintln!("{}", render_audit(format(), ts_ms, fields));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Level::Error < Level::Warn);
        assert!(Level::Warn < Level::Info);
        assert!(Level::Info < Level::Debug);
    }

    #[test]
    fn info_threshold_hides_debug_only() {
        // `enabled` compares against the process-wide threshold; assert the
        // ordering rule it relies on (default threshold is Info).
        assert!(Level::Error <= Level::Info);
        assert!(Level::Info <= Level::Info);
        assert!(Level::Debug > Level::Info);
    }

    #[test]
    fn render_audit_text() {
        let line = render_audit(
            Format::Text,
            1234,
            &[("req", "7"), ("tool", "page_click"), ("outcome", "ok")],
        );
        assert_eq!(line, "[AUDIT] ts=1234 req=7 tool=page_click outcome=ok");
    }

    #[test]
    fn render_audit_json_is_valid_and_escaped() {
        let line = render_audit(
            Format::Json,
            1234,
            &[("tool", "page_eval"), ("code", "EXECUTION_FAILED")],
        );
        // Parses as JSON and carries the fields.
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["kind"], "audit");
        assert_eq!(v["ts"], 1234);
        assert_eq!(v["tool"], "page_eval");
        assert_eq!(v["code"], "EXECUTION_FAILED");
    }

    #[test]
    fn json_escape_handles_quotes_and_control() {
        let line = render_audit(Format::Json, 0, &[("k", "a\"b\\c\nd")]);
        // Still valid JSON despite quotes/backslash/newline in the value.
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["k"], "a\"b\\c\nd");
    }
}
