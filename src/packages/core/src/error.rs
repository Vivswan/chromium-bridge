//! Typed errors for the tool-call path.
//!
//! The IO/wire layers (`protocol`, `ipc`) keep using `std::io::Result` because
//! `io::Error` is already the right currency there. This module covers the
//! higher-level session/tool boundary, where errors were previously stringly
//! typed. Each variant's `Display` text is what the model ultimately sees when
//! a tool call fails (surfaced through `tools::dispatch` as `isError` content).

use std::time::Duration;

/// An error from invoking a tool op over the bridge to the extension.
#[derive(Debug, thiserror::Error)]
pub enum CallError {
    /// No native host is currently connected (extension not loaded, Chrome not
    /// running, or the bridge hasn't reconnected yet).
    #[error("browser extension not connected - is the extension loaded and Chrome running?")]
    NotConnected,

    /// Failed to write the request onto the bridge socket.
    #[error("write to extension failed: {0}")]
    Write(#[source] std::io::Error),

    /// The extension accepted the request but produced no response in time.
    #[error("extension did not respond within {0:?}")]
    Timeout(Duration),

    /// The bridge connection dropped while we were awaiting the response.
    #[error("extension connection lost while waiting for response")]
    Disconnected,

    /// The requested tool name is not recognized by the dispatcher.
    #[error("unknown tool: {0}")]
    UnknownTool(String),

    /// The `browser` routing argument was present but not a string (e.g. a
    /// number or object). Rejected rather than treated as absent: with one
    /// browser connected, ignoring a malformed target would silently run the
    /// call there.
    #[error("invalid `browser` argument {0}: must be a string label from list_browsers")]
    InvalidBrowserArg(String),

    /// Several browsers are connected and the call did not say which one to
    /// use. Field 0 is the comma-joined list of live labels. Refusing (rather
    /// than guessing) is deliberate: acting in the wrong logged-in browser is
    /// worse than asking the caller to name one.
    #[error("multiple browsers are connected ({0}) - pass the `browser` argument to pick one (see list_browsers)")]
    AmbiguousBrowser(String),

    /// The call named a browser label that is not currently connected.
    /// Field 0 is the requested label, field 1 the comma-joined live labels.
    #[error("no connected browser is labeled '{0}' (connected: {1}) - see list_browsers")]
    BrowserNotFound(String, String),

    /// The extension executed the op and reported a failure of its own.
    #[error("{0}")]
    Extension(String),

    /// The global kill switch is engaged (ADR-0030): every tool call is
    /// refused until a trusted surface explicitly releases it. Never
    /// retry-until-cleared territory for a client: the state changes only by
    /// an explicit human act.
    #[error(
        "the bridge kill switch is engaged - all bridge activity is refused until it is \
         explicitly released (`chromium-bridge unkill`, or the extension's options page)"
    )]
    Killed,

    /// The kill state could not be read (a corrupt or unreadable revocation
    /// record). Ambiguity fails closed: with the latch unknowable, the call is
    /// refused exactly as if the switch were engaged. Field 0 is the read
    /// error.
    #[error(
        "the bridge kill state could not be read ({0}); failing closed - \
         see `chromium-bridge doctor` and docs/operations.md for recovery"
    )]
    KillStateUnknown(String),

    /// An internal invariant failed (e.g. a session registry lock poisoned by
    /// a panic in another thread). The call is refused rather than acting on
    /// possibly inconsistent state. Field 0 names the invariant for the log;
    /// no state is trusted after this fires.
    #[error("internal bridge error: {0}")]
    Internal(String),
}

impl CallError {
    /// The taxonomy entry for this variant. Returning a reference into
    /// [`specs`] (rather than a bare string) makes it impossible for a
    /// variant to map to a code the taxonomy has never heard of: the match
    /// below can only name existing entries, and the compiler forces a new
    /// variant to pick one.
    pub fn spec(&self) -> &'static ErrorSpec {
        match self {
            CallError::NotConnected => &specs::NOT_CONNECTED,
            CallError::Write(_) => &specs::CONNECTION_LOST,
            CallError::Timeout(_) => &specs::RESPONSE_TIMEOUT,
            CallError::Disconnected => &specs::CONNECTION_LOST,
            CallError::UnknownTool(_) => &specs::INVALID_ARGUMENT,
            CallError::InvalidBrowserArg(_) => &specs::INVALID_ARGUMENT,
            CallError::AmbiguousBrowser(_) => &specs::BROWSER_AMBIGUOUS,
            CallError::BrowserNotFound(..) => &specs::BROWSER_NOT_FOUND,
            CallError::Extension(_) => &specs::EXECUTION_FAILED,
            CallError::Killed => &specs::BRIDGE_KILLED,
            CallError::KillStateUnknown(_) => &specs::BRIDGE_KILLED,
            CallError::Internal(_) => &specs::INTERNAL_ERROR,
        }
    }

    /// The stable, cross-process error code for this variant.
    ///
    /// These strings are the contract between the Rust server and the
    /// extension: they are the `code` values in [`ERROR_SPECS`] (the canonical
    /// cross-process taxonomy) and are meant for programmatic handling by
    /// clients, while `Display` stays human-facing.
    pub fn code(&self) -> &'static str {
        self.spec().code
    }
}

/// The broad family an error code belongs to, for coarse programmatic
/// handling (a `connection` failure suggests reconnecting, a `permission`
/// failure suggests the extension's settings, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    Protocol,
    Connection,
    Permission,
    User,
    Execution,
    Internal,
}

impl ErrorCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCategory::Protocol => "protocol",
            ErrorCategory::Connection => "connection",
            ErrorCategory::Permission => "permission",
            ErrorCategory::User => "user",
            ErrorCategory::Execution => "execution",
            ErrorCategory::Internal => "internal",
        }
    }
}

/// One entry in the cross-process error taxonomy.
pub struct ErrorSpec {
    /// The stable code, for programmatic handling. Never renamed once
    /// released; retire a code rather than repurposing it.
    pub code: &'static str,
    pub category: ErrorCategory,
    /// Whether retrying the same call can plausibly succeed without the user
    /// or the caller changing anything first.
    pub retryable: bool,
    /// The user/model-facing default message for the code.
    pub message: &'static str,
}

/// Declares the named taxonomy entries and the iterable [`ERROR_SPECS`]
/// table from one list: every constant in [`specs`] is in the table by
/// construction, so a variant mapping ([`CallError::spec`]) can only name a
/// code the generator and the extension will also see, and the code string
/// is always the constant's own name.
macro_rules! error_taxonomy {
    ($($name:ident { category: $category:ident, retryable: $retryable:literal, message: $message:expr $(,)? }),* $(,)?) => {
        /// The named taxonomy entries. Each is a `pub const` so [`CallError::spec`]
        /// can reference entries directly - a mapping to a nonexistent code cannot
        /// compile - while [`ERROR_SPECS`] stays the one iterable table the
        /// generator and the tests consume.
        pub mod specs {
            use super::{ErrorCategory, ErrorSpec};

            $(pub const $name: ErrorSpec = ErrorSpec {
                code: stringify!($name),
                category: ErrorCategory::$category,
                retryable: $retryable,
                message: $message,
            };)*
        }

        /// The canonical cross-process error taxonomy (ADR-0028): the single source
        /// of the stable codes shared by the Rust server (via [`CallError::code`])
        /// and the extension (via the generated `src/packages/shared/src/errors.gen.ts`).
        /// Some codes are assigned only on the Rust side, some only by the extension;
        /// they live in one table so neither side can invent a code the other has
        /// never heard of.
        pub const ERROR_SPECS: &[ErrorSpec] = &[$(specs::$name),*];
    };
}

error_taxonomy! {
    INVALID_ARGUMENT {
        category: Protocol,
        retryable: false,
        message: "The tool arguments were missing or invalid.",
    },
    NOT_CONNECTED {
        category: Connection,
        retryable: true,
        message: "The browser extension is not connected (is it loaded and Chrome running?).",
    },
    PROTOCOL_MISMATCH {
        category: Protocol,
        retryable: false,
        message:
            "The extension and server protocol versions are incompatible; reload or upgrade the \
         extension.",
    },
    EXTENSION_NOT_READY {
        category: Connection,
        retryable: true,
        message: "The extension service worker is not ready yet; retry shortly.",
    },
    SITE_NOT_ALLOWED {
        category: Permission,
        retryable: false,
        message: "The target origin is not in the user's allowlist.",
    },
    HOST_PERMISSION_MISSING {
        category: Permission,
        retryable: false,
        message: "The extension lacks host permission for the target origin.",
    },
    TOOL_DISABLED {
        category: Permission,
        retryable: false,
        message: "This tool is disabled in the extension settings.",
    },
    USER_DENIED {
        category: User,
        retryable: false,
        message: "The user rejected the action.",
    },
    CONFIRMATION_TIMEOUT {
        category: User,
        retryable: true,
        message: "The confirmation prompt timed out without a decision.",
    },
    TAB_NOT_FOUND {
        category: Execution,
        retryable: false,
        message: "The target tab could not be found.",
    },
    UNSUPPORTED_PAGE {
        category: Execution,
        retryable: false,
        message: "The tool cannot run on this page (e.g. chrome://, the Web Store, or a \
          DevTools-attached tab).",
    },
    EXECUTION_FAILED {
        category: Execution,
        retryable: false,
        message: "The extension executed the operation but it failed.",
    },
    PAYLOAD_TOO_LARGE {
        category: Protocol,
        retryable: false,
        message: "The message exceeded the native-messaging size limit.",
    },
    RESPONSE_TIMEOUT {
        category: Connection,
        retryable: true,
        message: "The extension did not respond in time.",
    },
    CONNECTION_LOST {
        category: Connection,
        retryable: true,
        message: "The bridge connection was lost while awaiting a response.",
    },
    BROWSER_AMBIGUOUS {
        category: Protocol,
        retryable: false,
        message: "More than one browser is connected; pass the `browser` argument to pick one \
          (see list_browsers).",
    },
    BROWSER_NOT_FOUND {
        category: Connection,
        retryable: true,
        message: "No connected browser has that label (see list_browsers).",
    },
    BRIDGE_KILLED {
        category: Permission,
        retryable: false,
        message: "The bridge kill switch is engaged (or its state is unreadable); all bridge activity is refused until a trusted surface explicitly releases it.",
    },
    INTERNAL_ERROR {
        category: Internal,
        retryable: false,
        message: "An unexpected internal error occurred.",
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_text_is_model_facing() {
        assert!(CallError::NotConnected
            .to_string()
            .contains("not connected"));
        assert_eq!(
            CallError::UnknownTool("foo".into()).to_string(),
            "unknown tool: foo"
        );
        // The extension's own error text passes through verbatim.
        assert_eq!(CallError::Extension("boom".into()).to_string(), "boom");
        assert!(CallError::Timeout(Duration::from_secs(120))
            .to_string()
            .contains("did not respond"));
    }

    // ERROR_SPECS is the single source of truth for cross-process error
    // codes (the TS constants are generated from it). Every CallError variant
    // must map into the table.
    #[test]
    fn every_variant_code_is_in_the_taxonomy() {
        use std::io;

        // One real instance of every CallError variant. (The compiler forces
        // this list to stay exhaustive in spirit: adding a variant without a
        // code() arm won't compile, and a new code without a taxonomy entry
        // fails here.)
        let cases: &[CallError] = &[
            CallError::NotConnected,
            CallError::Write(io::Error::new(io::ErrorKind::BrokenPipe, "x")),
            CallError::Timeout(Duration::from_secs(1)),
            CallError::Disconnected,
            CallError::UnknownTool("t".into()),
            CallError::InvalidBrowserArg("123".into()),
            CallError::AmbiguousBrowser("brave, chrome".into()),
            CallError::BrowserNotFound("edge".into(), "brave, chrome".into()),
            CallError::Extension("boom".into()),
            CallError::Killed,
            CallError::KillStateUnknown("corrupt".into()),
            CallError::Internal("poisoned lock".into()),
        ];
        for err in cases {
            assert!(
                ERROR_SPECS.iter().any(|s| s.code == err.code()),
                "code {} has no ERROR_SPECS entry",
                err.code()
            );
        }
    }

    #[test]
    fn taxonomy_codes_are_unique_and_well_formed() {
        let mut codes: Vec<&str> = ERROR_SPECS.iter().map(|s| s.code).collect();
        let total = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), total, "duplicate error codes present");
        for spec in ERROR_SPECS {
            assert!(
                spec.code
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c == '_'),
                "code {} is not SCREAMING_SNAKE_CASE",
                spec.code
            );
            assert!(
                !spec.message.is_empty(),
                "code {} has no message",
                spec.code
            );
        }
    }
}
