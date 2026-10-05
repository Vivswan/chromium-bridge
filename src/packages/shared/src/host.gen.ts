// GENERATED from the Rust core (enclave/mod.rs KEY_LABEL, ipc/lockfile.rs
// LOCK_FILENAME, mcp_server.rs CLIENT_NAME_ENV, log.rs, audit.rs
// DEFAULT_AUDIT_LIMIT, browsers.rs Browser::ALL) by scripts/gen-ops.ts - DO NOT
// EDIT. Run `moon run gen`.
//
// The host's user-facing constants. scripts/check-docs-literals.ts holds the docs to these, so a rename in the Rust
// core fails the docs gate instead of leaving a troubleshooting page quietly wrong.

// The keychain label of the enclave signing key.
export const KEYCHAIN_LABEL = "com.vivswan.chromium-bridge.enclave.signing.v1";

// The lock file under the per-user runtime directory.
export const LOCK_FILENAME = "run.lock";

// The env var a harness may set to name itself in logs and the audit surface.
export const CLIENT_NAME_ENV = "CHROMIUM_BRIDGE_CLIENT_NAME";

// The stderr threshold env var and its accepted values, least to most verbose.
export const LOG_LEVEL_ENV = "BB_LOG";
export const LOG_LEVELS = ["error", "warn", "info", "debug"] as const;

// The audit line format env var and its accepted values, the default first.
export const LOG_FORMAT_ENV = "BB_LOG_FORMAT";
export const LOG_FORMATS = ["text", "json"] as const;

// How many records `audit` prints without `--limit`.
export const AUDIT_DEFAULT_LIMIT = 200;

// The browser CLI keys (`--browser`), in report order.
export const BROWSER_KEYS = ["chrome", "chromium", "brave", "edge", "vivaldi", "opera"] as const;
