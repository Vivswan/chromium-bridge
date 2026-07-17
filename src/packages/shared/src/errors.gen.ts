// GENERATED from the Rust core (src/packages/core/src/error.rs ERROR_SPECS) by
// scripts/gen-ops.ts - DO NOT EDIT. Edit the taxonomy, then run `just gen`.
//
// The stable cross-process error codes. The Rust server assigns them via
// CallError::code(); the extension reports its own failures with the same
// codes so neither side can invent one the other has never heard of.

export const ERROR_CODES = [
  "INVALID_ARGUMENT",
  "NOT_CONNECTED",
  "PROTOCOL_MISMATCH",
  "EXTENSION_NOT_READY",
  "SITE_NOT_ALLOWED",
  "HOST_PERMISSION_MISSING",
  "TOOL_DISABLED",
  "USER_DENIED",
  "CONFIRMATION_TIMEOUT",
  "TAB_NOT_FOUND",
  "UNSUPPORTED_PAGE",
  "EXECUTION_FAILED",
  "PAYLOAD_TOO_LARGE",
  "RESPONSE_TIMEOUT",
  "CONNECTION_LOST",
  "BROWSER_AMBIGUOUS",
  "BROWSER_NOT_FOUND",
  "BRIDGE_KILLED",
  "INTERNAL_ERROR",
] as const;

export type ErrorCode = (typeof ERROR_CODES)[number];

export type ErrorCategory =
  | "connection"
  | "execution"
  | "internal"
  | "permission"
  | "protocol"
  | "user";

export interface ErrorMeta {
  category: ErrorCategory;
  /** Whether retrying the same call can plausibly succeed unchanged. */
  retryable: boolean;
  /** The user/model-facing default message for the code. */
  message: string;
}

export const ERROR_META: Readonly<Record<ErrorCode, ErrorMeta>> = {
  INVALID_ARGUMENT: {
    category: "protocol",
    retryable: false,
    message: "The tool arguments were missing or invalid.",
  },
  NOT_CONNECTED: {
    category: "connection",
    retryable: true,
    message: "The browser extension is not connected (is it loaded and Chrome running?).",
  },
  PROTOCOL_MISMATCH: {
    category: "protocol",
    retryable: false,
    message:
      "The extension and server protocol versions are incompatible; reload or upgrade the extension.",
  },
  EXTENSION_NOT_READY: {
    category: "connection",
    retryable: true,
    message: "The extension service worker is not ready yet; retry shortly.",
  },
  SITE_NOT_ALLOWED: {
    category: "permission",
    retryable: false,
    message: "The target origin is not in the user's allowlist.",
  },
  HOST_PERMISSION_MISSING: {
    category: "permission",
    retryable: false,
    message: "The extension lacks host permission for the target origin.",
  },
  TOOL_DISABLED: {
    category: "permission",
    retryable: false,
    message: "This tool is disabled in the extension settings.",
  },
  USER_DENIED: {
    category: "user",
    retryable: false,
    message: "The user rejected the action.",
  },
  CONFIRMATION_TIMEOUT: {
    category: "user",
    retryable: true,
    message: "The confirmation prompt timed out without a decision.",
  },
  TAB_NOT_FOUND: {
    category: "execution",
    retryable: false,
    message: "The target tab could not be found.",
  },
  UNSUPPORTED_PAGE: {
    category: "execution",
    retryable: false,
    message:
      "The tool cannot run on this page (e.g. chrome://, the Web Store, or a DevTools-attached tab).",
  },
  EXECUTION_FAILED: {
    category: "execution",
    retryable: false,
    message: "The extension executed the operation but it failed.",
  },
  PAYLOAD_TOO_LARGE: {
    category: "protocol",
    retryable: false,
    message: "The message exceeded the native-messaging size limit.",
  },
  RESPONSE_TIMEOUT: {
    category: "connection",
    retryable: true,
    message: "The extension did not respond in time.",
  },
  CONNECTION_LOST: {
    category: "connection",
    retryable: true,
    message: "The bridge connection was lost while awaiting a response.",
  },
  BROWSER_AMBIGUOUS: {
    category: "protocol",
    retryable: false,
    message:
      "More than one browser is connected; pass the `browser` argument to pick one (see list_browsers).",
  },
  BROWSER_NOT_FOUND: {
    category: "connection",
    retryable: true,
    message: "No connected browser has that label (see list_browsers).",
  },
  BRIDGE_KILLED: {
    category: "permission",
    retryable: false,
    message:
      "The bridge kill switch is engaged (or its state is unreadable); all bridge activity is refused until a trusted surface explicitly releases it.",
  },
  INTERNAL_ERROR: {
    category: "internal",
    retryable: false,
    message: "An unexpected internal error occurred.",
  },
};
