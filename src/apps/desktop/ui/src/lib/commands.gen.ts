// GENERATED from the desktop crate's Tauri command DTOs (src/apps/desktop/src/)
// by the ts-export cargo test (src/apps/desktop/src/ts_export.rs) - DO NOT
// EDIT. Edit the Rust structs, then run `moon run gen`.
//
// Display contracts for the app's own webview (trusted same-author IPC over
// Tauri invoke): static types only, no runtime validators - every decision
// stays in Rust. lib/tauri.ts wraps these in the typed `api` facade.

/**
 * The kill switch as the status view names it. An unreadable record is its
 * own state, not "off": while it is unreadable every enforcement point is
 * refusing, and the UI must say so.
 */
export type KillState =
  | { "state": "off" }
  | { "state": "engaged" }
  | { "state": "unreadable"; detail: string };

export type ServerStatus = {
  lockPresent: boolean;
  lockError: string | null;
  endpoint: string | null;
  pid: number | null;
  /**
   * `None` when no probe was attempted (no lock file / no endpoint).
   */
  reachable: boolean | null;
};

export type BridgeStatus = {
  version: string;
  os: string;
  arch: string;
  kill: KillState;
  server: ServerStatus;
  /**
   * The bundled host binary this app manages, when it resolves.
   */
  hostPath: string | null;
  hostError: string | null;
};

/**
 * The keychain lookup outcome, lowercased on the wire. `invalid` means a key
 * exists under our label but must be treated as untrusted (planted or
 * malformed), which a consumer surfaces as loudly as the human report does.
 */
export type EnclaveKeyState = "present" | "none" | "invalid" | "unsupported" | "error";

/**
 * The enrollment policy carried in the report, mirrored from [`HostConfig`].
 */
export type EnclavePolicyReport = { enrolled: boolean; granularity: string };

/**
 * The versioned, machine-readable enclave status: the exact object
 * `chromium-bridge enclave-status --json` prints (ADR-0029). It is a typed
 * mirror of what used to be an ad-hoc `serde_json::json!`, so the host that
 * emits it and the desktop app that parses it back (`src/apps/desktop`) share
 * one Rust definition instead of two hand-kept shapes.
 *
 * The wire form is frozen: a consumer refuses an unrecognized `v` BEFORE it
 * trusts any other field, so field names and `v` must not change without a
 * version bump. `deny_unknown_fields` makes an unexpected shape a loud
 * refusal on the parsing side.
 */
export type EnclaveStatusReport = {
  /**
   * Schema version. `1` today; a newer value must be refused before any
   * field below is read (fail closed).
   */
  v: number;
  /**
   * Whether this platform has a Secure Enclave (macOS today).
   */
  supported: boolean;
  /**
   * The keychain label the enrollment key lives under.
   */
  key_label: string;
  /**
   * The keychain lookup outcome.
   */
  key: EnclaveKeyState;
  /**
   * Base64 X9.63 public key; present only when `key == present`.
   */
  public_key_b64?: string;
  /**
   * The public key's SHA-256 fingerprint; present only when `key == present`.
   */
  fingerprint?: string;
  /**
   * Human detail for a `key == invalid` or `key == error` state.
   */
  detail?: string;
  /**
   * The recorded enrollment policy, or `null` when there is no readable
   * config. Always present on the wire (as `null`), never omitted.
   */
  policy: EnclavePolicyReport | null;
  /**
   * Set only when the policy read itself failed; `policy` is then `null`.
   */
  policy_error?: string;
};

export type EnclaveOutcome = {
  ok: boolean;
  /**
   * The host subcommand's own words, verbatim (stdout + stderr).
   */
  transcript: string;
  /**
   * Fresh `enclave-status --json` after the operation, when readable. The
   * typed report the core defines and the host emits (`null` when the
   * follow-up read failed).
   */
  status: EnclaveStatusReport | null;
};

export type BrowserRow = {
  /**
   * Stable key (`chrome`, `brave`, ...), also the register/unregister handle.
   */
  key: string;
  detected: boolean;
  /**
   * `RegState::describe()` output: human wording, display only.
   */
  state: string;
  /**
   * `RegState::code()`: ok | missing | stale | foreign | unreadable. The
   * machine form the UI branches on; an unknown code offers no action.
   * Typed as plain `string`: the value set lives in core's RegState, not
   * in this crate.
   */
  code: string;
  healthy: boolean;
  /**
   * Where the registration lives (manifest path, or the HKCU key).
   */
  location: string;
};

/**
 * What first launch found, for the onboarding card. Detection only: no
 * browser configuration is touched (ADR-0029 as amended); every manifest
 * write goes through the user-initiated register commands above.
 */
export type FirstRunReport = {
  /**
   * Keys of the browsers detected for this user (may be empty).
   */
  detected: Array<string>;
};

/**
 * A granted release: the new epoch, and the presence path that authorized
 * it (the UI shows which proof was used - Touch ID or the app floor).
 */
export type ReleaseOutcome = {
  epoch: number;
  /**
   * Which presence proof authorized the release (touch_id, app_confirm, ...).
   */
  auth: string;
};

/**
 * Events recorded (and thus parsed back) by this binary. `snake_case` on the
 * wire. The `confirm_*` and `enroll_*` kinds originate in the extension and
 * arrive over the ADR-0030 `audit_event` control frame; everything else is
 * recorded by the host-side surface that made the decision.
 */
export type AuditKind =
  | "tool_call"
  | "harness_admit"
  | "harness_refuse"
  | "attach_refuse"
  | "browser_attach"
  | "browser_refuse"
  | "pair_client"
  | "revoke_client"
  | "host_key_revoke"
  | "kill_engage"
  | "kill_release"
  | "presence_sign"
  | "confirm_shown"
  | "confirm_allowed"
  | "confirm_denied"
  | "enroll_approved"
  | "enroll_rejected"
  | "enroll_revoked";

/**
 * Which trusted surface performed the recorded act.
 */
export type Surface = "cli" | "extension" | "broker" | "host" | "core";

/**
 * One audit record: one line of `audit.log`. Every field beyond the first
 * three is optional so one flat shape covers every kind without inventing a
 * nested schema per event; `deny_unknown_fields` keeps reads strict.
 */
export type AuditRecord = {
  /**
   * Schema version; see [`AUDIT_VERSION`]. Stamped by [`record`].
   */
  v: number;
  /**
   * Milliseconds since the Unix epoch. Stamped by [`record`].
   */
  ts_ms: number;
  kind: AuditKind;
  surface?: Surface;
  /**
   * Short outcome word: `ok`, `refused`, `error`, `unenrolled`, ...
   */
  outcome?: string;
  /**
   * Tool name, for [`AuditKind::ToolCall`].
   */
  tool?: string;
  /**
   * Stable taxonomy code (`ERROR_SPECS` in error.rs), when the event has one.
   */
  code?: string;
  /**
   * The client name / browser label the event concerns.
   */
  name?: string;
  /**
   * Bounded free-text detail (a reason, an anchor kind).
   */
  detail?: string;
  /**
   * Per-call request id, for [`AuditKind::ToolCall`].
   */
  req?: number;
  /**
   * Browser-connection generation, for [`AuditKind::ToolCall`].
   */
  conn?: number;
  dur_ms?: number;
  /**
   * How many records were dropped (write failures) since the previous
   * successfully written record in this process.
   */
  dropped?: number;
};

/**
 * One line of the audit panel: a strictly parsed record, or an explicit
 * unrecognized marker in its place (order preserved).
 */
export type AuditLine = AuditRecord | { unrecognized: boolean };

export type AuditPage = {
  /**
   * Oldest first, rotated file included, capped to `limit` newest.
   */
  lines: Array<AuditLine>;
  unrecognized: number;
  path: string;
};

/**
 * The anchor kind on the wire: the same `hash` / `team_id` names
 * `AnchorSpec` parses back in [`pair`]. An enum rather than a string so the
 * generated TS carries the literal union straight from the serde attribute.
 */
export type AnchorKind = "hash" | "team_id";

export type ClientRow = {
  name: string;
  anchorKind: AnchorKind;
  anchorValue: string;
  addedUnix: number;
};

/**
 * Whether client admission is enforced: `unenrolled` (no allowlist yet) or
 * `enforced`.
 */
export type Posture = "unenrolled" | "enforced";

export type ClientsPayload = { posture: Posture; clients: Array<ClientRow> };

/**
 * The symlink's assessed state: `installed` (a symlink to a chromium-bridge
 * binary), `missing`, or `foreign` (something else occupies the path; we
 * will not touch it). An enum rather than a string so the generated TS
 * carries the literal union straight from the serde attribute.
 */
export type LinkState = "installed" | "missing" | "foreign";

export type CliToolStatus = {
  /**
   * Where the link lives (or would live): `~/.local/bin/chromium-bridge`.
   */
  path: string;
  state: LinkState;
  /**
   * The link's current target, when installed.
   */
  target: string | null;
  /**
   * Whether the link's target is exactly the host this app bundles (an
   * older install or a dev build shows `installed` but not current).
   */
  current: boolean;
};

export type McpSnippet = {
  hostPath: string;
  /**
   * The copy-paste command for Claude Code.
   */
  command: string;
};

export type ExtensionInfo = { path: string | null; exists: boolean };
