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

/**
 * The MCP server, classified once from `LockFile::read()`'s three-way
 * result: exactly stopped (no lock file), running (parsed, with the probe
 * result), or lock-unreadable. A discriminated union on the wire, so the UI
 * matches states instead of re-deriving them from correlated nullables.
 */
export type ServerStatus =
  | { "state": "stopped" }
  | { "state": "running"; endpoint: string; pid: number; reachable: boolean }
  | { "state": "unreadable"; detail: string };

/**
 * Where the bundled host binary resolved to, mirroring the `Result` it
 * flattens onto the webview wire: exactly one of a path or an error.
 */
export type HostResolution =
  | { "state": "resolved"; path: string }
  | { "state": "unresolved"; error: string };

export type BridgeStatus = {
  version: string;
  os: string;
  arch: string;
  kill: KillState;
  server: ServerStatus;
  /**
   * The bundled host binary this app manages: resolved to its path, or the
   * everywhere-it-looked error.
   */
  host: HostResolution;
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

/**
 * Just the 15 policy field values, detached from a document's version /
 * revision / touched scoping: the shape the comparisons and the effective
 * policy work in.
 *
 * Serializable in camelCase (the wire field names) so it can be the
 * `effective` payload of [`crate::policy::PolicyStatusReport`] that the CLI
 * emits and the desktop app parses back; `ts_rs`-exported under the gen-only
 * feature, the same posture as the enclave report types. Strict on the way
 * in: serde does NOT inherit a container attribute from an embedding type,
 * so without its own `deny_unknown_fields` an unknown field inside a
 * report's `effective` would parse silently.
 */
export type PolicyValues = {
  cdpMode: boolean;
  fileUploadEnabled: boolean;
  handleDialogEnabled: boolean;
  pageEvalEnabled: boolean;
  confirmHighRiskClick: boolean;
  confirmPageEval: boolean;
  touchIdConfirm: boolean;
  confirmTabClose: boolean;
  warnPreciseSnapshot: boolean;
  evalMask: boolean;
  hostReverifyMs: number;
  confirmGraceMs: number;
  clickToastTimeoutMs: number;
  evalToastTimeoutMs: number;
  disabledTools: Array<string>;
};

/**
 * The store state a status report distinguishes. `none` is the pre-cutover
 * state and is HEALTHY - it is not an error (the extension enforces the deny
 * baseline until a first policy signs). `error` is a present-but-unreadable
 * store, which fails closed.
 */
export type PolicyStoreState = "none" | "present" | "error";

/**
 * The versioned, machine-readable policy status: the exact object
 * `chromium-bridge policy show --json` prints (ADR-0032), the typed mirror
 * the desktop app parses back, and the shape the doctor row renders from.
 *
 * The wire form is frozen: a consumer refuses an unrecognized `v` before it
 * trusts any other field, so field names and `v` must not change without a
 * version bump. `deny_unknown_fields` makes an unexpected shape a loud
 * refusal on the parsing side. The fields below carry data only when the
 * store is `present`; `detail` only when it is `error`.
 */
export type PolicyStatusReport = {
  /**
   * Schema version. `1` today; a newer value must be refused before any
   * field below is read (fail closed).
   */
  v: number;
  /**
   * The store's state.
   */
  store: PolicyStoreState;
  /**
   * The signed baseline's monotonic revision; present only when
   * `store == present`.
   */
  revision?: number;
  /**
   * Whether the stored baseline carries an enclave signature (`true`) or is
   * an app-floor UNSIGNED baseline (`false`). Present only when
   * `store == present`. Host-side this is only "a signature is stored" -
   * the host never self-certifies; the extension verifies it against its
   * pinned key.
   */
  signed?: boolean;
  /**
   * Whether an unsigned restriction overlay is active on top of the
   * baseline. Present only when `store == present`.
   */
  overlay_active?: boolean;
  /**
   * The effective policy: the baseline with the overlay folded over it -
   * what the bridge actually enforces. Present only when `store == present`.
   */
  effective?: PolicyValues;
  /**
   * Human detail for a `store == error` state.
   */
  detail?: string;
};

/**
 * One superseded record, reduced to what a rollback surface needs.
 */
export type PolicyHistoryEntryReport = {
  /**
   * The record's baseline revision, or `null` if that historical baseline
   * is unreadable (a damaged ring entry never blocks the report).
   */
  revision: number | null;
  /**
   * Whether the superseded baseline carried a signature.
   */
  signed: boolean;
  /**
   * Whether it carried a restriction overlay.
   */
  overlay_active: boolean;
  /**
   * Unix seconds when the record stopped being the current store.
   */
  superseded_unix: number;
};

/**
 * The versioned policy-history report: the superseded-revision ring, oldest
 * first, as `chromium-bridge policy history --json` prints it.
 */
export type PolicyHistoryReport = {
  /**
   * Schema version.
   */
  v: number;
  entries: Array<PolicyHistoryEntryReport>;
};

/**
 * The unsigned restriction overlay (ADR-0032 decision 3): per-field
 * overrides on top of the signed baseline, `None` fields omitted from the
 * wire. The overlay travels free precisely because it may only restrict;
 * that direction check is the consumer's business ([`relaxes`] against the
 * effective policy), not this shape's.
 *
 * `ts_rs`-exported under the gen-only feature: the desktop app's editor
 * sends its per-field edits in exactly this shape, strict-parsed by serde
 * at the Tauri boundary (`deny_unknown_fields`).
 */
export type PolicyOverlay = {
  cdpMode?: boolean;
  fileUploadEnabled?: boolean;
  handleDialogEnabled?: boolean;
  pageEvalEnabled?: boolean;
  confirmHighRiskClick?: boolean;
  confirmPageEval?: boolean;
  touchIdConfirm?: boolean;
  confirmTabClose?: boolean;
  warnPreciseSnapshot?: boolean;
  evalMask?: boolean;
  hostReverifyMs?: number;
  confirmGraceMs?: number;
  clickToastTimeoutMs?: number;
  evalToastTimeoutMs?: number;
  disabledTools?: Array<string>;
};

/**
 * How a draft overlay moves each edited field relative to the currently
 * enforced policy, in catalogue order, by wire name. Computed in Rust from
 * the core's direction table; the webview uses it only to pick the lane
 * and to show the user exactly which fields relax before any prompt.
 */
export type PolicyPlan = {
  /**
   * Edited fields that move toward their permissive pole: applying them
   * is a grant and takes the signed lane.
   */
  relaxes: Array<string>;
  /**
   * Edited fields that move toward their restrictive pole.
   */
  tightens: Array<string>;
};

/**
 * One subprocess policy write, mirroring `EnclaveOutcome`: on success the
 * post-write [`PolicyStatusReport`] the host printed under `--json`; on a
 * refusal the host's own words verbatim (the versioned error object where
 * it parses, the raw transcript where it does not - never smoothed over).
 */
export type PolicyOutcome = {
  ok: boolean;
  /**
   * The refusal or diagnostics, verbatim; empty on a quiet success.
   */
  transcript: string;
  /**
   * The post-write status, parsed from the subprocess's `--json` stdout
   * (version-gated). `None` on a refusal.
   */
  status: PolicyStatusReport | null;
};

/**
 * The typed, versioned pending-import status for the desktop app's first-run
 * import screen (ADR-0032 decision 8), gathered fail-closed from the store -
 * the same read discipline as [`crate::policy::gather_policy_status`], and
 * the exact object `chromium-bridge policy pending-import --json` prints
 * (the [`crate::policy::PolicyStatusReport`] pattern: one Rust definition,
 * ts_rs-exported, emitted by the host and parsed back by the app). A
 * tagged sum like the on-disk record, so an impossible combination (a
 * `consumed` answer smuggling a bag, an `error` with no detail) cannot even
 * deserialize: `none` is the ordinary no-receipt state (healthy), `present`
 * is the only arm that carries the recorded bag, `consumed` is the
 * post-import tombstone (structurally bagless), `error` is a
 * present-but-unreadable receipt (fail closed).
 */
export type PendingImportReport =
  | {
      "state": "none";
      /**
       * Schema version; see [`PENDING_IMPORT_REPORT_VERSION`].
       */
      v: number;
    }
  | {
      "state": "present";
      /**
       * Schema version; see [`PENDING_IMPORT_REPORT_VERSION`].
       */
      v: number;
      /**
       * The recorded legacy settings bag. Untrusted free-form JSON
       * (`unknown` on the TS side): a suggestion the user reviews, never
       * applied as policy.
       */
      bag: unknown;
    }
  | {
      "state": "consumed";
      /**
       * Schema version; see [`PENDING_IMPORT_REPORT_VERSION`].
       */
      v: number;
    }
  | {
      "state": "error";
      /**
       * Schema version; see [`PENDING_IMPORT_REPORT_VERSION`].
       */
      v: number;
      /**
       * Human detail of the read failure.
       */
      detail: string;
    };

/**
 * The reviewable mapping of a legacy bag (ADR-0032 decision 8): what Adopt
 * would sign, plus exactly which bag keys fed it and which were dropped.
 */
export type ImportSuggestion = {
  /**
   * The suggested initial policy: the core's deny defaults with every
   * validly-mapped bag field applied. What revision 1 would carry.
   */
  values: PolicyValues;
  /**
   * The same values as a FULL overlay (all 15 fields present): the exact
   * edit Adopt submits to `policy_set`, so the signed document's touched
   * set names every field the user reviewed - a superset of whatever the
   * write relaxes, which is what the grant seam's coverage check needs.
   */
  overlay: PolicyOverlay;
  /**
   * Wire names of the policy fields adopted from the bag, catalogue order.
   */
  mapped: Array<string>;
  /**
   * Bag keys NOT adopted, sorted: browser-owned settings (the policy
   * catalogue does not carry them), unknown keys, and known fields whose
   * value failed its shape check (dropped whole, never coerced).
   */
  ignored: Array<string>;
};

/**
 * What the first-run import screen renders: the pending-import state with a
 * `present` bag already mapped to a reviewable suggestion. The same tagged
 * sum discipline as the report it derives from - `consumed` cannot smuggle
 * a suggestion, `error` always carries its detail.
 */
export type PendingImportSurvey =
  | { "state": "none" }
  | { "state": "present"; suggestion: ImportSuggestion }
  | { "state": "consumed" }
  | { "state": "error"; detail: string };

/**
 * The shared-language state the webview renders and the picker round-trips:
 * `seq == 0` means "never explicitly set anywhere" (the host store's
 * default), which the applying side treats as no signal.
 */
export type LangState = {
  /**
   * One of the shared `uiLanguage` values (`auto`, `en`, `zh_CN`, `zh_TW`).
   */
  value: string;
  /**
   * The echo-suppression sequence; apply a value only when it is strictly
   * greater than the last applied.
   */
  seq: number;
};

/**
 * Core's [`RegState`] with its reasons stripped, mirrored as a serde enum
 * (the same pattern as `clients::AnchorKind`) so the webview receives a
 * closed literal union instead of a plain string. The `From` impl matches
 * exhaustively: a new core state fails to compile here instead of reaching
 * the UI as an unknown code that offers no action.
 */
export type RegCode = "ok" | "missing" | "stale" | "foreign" | "unreadable";

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
   * The machine form the UI branches on, as the closed union the generated
   * TS carries. Healthy is `code === "ok"`, derived - not a sibling field
   * that could disagree.
   */
  code: RegCode;
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
  | "policy_write"
  | "legacy_import_receipt"
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
   * Confirmation-correlation id, for the extension `confirm_*` kinds
   * (ADR-0030). The extension mints one opaque id per confirmation and
   * stamps it on the `confirm_shown` record AND on that confirmation's
   * later `confirm_allowed`/`confirm_denied` verdict, so a reader (the
   * desktop audit panel) joins a verdict to exactly its own shown row
   * instead of guessing by tool/origin. Pre-surface denials - the panic
   * latch denying a confirmation that never reached a surface - carry
   * their own fresh cid that matches no `confirm_shown` row, so they
   * resolve none. (This is load-bearing: a cid-less denial would fall to
   * the subject fallback and could close an unrelated legacy row.)
   * Distinct from `req`: `req` is the host-side per-tool-call id (a
   * `u64`), this is the browser-minted confirmation id (an opaque
   * string), a different subsystem.
   */
  cid?: string;
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
export type AuditLine = AuditRecord | { unrecognized: true };

export type AuditPage = {
  /**
   * Oldest first, rotated file included, capped to `limit` newest. The
   * unrecognized count is derived by the consumer from the marker lines,
   * never carried as a second copy that could disagree.
   */
  lines: Array<AuditLine>;
  path: string;
};

/**
 * The anchor kind on the wire, in both directions: [`list`] serializes it
 * out, and the `client_pair` command deserializes it back in [`pair`]. An
 * enum rather than a string so the generated TS carries the literal union
 * straight from the serde attribute, and an unknown kind from the webview is
 * refused by serde before `pair` runs. `AnchorSpec::ThisParent` has no
 * variant here on purpose: it stays unreachable from the webview.
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

export type ExtensionInfo = {
  /**
   * The loadable unpacked-extension directory, when one resolved.
   */
  path: string | null;
};
