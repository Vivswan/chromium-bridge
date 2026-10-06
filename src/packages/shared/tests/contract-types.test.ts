// The exported TYPES of the generated contract modules, pinned shape by shape. tsc over the consumers only
// proves the usages they happen to have; a generator change that widens a type (a lost literal tag, `unknown`
// where a union stood, an optional field made required) compiles everywhere and drifts silently. Each pin is
// strict type equality with a hand-written shape, so `bun run typecheck` fails on a drifted export; bun runs
// the file and finds no tests, which is the point: the proof is the compile.

import type * as envelope from "../src/envelope.gen";
import type { BridgeCommand, OpArgs } from "../src/ops.gen";
import type { PolicyDoc, PolicyOverlay, PolicyValues } from "../src/policy.gen";

// Strict equality (the generic-function trick: mutual assignability lets an added optional field through),
// over types flattened at every depth so an intersection and its spelled-out object read as one; Flat
// distributes over a union so each arm is flattened on its own.
type Flat<T> = T extends object ? { [K in keyof T]: Flat<T[K]> } : T;
type Same<A, B> =
  (<T>() => T extends Flat<A> ? 1 : 2) extends <T>() => T extends Flat<B> ? 1 : 2 ? true : false;
function pin<A, B>(_same: Same<A, B> extends true ? true : never): void {}

type Loose = { [k: string]: unknown };

type Anchor = { kind: "hash" | "signer"; value: string } & Loose;

type RowState =
  | ({ kind: "missing" } & Loose)
  | ({ kind: "ok" } & Loose)
  | ({ kind: "stale"; detail: string } & Loose)
  | ({ kind: "foreign"; detail: string } & Loose)
  | ({ kind: "unreadable"; detail: string } & Loose);

type Overlay = {
  cdpMode?: boolean;
  fileUploadEnabled?: boolean;
  handleDialogEnabled?: boolean;
  pageEvalEnabled?: boolean;
  confirmHighRiskClick?: boolean;
  confirmPageEval?: boolean;
  presenceConfirm?: boolean;
  confirmTabClose?: boolean;
  warnPreciseSnapshot?: boolean;
  evalMask?: boolean;
  hostReverifyMs?: number;
  confirmGraceMs?: number;
  clickToastTimeoutMs?: number;
  evalToastTimeoutMs?: number;
  disabledTools?: string[];
};

type Values = { [K in keyof Overlay]-?: Overlay[K] };

type Args = {
  tabId?: number;
  url?: string;
  ref?: string;
  selector?: string;
  value?: string;
  direction?: string;
  pixels?: number;
  nav?: boolean;
  text?: string;
  timeoutMs?: number;
  code?: string;
  frameId?: string;
  domain?: string;
  name?: string;
  key?: string;
  type?: string;
  keys?: string;
  limit?: number;
  action?: string;
  promptText?: string;
  path?: string;
};

/** An op without args: the empty STRICT object, never `{}` (which TypeScript reads as any non-null value). */
type NoArgs = Record<string, never>;

/** Every arm of the generated command union, so an op's args drifting (a required field made optional, a
 * field gaining `any`) fails here even when the three consumers that narrow on `op` never touch it. */
type Command =
  | { op: "list_browsers"; args: NoArgs }
  | { op: "tab_list"; args: NoArgs }
  | { op: "tab_focus"; args: { tabId: number } }
  | { op: "tab_open"; args: { url: string } }
  | { op: "tab_close"; args: { tabId: number } }
  | { op: "page_snapshot"; args: NoArgs }
  | { op: "page_click"; args: { ref?: string; selector?: string } }
  | { op: "page_fill"; args: { ref?: string; selector?: string; value: string } }
  | { op: "page_text"; args: NoArgs }
  | { op: "page_screenshot"; args: NoArgs }
  | { op: "page_scroll"; args: { direction?: string; pixels?: number } }
  | {
      op: "page_wait_for";
      args: { nav?: boolean; selector?: string; text?: string; timeoutMs?: number };
    }
  | { op: "page_eval"; args: { code: string } }
  | { op: "page_snapshot_precise"; args: { frameId?: string } }
  | { op: "cookie_get"; args: { domain?: string; name?: string; url?: string } }
  | { op: "storage_get"; args: { key?: string; type?: string } }
  | { op: "page_navigate"; args: { url: string } }
  | { op: "page_back"; args: NoArgs }
  | { op: "page_forward"; args: NoArgs }
  | { op: "page_reload"; args: NoArgs }
  | { op: "page_press"; args: { keys: string } }
  | { op: "page_hover"; args: { ref?: string; selector?: string } }
  | { op: "page_select"; args: { ref?: string; selector?: string; value: string } }
  | { op: "console_get"; args: { limit?: number } }
  | { op: "page_handle_dialog"; args: { action: string; promptText?: string } }
  | { op: "page_upload"; args: { path: string; selector: string } };

type BrowserKey = "chrome" | "chromium" | "brave" | "edge" | "vivaldi" | "opera";

type HealthCheck = { value: string; details: string[] } & Loose;

type Report = {
  healthy: boolean;
  host_key: string;
  kill_switch: HealthCheck;
  lock_file: HealthCheck;
  mcp_server: HealthCheck;
  platform: string;
  policy_baseline: HealthCheck;
  summary: string;
  version: string;
} & Loose;

/** The Rust-side nullable optional of a writer frame (Option<T> serialized with its null). */
type Opt<T> = T | null | undefined;

// The envelopes and the signal frame (strict).
pin<envelope.BridgeReqEnvelope, { id: number | string; op: string; browser?: string; args: Args }>(
  true,
);
pin<envelope.BridgeResp, { id: number | string; ok: boolean; data?: unknown; error?: string }>(
  true,
);
pin<envelope.BridgeCancel, { type: "cancel"; id: number | string }>(true);

// The embedded admin items (loose).
pin<envelope.TrustedClient, { name: string; anchor: Anchor; added_unix: number } & Loose>(true);
pin<
  envelope.RegistrationRow,
  { browser: string; detected: boolean; location: string; state: RowState } & Loose
>(true);

pin<
  envelope.AuditTrailEntry,
  | ({ entry: "record"; fields: string; kind: string; ts_ms: number } & Loose)
  | ({ entry: "unrecognized"; text: string } & Loose)
>(true);
pin<envelope.HealthReport, Report>(true);

// The host->extension readers (loose; the verdict frames split on ok).
pin<
  envelope.EnclaveProofFrame,
  { type: "enclave_proof"; key_id: string; pubkey: string; sig: string } & Loose
>(true);
pin<envelope.EnclaveErrorFrame, { type: "enclave_error"; reason: string } & Loose>(true);
pin<
  envelope.ClientListResult,
  {
    type: "client_list_result";
    ok: boolean;
    enrolled: boolean;
    clients: envelope.TrustedClient[];
    error?: string;
  } & Loose
>(true);
pin<
  envelope.ClientRevokeResult,
  { type: "client_revoke_result"; ok: boolean; error?: string } & Loose
>(true);
pin<
  envelope.KillStatusResult,
  { type: "kill_status_result"; ok: boolean; killed?: boolean; error?: string } & Loose
>(true);
pin<
  envelope.RegistrationStatusResult,
  | ({
      type: "registration_status_result";
      ok: true;
      browsers: envelope.RegistrationRow[];
      error?: undefined;
    } & Loose)
  | ({
      type: "registration_status_result";
      ok: false;
      error: string;
      browsers?: undefined;
    } & Loose)
>(true);
pin<
  envelope.AuditReadResult,
  | ({
      type: "audit_read_result";
      ok: true;
      entries: envelope.AuditTrailEntry[];
      older: number;
      path: string;
      error?: undefined;
    } & Loose)
  | ({
      type: "audit_read_result";
      ok: false;
      error: string;
      entries?: undefined;
      older?: undefined;
      path?: undefined;
    } & Loose)
>(true);
pin<
  envelope.DoctorReportResult,
  | ({ type: "doctor_report_result"; ok: true; report: Report; error?: undefined } & Loose)
  | ({ type: "doctor_report_result"; ok: false; error: string; report?: undefined } & Loose)
>(true);
pin<
  envelope.BrowserRevokeResultFrame,
  | ({ type: "browser_revoke_result"; ok: true; reason?: undefined } & Loose)
  | ({ type: "browser_revoke_result"; ok: false; reason: string } & Loose)
>(true);
pin<
  envelope.PolicyCurrentFrame,
  | ({
      type: "policy_current";
      ok: true;
      baseline: string;
      sig?: string;
      overlay?: Overlay;
      error?: undefined;
    } & Loose)
  | ({
      type: "policy_current";
      ok: false;
      error: string;
      baseline?: undefined;
      sig?: undefined;
      overlay?: undefined;
    } & Loose)
>(true);
pin<
  envelope.PolicyRestrictResult,
  | ({ type: "policy_restrict_result"; ok: true; error?: undefined } & Loose)
  | ({ type: "policy_restrict_result"; ok: false; error: string } & Loose)
>(true);
pin<envelope.LangCurrentFrame, { type: "lang_current"; value: string; seq: number } & Loose>(true);
pin<
  envelope.EnrollOptionsFrame,
  {
    type: "enroll_options";
    challenge: string;
    nonce: string;
    user_id: string;
    user_name: string;
    exclude_credential_ids: string[];
  } & Loose
>(true);
pin<
  envelope.EnrollResultFrame,
  | ({ type: "enroll_result"; ok: true; credential_id: string; reason?: undefined } & Loose)
  | ({ type: "enroll_result"; ok: false; reason: string; credential_id?: undefined } & Loose)
>(true);
pin<
  envelope.PresenceRequestFrame,
  {
    type: "presence_request";
    challenge: string;
    nonce: string;
    action: string;
    allowed_credential_ids: string[];
  } & Loose
>(true);
pin<
  envelope.PresenceResultFrame,
  | ({ type: "presence_result"; ok: true; reason?: undefined } & Loose)
  | ({ type: "presence_result"; ok: false; reason: string } & Loose)
>(true);

// The extension->host writers (strict; Option fields keep their null arm, the host's own serialization).
pin<
  envelope.EnclaveChallengeWire,
  { type: "enclave_challenge"; nonce: string; context?: Opt<string> }
>(true);
pin<envelope.EnclaveRevokeWire, { type: "enclave_revoke" }>(true);
pin<envelope.ClientListWire, { type: "client_list" }>(true);
pin<envelope.ClientRevokeWire, { type: "client_revoke"; name: string }>(true);
pin<envelope.KillStatusWire, { type: "kill_status" }>(true);
pin<envelope.KillEngageWire, { type: "kill_engage" }>(true);
pin<envelope.KillReleaseWire, { type: "kill_release" }>(true);
pin<
  envelope.AuditEventWire,
  {
    type: "audit_event";
    kind: string;
    cid?: Opt<string>;
    detail?: Opt<string>;
    name?: Opt<string>;
    outcome?: Opt<string>;
    tool?: Opt<string>;
  }
>(true);
pin<envelope.RegistrationStatusWire, { type: "registration_status" }>(true);
pin<envelope.RegistrationRepairWire, { type: "registration_repair"; browsers?: Opt<BrowserKey[]> }>(
  true,
);
pin<envelope.AuditReadWire, { type: "audit_read"; limit?: Opt<number> }>(true);
pin<envelope.DoctorReportWire, { type: "doctor_report" }>(true);
pin<envelope.BrowserRevokeWire, { type: "browser_revoke" }>(true);
pin<envelope.PolicyGetWire, { type: "policy_get" }>(true);
pin<
  envelope.PolicyRestrictWire,
  { type: "policy_restrict"; overlay: { [K in keyof Overlay]?: Opt<Overlay[K]> } }
>(true);
pin<envelope.LangSetWire, { type: "lang_set"; value: string }>(true);
pin<envelope.LangGetWire, { type: "lang_get" }>(true);
pin<envelope.EnrollBeginWire, { type: "enroll_begin" }>(true);
pin<
  envelope.EnrollFinishWire,
  { type: "enroll_finish"; attestation_object: string; client_data_json: string }
>(true);
pin<
  envelope.PresenceAssertWire,
  {
    type: "presence_assert";
    authenticator_data: string;
    client_data_json: string;
    credential_id: string;
    signature: string;
  }
>(true);
pin<envelope.PresenceConfirmWire, { type: "presence_confirm"; nonce: string }>(true);
pin<envelope.PresenceBeginWire, { type: "presence_begin"; action: string; origin: string }>(true);

// The catalogue and the policy contract.
pin<OpArgs, Args>(true);
pin<BridgeCommand, Command>(true);
pin<PolicyOverlay, Overlay>(true);
pin<PolicyValues, Values>(true);
pin<PolicyDoc, { v: 1; revision: number; touched: (keyof Values)[] } & Values>(true);
