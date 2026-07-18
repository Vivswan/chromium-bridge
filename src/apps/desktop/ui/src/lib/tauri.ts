// Typed wrappers over the Tauri command surface (src/apps/desktop/src/main.rs).
// The types here mirror the Rust payload structs field for field; they are
// display contracts, not enforcement - every decision stays in Rust.

import { invoke } from "@tauri-apps/api/core";

export type KillState =
  | { state: "off" }
  | { state: "engaged" }
  | { state: "unreadable"; detail: string };

export interface ServerStatus {
  lockPresent: boolean;
  lockError: string | null;
  endpoint: string | null;
  pid: number | null;
  reachable: boolean | null;
}

export interface BridgeStatus {
  version: string;
  os: string;
  arch: string;
  kill: KillState;
  server: ServerStatus;
  hostPath: string | null;
  hostError: string | null;
}

/** `chromium-bridge enclave-status --json` passed through the app
 * (snake_case: this object comes from the host CLI, not a Tauri struct). */
export interface EnclaveStatusJson {
  v: number;
  supported: boolean;
  key_label: string;
  key: "present" | "none" | "invalid" | "unsupported" | "error";
  public_key_b64?: string;
  fingerprint?: string;
  detail?: string;
  policy: { enrolled: boolean; granularity: string } | null;
  policy_error?: string;
}

export interface EnclaveOutcome {
  ok: boolean;
  transcript: string;
  status: EnclaveStatusJson | null;
}

export interface BrowserRow {
  key: string;
  detected: boolean;
  state: string;
  healthy: boolean;
  location: string;
}

export interface FirstRunReport {
  lines: string[];
  errors: string[];
  detected: string[];
}

/** One audit line: a strictly parsed record (snake_case wire fields from the
 * core's AuditRecord), or an explicit unrecognized marker. */
export interface AuditRecord {
  v: number;
  ts_ms: number;
  kind: string;
  surface?: string;
  outcome?: string;
  tool?: string;
  code?: string;
  name?: string;
  detail?: string;
  req?: number;
  conn?: number;
  dur_ms?: number;
  dropped?: number;
}

export type AuditLine = AuditRecord | { unrecognized: true };

export function isUnrecognized(line: AuditLine): line is { unrecognized: true } {
  return "unrecognized" in line;
}

export interface AuditPage {
  lines: AuditLine[];
  unrecognized: number;
  path: string;
}

export interface ClientRow {
  name: string;
  anchorKind: "hash" | "team_id";
  anchorValue: string;
  addedUnix: number;
}

export interface ClientsPayload {
  posture: "unenrolled" | "enforced";
  clients: ClientRow[];
}

export interface CliToolStatus {
  path: string;
  state: "installed" | "missing" | "foreign";
  target: string | null;
  current: boolean;
}

export interface McpSnippet {
  hostPath: string;
  command: string;
}

export interface ExtensionInfo {
  path: string | null;
  exists: boolean;
}

export interface ReleaseOutcome {
  epoch: number;
  /** Which presence proof authorized the release (touch_id, app_confirm, ...). */
  auth: string;
}

export const api = {
  bridgeStatus: () => invoke<BridgeStatus>("bridge_status"),
  enclaveStatus: () => invoke<EnclaveStatusJson>("enclave_status"),
  enclavePair: (reset: boolean) => invoke<EnclaveOutcome>("enclave_pair", { reset }),
  enclaveRevoke: () => invoke<EnclaveOutcome>("enclave_revoke"),
  browsersList: () => invoke<BrowserRow[]>("browsers_list"),
  browserRegister: (key: string) => invoke<string[]>("browser_register", { key }),
  browserUnregister: (key: string) => invoke<string>("browser_unregister", { key }),
  manifestDirRegister: (dir: string) => invoke<string[]>("manifest_dir_register", { dir }),
  manifestDirUnregister: (dir: string) => invoke<string>("manifest_dir_unregister", { dir }),
  firstLaunchRegister: () => invoke<FirstRunReport | null>("first_launch_register"),
  killEngage: () => invoke<number>("kill_engage"),
  /** Presence-gated: call ONLY from the confirm handler of the explicit
   * modal dialog (Floor::AppConfirm asserts that dialog was shown). */
  killRelease: () => invoke<ReleaseOutcome>("kill_release"),
  auditRead: (limit: number) => invoke<AuditPage>("audit_read", { limit }),
  auditReveal: () => invoke<void>("audit_reveal"),
  clientsList: () => invoke<ClientsPayload>("clients_list"),
  clientRevoke: (name: string) => invoke<boolean>("client_revoke", { name }),
  /** Presence-gated: same dialog-first obligation as killRelease. Returns
   * the presence path that authorized the pairing. */
  clientPair: (name: string, anchorKind: string, anchorValue: string) =>
    invoke<string>("client_pair", { name, anchorKind, anchorValue }),
  cliToolStatus: () => invoke<CliToolStatus>("cli_tool_status"),
  cliToolInstall: () => invoke<CliToolStatus>("cli_tool_install"),
  cliToolUninstall: () => invoke<CliToolStatus>("cli_tool_uninstall"),
  mcpSnippet: () => invoke<McpSnippet>("mcp_snippet"),
  extensionInfo: () => invoke<ExtensionInfo>("extension_info"),
  extensionReveal: () => invoke<void>("extension_reveal"),
};

/** Tauri rejects commands with the Rust error string; normalize whatever
 * arrives into a printable message. */
export function errorText(err: unknown): string {
  if (typeof err === "string") return err;
  if (err instanceof Error) return err.message;
  return JSON.stringify(err);
}
