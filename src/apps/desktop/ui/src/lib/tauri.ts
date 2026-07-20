// Typed wrappers over the Tauri command surface (src/apps/desktop/src/main.rs).
// The payload types are GENERATED from the Rust command DTOs into
// commands.gen.ts (`moon run gen`), so this facade cannot drift from Rust. They
// are display contracts, not enforcement - every decision stays in Rust.

import { invoke } from "@tauri-apps/api/core";
import type {
  AuditLine,
  AuditPage,
  BridgeStatus,
  BrowserRow,
  ClientsPayload,
  CliToolStatus,
  EnclaveOutcome,
  EnclaveStatusReport,
  ExtensionInfo,
  FirstRunReport,
  McpSnippet,
  ReleaseOutcome,
} from "./commands.gen";

// Re-export the generated types under the module the rest of the UI already
// imports from.
export type * from "./commands.gen";

export function isUnrecognized(line: AuditLine): line is { unrecognized: boolean } {
  return "unrecognized" in line;
}

export const api = {
  bridgeStatus: () => invoke<BridgeStatus>("bridge_status"),
  enclaveStatus: () => invoke<EnclaveStatusReport>("enclave_status"),
  enclavePair: (reset: boolean) => invoke<EnclaveOutcome>("enclave_pair", { reset }),
  enclaveRevoke: () => invoke<EnclaveOutcome>("enclave_revoke"),
  browsersList: () => invoke<BrowserRow[]>("browsers_list"),
  browserRegister: (key: string) => invoke<string[]>("browser_register", { key }),
  browserUnregister: (key: string) => invoke<string>("browser_unregister", { key }),
  manifestDirRegister: (dir: string) => invoke<string[]>("manifest_dir_register", { dir }),
  manifestDirUnregister: (dir: string) => invoke<string>("manifest_dir_unregister", { dir }),
  /** Detection only (ADR-0029 as amended): never writes into a browser's
   * configuration. Null after the first launch. */
  firstLaunchDetect: () => invoke<FirstRunReport | null>("first_launch_detect"),
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
