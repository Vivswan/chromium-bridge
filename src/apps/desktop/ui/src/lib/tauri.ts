// Typed wrappers over the Tauri command surface (src/apps/desktop/src/main.rs).
// The payload types are GENERATED from the Rust command DTOs into
// commands.gen.ts (`moon run gen`), so this facade cannot drift from Rust. They
// are display contracts, not enforcement - every decision stays in Rust.

import { invoke } from "@tauri-apps/api/core";
import type {
  AnchorKind,
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
  LangState,
  McpSnippet,
  PendingImportSurvey,
  PolicyHistoryReport,
  PolicyOutcome,
  PolicyOverlay,
  PolicyPlan,
  PolicyStatusReport,
  PolicyValues,
  ReleaseOutcome,
} from "./commands.gen";

// Re-export the generated types under the module the rest of the UI already
// imports from.
export type * from "./commands.gen";

export function isUnrecognized(line: AuditLine): line is { unrecognized: true } {
  return "unrecognized" in line;
}

/** Healthy is derived, never carried beside the code: a registration is
 * healthy exactly when its state code is "ok". */
export function isHealthy(row: BrowserRow): boolean {
  return row.code === "ok";
}

export const api = {
  bridgeStatus: () => invoke<BridgeStatus>("bridge_status"),
  enclaveStatus: () => invoke<EnclaveStatusReport>("enclave_status"),
  enclavePair: (reset: boolean) => invoke<EnclaveOutcome>("enclave_pair", { reset }),
  enclaveRevoke: () => invoke<EnclaveOutcome>("enclave_revoke"),
  policyStatus: () => invoke<PolicyStatusReport>("policy_status"),
  policyHistory: () => invoke<PolicyHistoryReport>("policy_history"),
  /** The core's canonical deny baseline; the editor's draft seed while no
   * baseline exists (never hardcoded in the webview). */
  policyDefaults: () => invoke<PolicyValues>("policy_defaults"),
  /** Which edited fields relax and which tighten, decided in Rust from the
   * core's direction table - the webview never classifies a direction. */
  policyPlan: (overlay: PolicyOverlay) => invoke<PolicyPlan>("policy_plan", { overlay }),
  policyRestrict: (overlay: PolicyOverlay) =>
    invoke<PolicyStatusReport>("policy_restrict", { overlay }),
  /** Signed grant lane: call ONLY from the confirm handler of the explicit
   * relax/adopt dialog. Rust picks the lane: the bundled host subprocess
   * (Touch ID) on an enrolled Mac, the app's documented unsigned floor on a
   * genuinely unenrolled one, a refusal everywhere else. */
  policySet: (overlay: PolicyOverlay) => invoke<PolicyOutcome>("policy_set", { overlay }),
  /** May raise Touch ID (a relaxing rollback): same dialog-first obligation
   * as policySet. */
  policyRollback: (revision: number) => invoke<PolicyOutcome>("policy_rollback", { revision }),
  /** The pending legacy-import state (ADR-0032 decision 8), READ-ONLY, with
   * a present bag already mapped to a reviewable suggestion. Consuming
   * happens only when revision 1 signs (policyAdopt / policySet). */
  pendingImport: () => invoke<PendingImportSurvey>("pending_import"),
  /** The import screen's Adopt: policySet behind a first-baseline gate (the
   * reviewed suggestion can only ever become revision 1). Same dialog-first
   * obligation as policySet. */
  policyAdopt: (overlay: PolicyOverlay) => invoke<PolicyOutcome>("policy_adopt", { overlay }),
  /** The shared language state; seq === 0 means never explicitly set. */
  langCurrent: () => invoke<LangState>("lang_current"),
  /** USER GESTURE ONLY (decision 7's echo-loop rule): call exclusively from
   * the language picker's click handler, never from the path that applies an
   * incoming lang-epoch event. lib/lang-sync.ts#chooseLanguage is the one
   * sanctioned call site. */
  langSet: (value: string) => invoke<LangState>("lang_set", { value }),
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
  clientPair: (name: string, anchorKind: AnchorKind, anchorValue: string) =>
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
