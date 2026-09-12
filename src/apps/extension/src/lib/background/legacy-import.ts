// The two durable facts of the ADR-0032 decision 8 migration: the send-once flag for the `legacy_settings { bag }`
// frame, and the bag snapshot. policy-sync.ts owns WHEN the send may happen; this module owns only the facts, in
// the enclave-pin.ts single-key pattern (browser.storage.local, confined to extension contexts by trusted-storage.ts).
//
// Sent once, EVER: nothing clears the flag (not a pin revoke, a re-pair, or a host-side key disposal), because a
// re-send after disposal is the replant vector the host's consumed tombstone (pending_import.rs) refuses.
//   absent                 -> never sent
//   any present value      -> sent (garbage and tampered shapes included, so the MEANING cannot be flipped)
//   key deleted outright   -> reads as never sent; the residual, bounded below rather than erased
//
// What bounds a forced resend: trusted-storage.ts blocks content-script writes once hardened (it names the
// cold-start window before setAccessLevel resolves, and the send gate re-awaits hardenStorageAccess before reading
// the flag), and the resend still faces policy-sync.ts's pinned+proven gate and the host's first-bag-wins tombstone.

import {
  DISABLED_TOOL_NAME_MAX_BYTES,
  DISABLED_TOOLS_MAX_ENTRIES,
  POLICY_FIELDS,
  type PolicyValues,
  salvageLegacySetting,
} from "@chromium-bridge/shared";
import { browser } from "wxt/browser";

/** Exported only for legacy-cleanup.ts, which reads it as a deletion precondition (bag shipped) and never
 * writes or deletes it; the flag's semantics stay owned here. */
export const LEGACY_SETTINGS_SENT_KEY = "legacySettingsSent";
const SENT_KEY = LEGACY_SETTINGS_SENT_KEY;

/** Bound disabledTools (the only unbounded legacy field) here, not in the enforcement salvage: the host drops a
 * bag over LEGACY_BAG_MAX_BYTES (64 KiB, pending_import.rs) WHOLE, after send-once has latched, and dropping a
 * bag entry costs a line on the import screen where truncating the enforced deny-list would grant capability.
 * Measured in serialized bytes, the unit the host counts (UTF-16 lengths undercount non-ASCII up to ~3x).
 *   256 entries x 128 bytes + separators  -> about 33 KiB, under the cap with the scalar fields to spare */
function boundBagDisabledTools(list: readonly string[]): string[] {
  const encoder = new TextEncoder();
  return list
    .filter((entry) => encoder.encode(JSON.stringify(entry)).length <= DISABLED_TOOL_NAME_MAX_BYTES)
    .slice(0, DISABLED_TOOLS_MAX_ENTRIES);
}

/** What `legacy_settings` carries: the 15 legacy policy fields (the source the app's first-run import screen
 * signs into revision 1) plus `requireEnrollment`, retired by ADR-0032 decision 8 but kept as history. Not the
 * whole Settings object: browser-owned fields never become policy and `uiLanguage` rides its own lane (decision 7). */
export interface LegacySettingsBag extends PolicyValues {
  requireEnrollment: boolean;
}

/** Whether the bag has ever been sent. Absent = never; anything present -
 * including a tampered value - reads as sent (fail closed, header above). */
export async function getLegacySettingsSent(): Promise<boolean> {
  const { [SENT_KEY]: value } = await browser.storage.local.get(SENT_KEY);
  return value !== undefined;
}

/** Latch the send-once flag. Written only AFTER a successful post (a failed
 * post leaves it unset so a later qualifying occasion retries; a crash
 * between post and this write degrades to one duplicate send, which the
 * host's first-bag-wins rule drops). Cleared by nothing (header above). */
export async function markLegacySettingsSent(): Promise<void> {
  await browser.storage.local.set({ [SENT_KEY]: true });
}

/** Snapshot the bag, each field salvaged by its own legacy schema (the same per-field validation the pre-cutover
 * enforcement applied, effective-policy.ts), so the bag is what the extension enforced, never raw storage bytes.
 * One divergence: disabledTools is bounded for the host's cap (boundBagDisabledTools). The literal is typed
 * LegacySettingsBag, so a policy field this mapping misses fails to compile. */
export async function readLegacySettingsBag(): Promise<LegacySettingsBag> {
  const bag = await browser.storage.local.get([...POLICY_FIELDS, "requireEnrollment"]);
  return {
    cdpMode: salvageLegacySetting("cdpMode", bag.cdpMode),
    fileUploadEnabled: salvageLegacySetting("fileUploadEnabled", bag.fileUploadEnabled),
    handleDialogEnabled: salvageLegacySetting("handleDialogEnabled", bag.handleDialogEnabled),
    pageEvalEnabled: salvageLegacySetting("pageEvalEnabled", bag.pageEvalEnabled),
    confirmHighRiskClick: salvageLegacySetting("confirmHighRiskClick", bag.confirmHighRiskClick),
    confirmPageEval: salvageLegacySetting("confirmPageEval", bag.confirmPageEval),
    touchIdConfirm: salvageLegacySetting("touchIdConfirm", bag.touchIdConfirm),
    confirmTabClose: salvageLegacySetting("confirmTabClose", bag.confirmTabClose),
    warnPreciseSnapshot: salvageLegacySetting("warnPreciseSnapshot", bag.warnPreciseSnapshot),
    evalMask: salvageLegacySetting("evalMask", bag.evalMask),
    hostReverifyMs: salvageLegacySetting("hostReverifyMs", bag.hostReverifyMs),
    confirmGraceMs: salvageLegacySetting("confirmGraceMs", bag.confirmGraceMs),
    clickToastTimeoutMs: salvageLegacySetting("clickToastTimeoutMs", bag.clickToastTimeoutMs),
    evalToastTimeoutMs: salvageLegacySetting("evalToastTimeoutMs", bag.evalToastTimeoutMs),
    disabledTools: boundBagDisabledTools(salvageLegacySetting("disabledTools", bag.disabledTools)),
    requireEnrollment: salvageLegacySetting("requireEnrollment", bag.requireEnrollment),
  };
}
