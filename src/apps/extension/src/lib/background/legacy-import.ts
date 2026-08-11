// The extension half of ADR-0032 decision 8 migration (Phase 4): the durable
// send-once flag for the `legacy_settings { bag }` frame, and the bag
// snapshot itself. policy-sync.ts owns WHEN the send may happen (the
// fail-closed pinned+proven gate on a reason:"absent" push); this module owns
// only the two durable facts, in the enclave-pin.ts single-key pattern
// (browser.storage.local, confined to extension contexts by
// trusted-storage.ts before any trust decision reads it).
//
// SEND-ONCE, EVER (the flag's reset semantics, decided here): once the bag
// has been posted, it is never posted again - the flag is cleared by NOTHING,
// not a pin revoke, not a re-pair, not a host-side key disposal. A re-send
// after disposal is exactly the replant vector the host's consumed tombstone
// (pending_import.rs) defends against, so the extension does not produce one
// either; the two sides refuse the same replay independently.
//
// Fail closed on ambiguity: ABSENT is the only "never sent" signal, and any
// present value - `true`, garbage, a tampered shape - reads as SENT, so a
// tamperer cannot flip the flag's MEANING. Deleting the key outright IS
// indistinguishable from never-sent and would allow a resend; that residual
// is bounded, not erased: the flag lives in TRUSTED_CONTEXTS-hardened
// storage (trusted-storage.ts), which content scripts cannot write once the
// restriction is applied - trusted-storage.ts names the residual cold-start
// window before setAccessLevel resolves in which storage.local is briefly
// still content-script-writable, and the send gate re-awaits
// hardenStorageAccess fail-closed before reading the flag - and a forced
// resend still faces the full pinned+proven send gate (policy-sync.ts) and
// the host's first-bag-wins consumed tombstone (pending_import.rs): it can
// neither reach an unproven host nor replant a forged bag.

import { POLICY_FIELDS, type PolicyValues, salvageSetting } from "@chromium-bridge/shared";
import { browser } from "wxt/browser";

const SENT_KEY = "legacySettingsSent";

/** The bag `legacy_settings` carries: the 15 legacy policy fields (the
 * migration source the app's first-run import screen signs into revision 1)
 * plus `requireEnrollment`, which decision 8 retires but keeps as history in
 * the snapshot. Deliberately NOT the whole Settings object: the browser-owned
 * fields (allowlist projections, groupTabs) never become policy and
 * `uiLanguage` rides its own lane (decision 7), so the host has no use for
 * them - minimize what crosses the boundary to what migration needs. */
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

/** Snapshot the legacy bag from chrome.storage, each field salvaged by its
 * own legacy schema - the same per-field validation the pre-cutover
 * enforcement read (effective-policy.ts legacyPolicyValues) applies, so the
 * bag is exactly the settings the extension has been enforcing, never raw
 * storage bytes. The object literal is typed LegacySettingsBag, so a policy
 * field this mapping misses fails to compile. */
export async function readLegacySettingsBag(): Promise<LegacySettingsBag> {
  const bag = await browser.storage.local.get([...POLICY_FIELDS, "requireEnrollment"]);
  return {
    cdpMode: salvageSetting("cdpMode", bag.cdpMode),
    fileUploadEnabled: salvageSetting("fileUploadEnabled", bag.fileUploadEnabled),
    handleDialogEnabled: salvageSetting("handleDialogEnabled", bag.handleDialogEnabled),
    pageEvalEnabled: salvageSetting("pageEvalEnabled", bag.pageEvalEnabled),
    confirmHighRiskClick: salvageSetting("confirmHighRiskClick", bag.confirmHighRiskClick),
    confirmPageEval: salvageSetting("confirmPageEval", bag.confirmPageEval),
    touchIdConfirm: salvageSetting("touchIdConfirm", bag.touchIdConfirm),
    confirmTabClose: salvageSetting("confirmTabClose", bag.confirmTabClose),
    warnPreciseSnapshot: salvageSetting("warnPreciseSnapshot", bag.warnPreciseSnapshot),
    evalMask: salvageSetting("evalMask", bag.evalMask),
    hostReverifyMs: salvageSetting("hostReverifyMs", bag.hostReverifyMs),
    confirmGraceMs: salvageSetting("confirmGraceMs", bag.confirmGraceMs),
    clickToastTimeoutMs: salvageSetting("clickToastTimeoutMs", bag.clickToastTimeoutMs),
    evalToastTimeoutMs: salvageSetting("evalToastTimeoutMs", bag.evalToastTimeoutMs),
    disabledTools: salvageSetting("disabledTools", bag.disabledTools),
    requireEnrollment: salvageSetting("requireEnrollment", bag.requireEnrollment),
  };
}
