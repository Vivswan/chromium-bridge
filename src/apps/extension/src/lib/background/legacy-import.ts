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

import {
  DISABLED_TOOL_NAME_MAX_BYTES,
  DISABLED_TOOLS_MAX_ENTRIES,
  POLICY_FIELDS,
  type PolicyValues,
  salvageLegacySetting,
} from "@chromium-bridge/shared";
import { browser } from "wxt/browser";

/** The send-once flag's storage key. Exported ONLY for the Phase 5 legacy
 * cleanup (legacy-cleanup.ts), which reads it as a deletion PRECONDITION
 * (bag shipped) and never writes or deletes it; the flag's semantics stay
 * owned here. */
export const LEGACY_SETTINGS_SENT_KEY = "legacySettingsSent";
const SENT_KEY = LEGACY_SETTINGS_SENT_KEY;

/** Bag-site bound on disabledTools (the ONLY unbounded legacy field). The
 * host drops a `legacy_settings` bag whose compact serialization exceeds its
 * 64 KiB cap (pending_import.rs LEGACY_BAG_MAX_BYTES) - WHOLE, after the
 * extension has already latched send-once - so a pathological stored list
 * must be bounded before it rides the wire. Bounded HERE and only here: the
 * enforcement salvage (legacy-settings.ts) stays byte-identical to the old
 * schema because truncating a deny-list is the permissive direction there,
 * while the bag is a migration suggestion the user reviews and signs, never
 * enforcement - dropping an entry costs a line on the import screen, no
 * capability.
 *
 * Measured honestly in SERIALIZED BYTES (TextEncoder over JSON.stringify),
 * the unit the host's cap counts: UTF-16 code-unit lengths undercount
 * non-ASCII up to ~3x and ignore escape inflation. Caps from the generated
 * policy contract: entries whose serialized form exceeds
 * DISABLED_TOOL_NAME_MAX_BYTES (128 - no real op name comes near it) drop
 * individually, and the list is cut at DISABLED_TOOLS_MAX_ENTRIES (256).
 * Worst case: 256 entries x 128 bytes + separators, about 33 KiB - under
 * the 64 KiB cap with the 15 scalar fields' few hundred bytes to spare. */
function boundBagDisabledTools(list: readonly string[]): string[] {
  const encoder = new TextEncoder();
  return list
    .filter((entry) => encoder.encode(JSON.stringify(entry)).length <= DISABLED_TOOL_NAME_MAX_BYTES)
    .slice(0, DISABLED_TOOLS_MAX_ENTRIES);
}

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
 * own legacy schema (legacy-settings.ts) - the same per-field validation the
 * pre-cutover enforcement read (effective-policy.ts legacyPolicyValues)
 * applies, so the bag is the settings the extension has been enforcing,
 * never raw storage bytes - with ONE deliberate divergence: disabledTools is
 * additionally bounded here to fit the host's bag cap
 * (boundBagDisabledTools above; enforcement stays unbounded). The object
 * literal is typed LegacySettingsBag, so a policy field this mapping misses
 * fails to compile. */
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
