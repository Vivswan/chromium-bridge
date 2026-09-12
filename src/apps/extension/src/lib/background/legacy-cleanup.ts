// Deletes the retired legacy policy keys from browser.storage.local (ADR-0032 decision 8), but only once
// they can no longer be needed: pre-cutover the legacy arm in effective-policy.ts still reads them (an
// install whose host never lands an accepted push stays pre-cutover indefinitely), and an armed cutover with
// an unshipped bag can never ship it anymore, so deleting then would destroy the only copy of that missed migration.
//
//   cutover flag        -> must read exactly `true`
//   legacySettingsSent  -> must read exactly `true`, the only value markLegacySettingsSent writes; the
//                          send-once gate in legacy-import.ts reads ANY present value as sent (fail closed
//                          against a resend), deletion demands the exact value (fail safe keeps data)
//   anything else       -> delete nothing
//
// Startup sweep only, no storage.onChanged trigger: getEffectivePolicy resolves the posture and reads the
// legacy keys two awaits apart, so a mid-life deletion could interleave. In any SW life where the sweep
// deletes, the cutover was armed at startup and no posture resolution takes the legacy arm, so nothing
// reads what the deletion could race. A cutover arming mid-life is swept one SW life later at no cost.
// The versioned settings-migration ladder is not used: it is one-shot per install version, and this
// deletion depends on runtime facts.
//
// Deliberately kept: `legacySettingsSent` (absent means never sent, so deleting it re-opens the send-once
// gate), the browser-owned settings (settings.ts), and every policy-sync key.
// Residual: a forged `legacySettingsSent: true` landing in trusted-storage.ts's cold-start window on an
// armed install deletes a never-shipped bag; what is lost is the import screen's pre-fill, never a
// capability or an enforced value. A host that never reports `reason:"absent"` never ships a bag, so its
// keys linger, inert. Removing `cdpMode` fires the cdp teardown listener (cdp/registry.ts) once; teardown
// is restriction-only.

import { POLICY_FIELDS } from "@chromium-bridge/shared";
import { browser } from "wxt/browser";
import { LEGACY_SETTINGS_SENT_KEY } from "./legacy-import";
import { POLICY_CUTOVER_KEY } from "./policy-sync";
import { hardenStorageAccess } from "./trusted-storage";

/** The generated field catalogue, so a renamed policy field cannot leave a
 * stale key behind silently, plus the retired requireEnrollment. */
export const LEGACY_SETTINGS_KEYS: readonly string[] = [...POLICY_FIELDS, "requireEnrollment"];

/** Idempotent. Both flags come from one snapshot behind the storage-hardening
 * gate like every other trust-state reader; anything but the two exact
 * written values deletes NOTHING (module header). */
export async function cleanupLegacySettings(): Promise<void> {
  if (!(await hardenStorageAccess()).ok) return;
  const flags = await browser.storage.local.get([POLICY_CUTOVER_KEY, LEGACY_SETTINGS_SENT_KEY]);
  if (flags[POLICY_CUTOVER_KEY] !== true) return;
  if (flags[LEGACY_SETTINGS_SENT_KEY] !== true) return;
  await browser.storage.local.remove([...LEGACY_SETTINGS_KEYS]);
}

/** One sweep per SW life, no storage watch: startup-only is what closes the
 * read/delete race (module header). Failures are loud and non-blocking. */
export function installLegacyCleanup(): void {
  void cleanupLegacySettings().catch((e) => {
    console.warn("[bb] legacy settings cleanup failed", e);
  });
}
