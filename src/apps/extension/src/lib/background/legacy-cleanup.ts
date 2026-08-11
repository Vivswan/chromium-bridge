// The Phase 5 legacy-settings storage cleanup (ADR-0032 decision 8: "the
// legacy fields themselves are deleted from chrome.storage only in the
// cleanup phase, after the import path has shipped"). The 15 retired policy
// keys plus `requireEnrollment` are deleted from browser.storage.local only
// when BOTH durable facts hold, read from ONE storage snapshot:
//   - the one-way cutover has ARMED (exactly `true`): pre-cutover the legacy
//     enforcement arm (effective-policy.ts) still reads these keys, and a
//     non-macOS install stays pre-cutover forever and must keep its values;
//   - the legacy bag has SHIPPED (legacySettingsSent reads exactly `true`,
//     the only value markLegacySettingsSent ever writes). This is the ADR's
//     own condition: cutover arms BEFORE the record write (policy-sync.ts)
//     and the bag ships only pre-cutover, so an armed cutover with an unsent
//     bag means the bag can never ship anymore - deleting the keys then
//     would turn that missed migration from "latent in storage" into
//     permanent destruction of the only copy.
//
// Note the deliberately DIFFERENT reads of the sent flag by consumer: for
// the send-once gate any present value reads sent (fail closed against a
// resend); for deletion only the exact written value warrants destroying
// data (fail safe keeps it on ambiguity). Neither flag is more than an
// unauthenticated storage.local value - #32 hardening confines who can write
// it, minus the named cold-start window (trusted-storage.ts) - so the
// hardening gate below plus the keep-data-on-anything-unexpected posture is
// what bounds a tampered value to "the inert keys linger", never to a
// deletion that costs enforcement. The residual write that CAN delete: a
// forged legacySettingsSent:true landing in that cold-start window on an
// armed install deletes a never-shipped bag - what is lost is the import
// screen's pre-fill (the user signs revision 1 from scratch), never a
// capability or an enforced value.
//
// The versioned settings-migration ladder is deliberately NOT used: it is
// one-shot per install version, while this deletion is conditional on
// runtime facts that can flip at any moment of any SW life.
//
// STARTUP SWEEP ONLY, no storage.onChanged trigger - the read/delete race is
// closed by construction, not patched: getEffectivePolicy resolves the
// posture and only then reads the legacy keys (two awaits apart), so a
// mid-life deletion could interleave between them. With deletion happening
// only at SW startup, no legacy read can ever observe it: in any SW life
// where the sweep deletes (cutover armed at startup), every posture
// resolution in that same life reads the armed flag and never takes the
// legacy arm, so the legacy keys are read by nothing the deletion could
// race. Post-cutover the keys are inert (no reader consults them once the
// posture is not legacy), so a cutover arming mid-life is swept one SW life
// later at no cost.
//
// Accepted residual, named: an install whose host never reports
// `reason:"absent"` (an old host, or one that already had a policy store)
// never ships a bag, so its legacy keys linger forever - inert, never
// enforced, acceptable.
//
// WHAT IS DELIBERATELY NOT DELETED:
// - the `legacySettingsSent` send-once flag: ABSENT means "never sent", so
//   deleting it would re-open the send-once gate - the replant vector both
//   sides refuse;
// - the browser-owned settings (settings.ts) and every policy-sync key.
//
// The one observable side effect is bounded: removing `cdpMode` fires the
// cdp teardown listener (cdp/registry.ts) once, which is restriction-only.

import { POLICY_FIELDS } from "@chromium-bridge/shared";
import { browser } from "wxt/browser";
import { LEGACY_SETTINGS_SENT_KEY } from "./legacy-import";
import { POLICY_CUTOVER_KEY } from "./policy-sync";
import { hardenStorageAccess } from "./trusted-storage";

/** The retired keys: the 15 migrated policy fields (the generated catalogue,
 * so a renamed field cannot leave a stale key behind silently) plus the
 * retired requireEnrollment. */
export const LEGACY_SETTINGS_KEYS: readonly string[] = [...POLICY_FIELDS, "requireEnrollment"];

/** Delete the retired legacy keys IFF the cutover flag reads exactly armed
 * AND the legacy bag has shipped (module header). Idempotent; reads both
 * flags itself from one snapshot, behind the #32 storage-hardening gate like
 * every other trust-state reader. Anything but the two exact written values
 * deletes NOTHING - the fail-safe here is to keep data. */
export async function cleanupLegacySettings(): Promise<void> {
  if (!(await hardenStorageAccess()).ok) return;
  const flags = await browser.storage.local.get([POLICY_CUTOVER_KEY, LEGACY_SETTINGS_SENT_KEY]);
  if (flags[POLICY_CUTOVER_KEY] !== true) return;
  if (flags[LEGACY_SETTINGS_SENT_KEY] !== true) return;
  await browser.storage.local.remove([...LEGACY_SETTINGS_KEYS]);
}

/** Wire the cleanup: ONE startup sweep per SW life, no storage watch (module
 * header: startup-only is what closes the read/delete race by construction;
 * a cutover arming mid-life is swept on the next SW start instead, which
 * costs tidiness for one SW life, never enforcement). Failures are loud and
 * non-blocking. */
export function installLegacyCleanup(): void {
  void cleanupLegacySettings().catch((e) => {
    console.warn("[bb] legacy settings cleanup failed", e);
  });
}
