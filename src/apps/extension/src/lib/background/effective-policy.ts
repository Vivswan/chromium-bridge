// The ONE effective-policy resolution the enforcement sites consume (ADR-0032
// decision 8, Lane S). Post-cutover: the host-pushed, verified, ratcheted
// effective policy from policy-sync while ACTIVE. Pre-cutover: the legacy
// chrome.storage settings, salvaged field-by-field exactly as the
// pre-migration getSetting always did - the shipped legacy system,
// byte-for-byte, now read through the permanent legacy-settings module
// (settings.ts owns only the browser-owned fields since Phase 5).
//
// STATE-TYPED (SFX-1): a blocked posture (awaitingBaseline / compromised) is
// NOT consumable as policy values - the sum type carries a reason instead of
// a PolicyValues, so no caller can enforce against the deny-baseline
// defaults outside the dispatch barrier. The invariant "POLICY_DEFAULTS only
// ever behind a refusing gate" is held by this type, not by call-site
// discipline: dispatch refuses from its single read, the connect-path
// re-verification skips loudly, and the cdp teardown maps blocked to
// no-grant (restriction-only).
//
// Per-decision snapshot (ADR-0032 decision 4): every multi-read decision
// calls this ONCE at its start and completes under the returned values -
// dispatch snapshots per request and threads it through the confirmation
// gate, the SW-op handlers, and egress masking - so a policy push landing
// mid-confirmation can never relax, or otherwise alter, an in-flight
// decision. An accepted push applies from the next decision on.

import type { PolicyValues } from "@chromium-bridge/shared";
import { POLICY_FIELDS, salvageLegacySetting, unreachable } from "@chromium-bridge/shared";
import { browser } from "wxt/browser";
import { getPolicyPosture, POLICY_CUTOVER_KEY } from "./policy-sync";

/** One immutable snapshot of the effective policy, resolved through the
 * cutover flag. `blocked` carries no values on purpose: enforcing anything
 * in that state - even the deny baseline, which is NOT the restrictive pole
 * on every field - would be a decision the barrier should have refused. */
export type EffectivePolicy =
  | { state: "legacy"; values: PolicyValues }
  | { state: "active"; values: PolicyValues }
  | { state: "blocked"; reason: string };

/** Resolve the effective policy for the START of one decision. Callers
 * inside a multi-read decision must thread the values they started with
 * instead of calling again mid-decision. */
export async function getEffectivePolicy(): Promise<EffectivePolicy> {
  const posture = await getPolicyPosture();
  switch (posture.kind) {
    case "active":
      return { state: "active", values: posture.effective };
    case "blocked":
      return { state: "blocked", reason: posture.reason };
    case "legacy": {
      const values = await legacyPolicyValues();
      if (values === null) {
        // The cutover key appeared between the posture read above and the
        // legacy-keys read (a first accepted push arming mid-decision, or a
        // torn write). Belt-and-braces single-snapshot coherence: refuse
        // this decision fail-closed rather than enforce legacy values under
        // a cutover that has already begun; the next decision re-resolves
        // through the posture, which will read the flag itself.
        return {
          state: "blocked",
          reason:
            "the policy cutover flag appeared while resolving the legacy settings " +
            "(mid-decision arming); refusing this decision - the next one re-resolves " +
            "through the policy posture (ADR-0032 decision 4)",
        };
      }
      return { state: "legacy", values };
    }
    default:
      return unreachable(posture);
  }
}

/** A standalone decision entry point for callers OUTSIDE dispatch's
 * per-request threading (in practice: tests): take this decision's own
 * fresh snapshot and run `fn` entirely under it, refusing outright when the
 * posture is blocked. The enforcement sites take a REQUIRED PolicyValues
 * parameter, so the one-snapshot-per-decision invariant (ADR-0032 decision
 * 4) is held by their signatures; this wrapper is the explicit way to start
 * a new decision when dispatch did not. */
export async function withFreshPolicy<T>(fn: (policy: PolicyValues) => Promise<T>): Promise<T> {
  const policy = await getEffectivePolicy();
  if (policy.state === "blocked") throw new Error(policy.reason);
  return fn(policy.values);
}

/** The pre-cutover values: the 15 policy fields read from the legacy
 * settings bag under their (identical) legacy names, each salvaged by its
 * own legacy schema (legacy-settings.ts) - the exact per-field validation
 * the pre-migration getSetting applied, so pre-cutover behavior cannot
 * drift from what shipped. The cutover flag rides the SAME storage.get
 * (single-snapshot coherence): a flag present in the snapshot means the
 * legacy posture this decision started from is already stale, and `null`
 * tells the caller to refuse instead of enforcing legacy values
 * post-cutover. The object literal is typed PolicyValues, so a policy
 * field this mapping misses fails to compile. */
async function legacyPolicyValues(): Promise<PolicyValues | null> {
  const bag = await browser.storage.local.get([...POLICY_FIELDS, POLICY_CUTOVER_KEY]);
  if (bag[POLICY_CUTOVER_KEY] !== undefined) return null;
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
    disabledTools: salvageLegacySetting("disabledTools", bag.disabledTools),
  };
}
