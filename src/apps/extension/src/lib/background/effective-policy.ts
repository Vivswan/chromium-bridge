// The ONE effective-policy resolution the enforcement sites consume (ADR-0032
// decision 8, Lane S). Post-cutover: the host-pushed, verified, ratcheted
// effective policy from policy-sync while ACTIVE. Pre-cutover: the legacy
// chrome.storage settings, salvaged field-by-field exactly as getSetting
// always did - today's system, byte-for-byte. settings.ts stays untouched as
// the owner of the browser-owned fields and keeps carrying the legacy policy
// fields until Phase 5 slims it.
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
import { POLICY_FIELDS, salvageSetting, unreachable } from "@chromium-bridge/shared";
import { browser } from "wxt/browser";
import { getPolicyPosture } from "./policy-sync";

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
    case "legacy":
      return { state: "legacy", values: await legacyPolicyValues() };
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
 * own legacy schema - the exact per-field validation getSetting applied, so
 * pre-cutover behavior cannot drift from today's. The object literal is
 * typed PolicyValues, so a policy field this mapping misses (or Phase 5
 * removing a legacy field out from under it) fails to compile. */
async function legacyPolicyValues(): Promise<PolicyValues> {
  const bag = await browser.storage.local.get([...POLICY_FIELDS]);
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
  };
}
