// The ONE effective-policy resolution the enforcement sites consume.
// Post-cutover: the host-pushed, verified, ratcheted effective policy from
// policy-sync while ACTIVE. Pre-cutover (no host policy has ever been
// accepted): the deny baseline, POLICY_DEFAULTS.
//
// STATE-TYPED: a blocked posture (awaitingBaseline / compromised) is
// NOT consumable as policy values - the sum type carries a reason instead of
// a PolicyValues, so no caller can enforce against the deny-baseline
// defaults once a policy has applied. POLICY_DEFAULTS is consumable only
// pre-cutover, where nothing was ever accepted that the defaults could
// relax; after the cutover it only ever sits behind a refusing gate (the
// defaults are NOT the restrictive pole on every field). That invariant is
// held by this type, not by call-site discipline: dispatch refuses from its
// single read, the connect-path re-verification skips loudly, and the cdp
// teardown maps blocked to no-grant (restriction-only).
//
// Per-decision snapshot: every multi-read decision calls this ONCE at its
// start and completes under the returned values - dispatch snapshots per
// request and threads it through the confirmation gate, the SW-op handlers,
// and egress masking - so a policy push landing mid-confirmation can never
// relax, or otherwise alter, an in-flight decision. An accepted push applies
// from the next decision on.

import { POLICY_DEFAULTS, type PolicyValues } from "@chromium-bridge/shared/generated/policy";
import { unreachable } from "@chromium-bridge/shared/util";
import { getPolicyPosture } from "./policy-sync";

/** One immutable snapshot of the effective policy, resolved through the
 * cutover flag. `blocked` carries no values on purpose: enforcing anything
 * in that state - even the deny baseline - would be a decision the barrier
 * should have refused. */
export type EffectivePolicy =
  | { state: "preCutover"; values: PolicyValues }
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
    case "preCutover":
      return { state: "preCutover", values: POLICY_DEFAULTS };
    default:
      return unreachable(posture);
  }
}

/** A standalone decision entry point for callers OUTSIDE dispatch's
 * per-request threading (in practice: tests): take this decision's own
 * fresh snapshot and run `fn` entirely under it, refusing outright when the
 * posture is blocked. The enforcement sites take a REQUIRED PolicyValues
 * parameter, so the one-snapshot-per-decision invariant is held by their
 * signatures; this wrapper is the explicit way to start a new decision when
 * dispatch did not. */
export async function withFreshPolicy<T>(fn: (policy: PolicyValues) => Promise<T>): Promise<T> {
  const policy = await getEffectivePolicy();
  if (policy.state === "blocked") throw new Error(policy.reason);
  return fn(policy.values);
}
