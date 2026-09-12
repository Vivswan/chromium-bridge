// The unpinned-machine window-approval surface (ADR-0032). On an extension with NO pinned key, an
// unsigned `policy_current` push that would RELAX the enforced effective policy (or is the first document ever)
// is held unapplied by policy-sync and handed to the approver registered here, which turns it into one
// confirmation in the extension-owned off-DOM window (ADR-0027): the same queue, deadline, fail-closed
// semantics, and sender-gated resolve path as every other confirmation.
//   restriction-or-equal push, active anchor stored      -> never reaches this module (policy-sync applies it free)
//   first document ever (no active anchor)               -> held here even when it only restricts
//   PINNED extension                                     -> never consults it (the no-downgrade rule refuses unsigned pushes first)
//   decline, timeout, window closed, SW death mid-prompt -> false; policy-sync refuses the push, the stored effective stays enforced
// One approval per push, never blanket: nothing here caches a verdict or opens a grace window, and every
// round trip is audit-visible through the service's confirm_shown/confirm_denied events (ADR-0030).

import { POLICY_FIELDS, relaxedPolicyFields } from "@chromium-bridge/shared";
import { confirmWithUser, currentPanicEpoch } from "./confirm/service";
import { setUnpinnedRelaxationApprover, type UnpinnedRelaxation } from "./policy-sync";

// Generous but bounded: the prompt names a policy change, not a page action,
// and the push-on-connect replay means a missed prompt is re-offered on the
// next connection. Timeout denies (the service's fail-closed default).
export const POLICY_APPROVAL_TIMEOUT_MS = 120_000;

/** The detail the window shows, recomputed here with the same comparator policy-sync uses (never trusted
 * from the frame), so the window shows exactly what the ratchet saw.
 *   later document (storedEffective set)   -> the relaxing fields' wire names, one per line, against the stored effective
 *   first document (storedEffective null)  -> the FULL value set, `field = value` per line: approving it adopts a whole policy
 * A diff against a fabricated anchor would lie: POLICY_DEFAULTS is the PERMISSIVE pole on hostReverifyMs
 * (0 = never re-verify) and disabledTools ([]), so a document zeroing both would read as "nothing relaxes"
 * while relaxing exactly those fields. */
export function relaxationDetail(relaxation: UnpinnedRelaxation): string {
  if (relaxation.storedEffective === null) {
    return POLICY_FIELDS.map(
      (field) => `${field} = ${JSON.stringify(relaxation.effective[field])}`,
    ).join("\n");
  }
  return relaxedPolicyFields(relaxation.effective, relaxation.storedEffective).join("\n");
}

/** Install the approver into policy-sync's seam. Idempotent; called once from the background entrypoint
 * after the confirmation provider is installed (a consultation before that would deny: fail closed, correct). */
export function registerUnpinnedRelaxationApprover(): void {
  setUnpinnedRelaxationApprover((relaxation) =>
    confirmWithUser({
      kind: "policy_relax",
      // No page is involved: the push comes over the native-messaging port.
      origin: "",
      tabTitle: "",
      detail: relaxationDetail(relaxation),
      timeoutMs: POLICY_APPROVAL_TIMEOUT_MS,
      // NEVER presence-routed (anti-overclaim): the verdict on an UNSIGNED
      // push must render as an app confirmation, not as anything resembling
      // hardware attestation of the (unproven) host.
      presenceRouting: false,
      // Captured synchronously at this approval's own decision start: a panic landing while the
      // prompt waits denies on the epoch mismatch.
      panicEpoch: currentPanicEpoch(),
    }),
  );
}
