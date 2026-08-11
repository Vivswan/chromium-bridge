// Lane U of ADR-0032 Phase 3: the unpinned-machine window-approval surface.
// On an extension with NO pinned key, an unsigned `policy_current` push that
// would RELAX the enforced effective policy is held unapplied by policy-sync
// and handed to the approver registered here; this module turns that hold
// into one confirmation in the extension-owned off-DOM window (ADR-0027) -
// the same surface, queue, deadline, and fail-closed semantics as every
// other confirmation, and the same sender-gated resolve path (the router
// accepts the verdict only from the confirmation window itself).
//
// One approval per push, never blanket: each held push runs its own
// confirmWithUser round trip, and nothing here caches a verdict or opens a
// grace window. Decline (or timeout, or the window closing, or the SW dying
// mid-prompt) resolves false, policy-sync refuses the push, and the stored
// effective stays enforced - audit-visible through the confirmation
// service's confirm_shown/confirm_denied events (ADR-0030). Restrictions-
// or-equal never reach this module (policy-sync applies them free), and a
// PINNED extension never consults it at all: the no-downgrade rule refuses
// unsigned pushes before the approver seam is even considered.

import { POLICY_FIELDS, relaxedPolicyFields } from "@chromium-bridge/shared";
import { confirmWithUser, currentPanicEpoch } from "./confirm/service";
import { setUnpinnedRelaxationApprover, type UnpinnedRelaxation } from "./policy-sync";

// Generous but bounded: the prompt names a policy change, not a page action,
// and the push-on-connect replay means a missed prompt is re-offered on the
// next connection. Timeout denies (the service's fail-closed default).
export const POLICY_APPROVAL_TIMEOUT_MS = 120_000;

/** What the window shows as the contained payload. For a LATER document: the
 * relaxing fields' wire names, one per line, against the SAME anchor
 * policy-sync compares with - the stored effective - recomputed here from
 * Lane E's comparator (never trusted from the frame), so the window shows
 * exactly what the ratchet saw. For the FIRST document ever
 * (storedEffective null) there is no stored anchor that governs anything, so
 * the detail is the document's FULL value set, `field = value` per line
 * (U2): a diff against a fabricated anchor would lie - POLICY_DEFAULTS in
 * particular is the PERMISSIVE pole on hostReverifyMs (0 = never re-verify)
 * and disabledTools ([]), so a document that zeroes both would render as
 * "nothing relaxes" while relaxing exactly those fields. The user approving
 * the first document is adopting a whole policy (and arming the one-way
 * cutover); the window shows the whole policy. */
export function relaxationDetail(relaxation: UnpinnedRelaxation): string {
  if (relaxation.storedEffective === null) {
    return POLICY_FIELDS.map(
      (field) => `${field} = ${JSON.stringify(relaxation.effective[field])}`,
    ).join("\n");
  }
  return relaxedPolicyFields(relaxation.effective, relaxation.storedEffective).join("\n");
}

/** Install the Lane U approver into policy-sync's seam. Idempotent; called
 * once from the background entrypoint after the confirmation provider is
 * installed (a consultation before that would deny - fail closed, correct). */
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
      // Captured synchronously at this approval's own decision start (SFX-2):
      // a panic landing while the prompt waits denies on the epoch mismatch.
      panicEpoch: currentPanicEpoch(),
    }),
  );
}
