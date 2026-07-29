// Policy layer (foundation, additive only).
//
// A PURE decision function that, given an op name and the current settings
// context, says whether the op is allowed and how it should be confirmed. It is
// derived entirely from TOOL_META (generated from the Rust catalogue) plus the
// user's disabledTools list - no chrome.* calls, no I/O, no import-time side
// effects - so it is trivially unit-testable and can be reused from anywhere.
//
// NOTE: only the disable gate (dispatch.assertNotDisabled) is wired into
// background/dispatch.ts so far. Wiring the rest is a separate, supervised
// step.

import { type Confirmation, isOpName, type Risk, TOOL_META } from "@chromium-bridge/shared";

/** How a call must be confirmed, as one value: "required over no channel"
 * (and its inverse) are unrepresentable. Since ADR-0027 every confirmation
 * shows on the extension-owned surface, so that is the only channel. */
export type PolicyConfirmation = { required: false } | { required: true; channel: "extension-ui" };

/** Why a call was refused, as a closed union. Refusal behavior downstream
 * keys on this, never on the display `reason` - rewording prose must not be
 * able to change what a gate does. */
export type RefusalCause = "unknown-tool" | "disabled-in-settings";

export type PolicyDecision =
  | { allowed: true; risk: Risk; confirmation: PolicyConfirmation; reason: string }
  | {
      allowed: false;
      cause: RefusalCause;
      risk: Risk;
      confirmation: PolicyConfirmation;
      reason: string;
    };

export interface PolicyContext {
  /** Op names the user has disabled in settings. */
  disabledTools: string[];
}

// Risk assigned to an op we have no metadata for. Treated as the most dangerous
// bucket so unknown ops fail closed.
const UNKNOWN_RISK: Risk = "critical";

/**
 * Map a tool's `confirmation` field to how a call must be confirmed.
 *
 * - "none"      -> no confirmation
 * - everything else ("every-call", "high-risk", "warn", and any value added
 *   to the contract later) -> confirm via the extension UI (fail-safe).
 */
function confirmationFor(confirmation: Confirmation): PolicyConfirmation {
  switch (confirmation) {
    case "none":
      return { required: false };
    default:
      return { required: true, channel: "extension-ui" };
  }
}

/**
 * Decide whether `op` may run given the current settings context.
 *
 * Pure: depends only on its arguments and the static TOOL_META table. The
 * `reason` on every branch is derived display text; consumers act on
 * `allowed`/`cause`/`confirmation`, never on the prose.
 */
export function decide(op: string, ctx: PolicyContext): PolicyDecision {
  const meta = isOpName(op) ? TOOL_META[op] : undefined;

  // Unknown op: fail closed.
  if (!meta) {
    return {
      allowed: false,
      cause: "unknown-tool",
      risk: UNKNOWN_RISK,
      confirmation: { required: true, channel: "extension-ui" },
      reason: "unknown tool",
    };
  }

  const confirmation = confirmationFor(meta.confirmation);

  // Disabled by the user in settings: not allowed, but still report the tool's
  // real risk/confirmation shape for UI purposes.
  if (ctx.disabledTools.includes(op)) {
    return {
      allowed: false,
      cause: "disabled-in-settings",
      risk: meta.risk,
      confirmation,
      reason: "tool disabled in settings",
    };
  }

  return {
    allowed: true,
    risk: meta.risk,
    confirmation,
    reason: confirmation.required ? "allowed; requires confirmation" : "allowed",
  };
}
