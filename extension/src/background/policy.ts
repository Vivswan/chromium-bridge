// Policy layer (foundation, additive only).
//
// A PURE decision function that, given an op name and the current settings
// context, says whether the op is allowed and how it should be confirmed. It is
// derived entirely from TOOL_META (generated from contracts/tools.json) plus the
// user's disabledTools list — no chrome.* calls, no I/O, no import-time side
// effects — so it is trivially unit-testable and can be reused from anywhere.
//
// NOTE: this module is not yet wired into background/dispatch.ts. Wiring is a
// separate, supervised step; for now this is scaffolding.

import { TOOL_META, type Confirmation, type Risk } from "../shared/ops";

export type ConfirmationChannel = "page-toast" | "extension-ui" | "none";

export interface PolicyDecision {
  allowed: boolean;
  risk: Risk;
  requiresConfirmation: boolean;
  confirmationChannel: ConfirmationChannel;
  reason: string;
}

export interface PolicyContext {
  /** Op names the user has disabled in settings. */
  disabledTools: string[];
}

// Risk assigned to an op we have no metadata for. Treated as the most dangerous
// bucket so unknown ops fail closed.
const UNKNOWN_RISK: Risk = "critical";

/**
 * Map a tool's `confirmation` field to whether a call must be confirmed and via
 * which channel.
 *
 * - "none"                        → no confirmation
 * - "page-toast"                  → confirm, in-page toast
 * - "every-call" | "grace-window" → confirm, extension UI
 * - anything else (e.g. "high-risk", "warn") also requires confirmation and
 *   defaults to the extension UI channel (fail-safe for future contract values)
 */
function confirmationFor(confirmation: Confirmation): {
  requiresConfirmation: boolean;
  confirmationChannel: ConfirmationChannel;
} {
  switch (confirmation) {
    case "none":
      return { requiresConfirmation: false, confirmationChannel: "none" };
    case "page-toast":
      return { requiresConfirmation: true, confirmationChannel: "page-toast" };
    default:
      // "every-call", "grace-window", "high-risk", "warn", and any value added
      // to the contract later: require confirmation via the extension UI.
      return { requiresConfirmation: true, confirmationChannel: "extension-ui" };
  }
}

/**
 * Decide whether `op` may run given the current settings context.
 *
 * Pure: depends only on its arguments and the static TOOL_META table.
 */
export function decide(op: string, ctx: PolicyContext): PolicyDecision {
  const meta = TOOL_META[op];

  // Unknown op: fail closed.
  if (!meta) {
    return {
      allowed: false,
      risk: UNKNOWN_RISK,
      requiresConfirmation: true,
      confirmationChannel: "extension-ui",
      reason: "unknown tool",
    };
  }

  const { requiresConfirmation, confirmationChannel } = confirmationFor(meta.confirmation);

  // Disabled by the user in settings: not allowed, but still report the tool's
  // real risk/confirmation shape for UI purposes.
  if (ctx.disabledTools.includes(op)) {
    return {
      allowed: false,
      risk: meta.risk,
      requiresConfirmation,
      confirmationChannel,
      reason: "tool disabled in settings",
    };
  }

  return {
    allowed: true,
    risk: meta.risk,
    requiresConfirmation,
    confirmationChannel,
    reason: requiresConfirmation ? "allowed; requires confirmation" : "allowed",
  };
}
