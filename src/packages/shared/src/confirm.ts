// The off-DOM confirmation surface protocol (ADR-0027): what the service
// worker shows in the extension-owned confirmation window, and the two
// runtime messages the window exchanges with it.
//
// The whole point of this surface is that a guarded PAGE cannot reach it: the
// window is an extension page (chrome-extension:// origin, separate process),
// and the router additionally accepts confirm_ready / confirm_resolve ONLY
// from extension pages. A content script or page script can therefore
// neither read a pending confirmation nor answer one.
//
// Phase 8 (ADR-0031): ConfirmKind "eval" and "upload" are the two kinds whose
// authorization moves to the host's Secure-Enclave user-presence gate
// (Touch ID) on a capable, enrolled device. The surface stays as a
// display-only window; `hardware: true` marks such a payload, and the
// service refuses a window-side approval for it - the tap is the approval.
//
// The payload is a discriminated union on `kind`, each arm carrying exactly
// its own fields, so the combinations the service never produces cannot even
// parse: `hardware` exists only on the two presence-gated kinds (a
// `policy_relax` or `click` payload claiming hardware attestation is a
// schema error, not a rendering decision), and `policy_relax` - where no
// page is involved - pins origin/tabTitle to the empty string instead of
// merely defaulting them there.

import { z } from "zod";

export const ConfirmKindSchema = z.enum([
  "click", // a high-risk click (submit button / navigating link)
  "press", // a synthetic keypress (can submit or trigger)
  "select", // a <select> change (form state)
  "eval", // page_eval - arbitrary JS; detail carries the FULL code
  "tab_close", // closing a tab
  "upload", // page_upload - detail carries the exact local file path
  // ADR-0032 decision 3, the unpinned lane: an UNSIGNED host policy push
  // that would relax the enforced effective policy on an extension with no
  // pinned key. origin/tabTitle are "" (no page is involved); detail carries
  // the relaxing fields' wire names, one per line (possibly none: the
  // first-ever document always rides this lane even when it grants nothing
  // over the deny baseline). Never presented on a pinned extension.
  "policy_relax",
]);

export type ConfirmKind = z.infer<typeof ConfirmKindSchema>;

// The fields every arm carries.
const confirmCommon = {
  id: z.string().min(1),
  /** Auto-deny deadline, ms since epoch. The window renders a countdown and
   * the service worker enforces it regardless. */
  deadline: z.int().positive(),
} as const;

// The page-context fields of the six tool-call kinds.
const confirmPage = {
  /** Origin of the affected page ("" when not applicable). */
  origin: z.string(),
  /** Title of the affected tab ("" when not applicable). */
  tabTitle: z.string(),
  /** Action-specific detail: element description, keys, option value, the
   * full eval code, or the exact upload path. Rendered as text, never HTML. */
  detail: z.string(),
} as const;

/** ADR-0031: approval comes from the host's Enclave user-presence tap, not
 * the window. The window renders display-only (no Allow button) and the
 * service refuses a window-side approval; denial stays window-reachable
 * (removing capability is always friction-free). Only the two
 * presence-gated kinds ("eval"/"upload") may carry it, and only as the
 * literal `true`: the service never emits `hardware: false` (absence IS the
 * not-gated state), so the boolean's dead false arm is unrepresentable. */
const hardware = z.literal(true).optional();

export const ConfirmPayloadSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("click"), ...confirmCommon, ...confirmPage }),
  z.strictObject({ kind: z.literal("press"), ...confirmCommon, ...confirmPage }),
  z.strictObject({ kind: z.literal("select"), ...confirmCommon, ...confirmPage }),
  z.strictObject({ kind: z.literal("tab_close"), ...confirmCommon, ...confirmPage }),
  z.strictObject({ kind: z.literal("eval"), ...confirmCommon, ...confirmPage, hardware }),
  z.strictObject({ kind: z.literal("upload"), ...confirmCommon, ...confirmPage, hardware }),
  z.strictObject({
    kind: z.literal("policy_relax"),
    ...confirmCommon,
    /** No page is involved: the push arrives over the native-messaging
     * port, so the page-context fields are structurally empty rather than
     * conventionally empty. */
    origin: z.literal(""),
    tabTitle: z.literal(""),
    /** The relaxing fields' wire names, one per line - or, for the
     * first-ever document, the full `field = value` set (U2). */
    detail: z.string(),
  }),
]);

export type ConfirmPayload = z.infer<typeof ConfirmPayloadSchema>;

/** Whether this payload's approval belongs to the hardware tap (ADR-0031).
 * The union already confines `hardware` to the two presence-gated kinds;
 * this is the one place consumers read it, so the narrowing lives here
 * instead of at every call site. */
export function isHardwareGated(payload: ConfirmPayload): boolean {
  return (payload.kind === "eval" || payload.kind === "upload") && payload.hardware === true;
}
