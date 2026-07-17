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
// Phase 8 seam: ConfirmKind "eval" and "upload" are the two kinds whose
// authorization will move to the host's Secure-Enclave user-presence gate
// (Touch ID). The surface stays; only the approval mechanism behind it
// changes (see lib/background/confirm/provider.ts in the extension).

import { z } from "zod";

export const ConfirmKindSchema = z.enum([
  "click", // a high-risk click (submit button / navigating link)
  "press", // a synthetic keypress (can submit or trigger)
  "select", // a <select> change (form state)
  "eval", // page_eval - arbitrary JS; detail carries the FULL code
  "tab_close", // closing a tab
  "upload", // page_upload - detail carries the exact local file path
]);

export type ConfirmKind = z.infer<typeof ConfirmKindSchema>;

export const ConfirmPayloadSchema = z.strictObject({
  id: z.string().min(1),
  kind: ConfirmKindSchema,
  /** Origin of the affected page ("" when not applicable). */
  origin: z.string(),
  /** Title of the affected tab ("" when not applicable). */
  tabTitle: z.string(),
  /** Action-specific detail: element description, keys, option value, the
   * full eval code, or the exact upload path. Rendered as text, never HTML. */
  detail: z.string(),
  /** Auto-deny deadline, ms since epoch. The window renders a countdown and
   * the service worker enforces it regardless. */
  deadline: z.int().positive(),
});

export type ConfirmPayload = z.infer<typeof ConfirmPayloadSchema>;
