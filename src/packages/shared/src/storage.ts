// Shapes for the remaining chrome.storage.local records the extension reads
// back at runtime. Storage is same-extension-private but still an input: a
// corrupted or unexpectedly-shaped record must degrade to a safe default,
// never be interpreted as-is.

import { z } from "zod";

// The user's origin allowlist: an array of origin globs. A read that fails
// this schema degrades to [] (nothing allowed) - fail closed.
export const AllowlistSchema = z.array(z.string().min(1));

// One pending origin-approval request surfaced to the popup. `expiresAt` is
// the auto-deny deadline the service worker armed; a record orphaned by a
// worker restart (its resolver died with the worker) ages out of the popup
// at that deadline instead of ghosting forever.
export const PendingApprovalSchema = z.strictObject({
  id: z.string().min(1),
  glob: z.string().min(1),
  expiresAt: z.number(),
});

// The whole outstanding collection, oldest first: the persisted mirror of
// the service worker's resolver map, written as ONE record so concurrent
// prompts cannot shadow each other.
export const PendingApprovalsSchema = z.array(PendingApprovalSchema);

export type PendingApproval = z.infer<typeof PendingApprovalSchema>;
