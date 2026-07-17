// Shapes for the remaining chrome.storage.local records the extension reads
// back at runtime. Storage is same-extension-private but still an input: a
// corrupted or unexpectedly-shaped record must degrade to a safe default,
// never be interpreted as-is.

import { z } from "zod";

// The user's origin allowlist: an array of origin globs. A read that fails
// this schema degrades to [] (nothing allowed) - fail closed.
export const AllowlistSchema = z.array(z.string().min(1));

// A pending origin-approval request surfaced to the popup.
export const PendingAllowSchema = z.strictObject({
  id: z.string().min(1),
  glob: z.string().min(1),
});

export type PendingAllow = z.infer<typeof PendingAllowSchema>;
