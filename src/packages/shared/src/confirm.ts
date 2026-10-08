// What the service worker shows in the extension-owned confirmation window and the two runtime messages they
// exchange. A guarded PAGE cannot reach it: the window is an extension page (separate origin and process) and
// the router (background/messages.ts) accepts confirm_ready / confirm_resolve from the confirmation window alone.
//
// Each arm carries exactly its own fields, so a combination the service never produces fails to parse:
//   presence                      -> only on eval and upload, the kinds the host's presence exchange may answer
//                                    instead of Allow (the service's presenceRouting decides per request)
//   policy_relax origin, tabTitle -> pinned to "": no page is involved

import { z } from "zod";

export const ConfirmKindSchema = z.enum([
  "click",
  "press",
  "select",
  "eval", // detail carries the FULL code
  "tab_close",
  "upload", // detail carries the exact local file path
  // An UNSIGNED host push that would relax the enforced policy on an extension with no pinned key; never
  // presented on a pinned one. detail lists the relaxing fields' wire names one per line, or every field as
  // `name = value` for the first-ever document.
  "policy_relax",
]);

export type ConfirmKind = z.infer<typeof ConfirmKindSchema>;

const confirmCommon = {
  id: z.string().min(1),
  /** Auto-deny deadline, ms since epoch; the service worker enforces it whatever the window's countdown shows. */
  deadline: z.int().positive(),
} as const;

const confirmPage = {
  origin: z.string(),
  tabTitle: z.string(),
  /** Rendered as text, never HTML: it carries the full eval code or the exact upload path. */
  detail: z.string(),
} as const;

/** Approval for a presence-gated payload comes through the host's presence exchange, never the window's Allow;
 * denial stays window-reachable. Only the literal `true`: the service never emits `presence: false`, so absence
 * is the not-gated state and the false arm is unrepresentable. */
const presence = z.literal(true).optional();

export const ConfirmPayloadSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("click"), ...confirmCommon, ...confirmPage }),
  z.strictObject({ kind: z.literal("press"), ...confirmCommon, ...confirmPage }),
  z.strictObject({ kind: z.literal("select"), ...confirmCommon, ...confirmPage }),
  z.strictObject({ kind: z.literal("tab_close"), ...confirmCommon, ...confirmPage }),
  z.strictObject({ kind: z.literal("eval"), ...confirmCommon, ...confirmPage, presence }),
  z.strictObject({ kind: z.literal("upload"), ...confirmCommon, ...confirmPage, presence }),
  z.strictObject({
    kind: z.literal("policy_relax"),
    ...confirmCommon,
    /** The push arrives over the native-messaging port, so the page fields are structurally empty, not
     * conventionally. */
    origin: z.literal(""),
    tabTitle: z.literal(""),
    detail: z.string(),
  }),
]);

export type ConfirmPayload = z.infer<typeof ConfirmPayloadSchema>;

/** The one place consumers read `presence`, so the narrowing lives here and not at every call site. */
export function isPresenceGated(payload: ConfirmPayload): boolean {
  return (payload.kind === "eval" || payload.kind === "upload") && payload.presence === true;
}
