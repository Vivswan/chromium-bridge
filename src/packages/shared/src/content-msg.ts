// Parsed with Zod on both sides: the SW validates what it sends (backends/content-script.ts), the content
// script parses every inbound message (lib/content/handle.ts), and the SW parses every reply (the same backend,
// plus background/precise.ts).
//
// Page-acting ops carry a REQUIRED guard, the origin the allowlist check and any confirmation were based on (for
// page_click also the approved target), so a message without one is refused: there is no "guard absent, skip
// the check" state.

import { z } from "zod";
import { OpArgsSchema } from "../generated/ops";

// The SW probes before classifying a click; the page re-probes before clicking and refuses a changed target.
// Kept in lockstep with the page API's ClickProbe (the extension's handle.test.ts assigns each to the other).
export const ClickProbeSchema = z.strictObject({
  tagName: z.string(),
  role: z.string(),
  type: z.string(),
  hasHref: z.boolean(),
  name: z.string(),
});

export type ClickProbeWire = z.infer<typeof ClickProbeSchema>;

export const PageOpGuardSchema = z.strictObject({
  expectOrigin: z.string().min(1),
});

export const ClickGuardSchema = z.strictObject({
  expectOrigin: z.string().min(1),
  clickExpect: ClickProbeSchema,
});

// NOT a confirmation surface.
const InfoToastArgsSchema = z.strictObject({
  message: z.string(),
  cancelLabel: z.string().optional(),
});

function guardedOp<O extends string>(op: O) {
  return z.strictObject({
    op: z.literal(op),
    args: OpArgsSchema,
    tabId: z.int().optional(),
    guard: PageOpGuardSchema,
  });
}

// page_screenshot is absent on purpose: captured in the SW, it never reaches the page (the extension's
// rosters.test.ts holds the guarded branches to PAGE_OPS minus it).
export const ContentMsgSchema = z.discriminatedUnion("op", [
  // None of these act on the page; _probe_click's result IS what the user then approves.
  z.strictObject({ op: z.literal("ping") }),
  z.strictObject({ op: z.literal("_info_toast"), args: InfoToastArgsSchema }),
  z.strictObject({
    op: z.literal("_probe_click"),
    args: OpArgsSchema,
    tabId: z.int().optional(),
  }),
  z.strictObject({
    op: z.literal("page_click"),
    args: OpArgsSchema,
    tabId: z.int().optional(),
    guard: ClickGuardSchema,
  }),
  guardedOp("page_snapshot"),
  guardedOp("page_fill"),
  guardedOp("page_text"),
  guardedOp("page_scroll"),
  guardedOp("page_wait_for"),
  guardedOp("page_eval"),
  guardedOp("storage_get"),
  guardedOp("page_press"),
  guardedOp("page_hover"),
  guardedOp("page_select"),
]);

export type ContentMsg = z.infer<typeof ContentMsgSchema>;

export type GuardedContentOp = Extract<ContentMsg, { guard: unknown }>["op"];

// Constructed at ONE place (the entrypoint's onMessage listener). `data` may be undefined (an eval returning
// nothing); a cancellation travels as structured data ({ cancelled: true } from _info_toast), never a falsy
// sentinel.
export const PageReplySchema = z.discriminatedUnion("ok", [
  z.strictObject({ ok: z.literal(true), data: z.unknown().optional() }),
  z.strictObject({ ok: z.literal(false), error: z.string() }),
]);

export type PageReply = z.infer<typeof PageReplySchema>;

export const InfoToastResultSchema = z.strictObject({
  cancelled: z.boolean(),
});

// The three shapes readStorage produces; the egress mask (background/egress.ts) refuses anything else, so a
// drifted shape fails closed.
export const StorageReadResultSchema = z.union([
  z.strictObject({ key: z.string(), found: z.literal(false) }),
  z.strictObject({ key: z.string(), found: z.literal(true), value: z.string() }),
  z.strictObject({
    type: z.string(),
    entries: z.record(z.string(), z.string()),
    count: z.int(),
    truncated: z.boolean(),
    totalKeys: z.int(),
  }),
]);

export type StorageReadResultWire = z.infer<typeof StorageReadResultSchema>;
