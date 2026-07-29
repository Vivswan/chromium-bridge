// The service-worker <-> content-script messaging contract, parsed with Zod
// on both sides of the boundary: the SW validates what it is about to send
// (backends/content-script.ts), the content script parses every inbound
// message before acting (lib/content/handle.ts), and the SW parses every
// reply (the same backend, plus background/precise.ts for the info toast).
//
// Page-ACTING ops carry a REQUIRED guard: the origin the allowlist check and
// any user confirmation were based on, and - for page_click - the exact
// target descriptor the user approved. The guard is the confirmation-to-act
// binding, so a message without it is refused outright; there is no
// "guard absent, skip the check" state. The only guard-less messages are the
// internal ops (ping / _info_toast / _probe_click), none of which act on the
// page.

import { z } from "zod";
import { OpArgsSchema } from "./ops.gen";

// What the SW probed before classifying (and confirming) a click. The page
// re-probes immediately before clicking and refuses if the target no longer
// matches. Kept in lockstep with the page API's ClickProbe; the extension's
// tests assert two-way type parity.
export const ClickProbeSchema = z.strictObject({
  tagName: z.string(),
  role: z.string(),
  type: z.string(),
  hasHref: z.boolean(),
  name: z.string(),
});

export type ClickProbeWire = z.infer<typeof ClickProbeSchema>;

// Every page-acting op must carry the origin its checks were based on.
export const PageOpGuardSchema = z.strictObject({
  expectOrigin: z.string().min(1),
});

// page_click additionally carries the approved target descriptor.
export const ClickGuardSchema = z.strictObject({
  expectOrigin: z.string().min(1),
  clickExpect: ClickProbeSchema,
});

// The informational in-page notice (NOT a confirmation surface).
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

// The SW -> content-script envelope, discriminated on op. page_screenshot is
// absent on purpose: it is captured in the SW and never reaches the page.
// The extension's roster test holds the guarded branches to exactly
// PAGE_OPS minus page_screenshot.
export const ContentMsgSchema = z.discriminatedUnion("op", [
  // Internal, guard-less ops. None of them act on the page: ping is the
  // injection probe, _info_toast shows a courtesy notice, and _probe_click is
  // the pre-approval DOM read whose result IS what the user then approves.
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

// The ops the content script only acts on under a guard.
export type GuardedContentOp = Extract<ContentMsg, { guard: unknown }>["op"];

// The content-script reply envelope, constructed at ONE place (the
// entrypoint's onMessage listener) and parsed once by every SW consumer.
// `data` may legitimately be undefined (an eval returning nothing), and a
// user cancellation travels as structured data ({ cancelled: true } from
// _info_toast), never as a falsy sentinel.
export const PageReplySchema = z.discriminatedUnion("ok", [
  z.strictObject({ ok: z.literal(true), data: z.unknown().optional() }),
  z.strictObject({ ok: z.literal(false), error: z.string() }),
]);

export type PageReply = z.infer<typeof PageReplySchema>;

// _info_toast's structured result: cancelled=true means the user actively
// cancelled the notice within its timeout.
export const InfoToastResultSchema = z.strictObject({
  cancelled: z.boolean(),
});

// The three shapes the page API's readStorage can produce. The SW's egress
// mask (background/egress.ts, ADR-0010) parses against this union and REFUSES
// anything else - a drifted shape must fail closed, not pass through raw.
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
