// The runtime-message contract between the extension's pages and its service
// worker. Every message declares its request, its response, and which sender
// may issue it, in one table, and the gate refusal is an arm of every
// response: a sender gets the declared answer or `{ ok: false, error }`, never
// silence and never an undeclared shape.

import { z } from "zod";
import { ConfirmPayloadSchema } from "./confirm";
import { AuditEntrySchema, KillMirrorSchema } from "./enclave";
import { TrustedClientSchema } from "./envelope.gen";
import { UI_LANGUAGES } from "./settings";

/** The answer to a message the sender was not allowed to issue, a message the
 * router could not parse, or a handler that failed: the one failure shape. */
export const RefusalSchema = z.object({ ok: z.literal(false), error: z.string() });

export type Refusal = z.infer<typeof RefusalSchema>;

// Who may send a message. The router enforces this with the sender's URL:
// extension-page is any chrome-extension://<our-id>/ page, confirm-window is
// /confirm.html alone, so a content script (which carries the page's http(s)
// URL) is refused everything.
export type RuntimeGate = "extension-page" | "confirm-window";

const Acknowledged = z.object({ ok: z.literal(true) });

const enrollmentBase = {
  ok: z.literal(true),
  // False on platforms without a Secure Enclave, where the gate never blocks.
  platformSupported: z.boolean(),
  lastError: z.string().optional(),
  paused: z.boolean().optional(),
  // An unpair's host-key deletion is still awaiting the next host connection.
  hostRevokePending: z.boolean().optional(),
};

const pinIdentity = { keyId: z.string(), fingerprint: z.string() };

export const EnrollmentStatusSchema = z.union([
  z.object({ ...enrollmentBase, state: z.literal("unpaired"), blocked: z.boolean() }),
  z.object({
    ...enrollmentBase,
    state: z.literal("pending"),
    blocked: z.boolean(),
    ...pinIdentity,
  }),
  z.object({
    ...enrollmentBase,
    state: z.literal("pinned"),
    blocked: z.literal(false),
    ...pinIdentity,
    pinnedAt: z.number(),
    lastVerifiedAt: z.number().optional(),
  }),
  z.object({
    ...enrollmentBase,
    state: z.literal("compromised"),
    blocked: z.literal(true),
    compromisedReason: z.string(),
    ...pinIdentity,
  }),
  z.object({
    ...enrollmentBase,
    state: z.literal("compromised"),
    blocked: z.literal(true),
    compromisedReason: z.string(),
    keyId: z.undefined().optional(),
    fingerprint: z.undefined().optional(),
  }),
]);

export type EnrollmentStatus = z.infer<typeof EnrollmentStatusSchema>;

// The kill switch's answer: the exchange outcome plus the last-known mirror.
// `sent` false means the frame never reached the pipe; absent or true means
// the host may still apply it even when `ok` is false, so only an explicit
// false may be read as "nothing is in flight".
export const KillViewSchema = z.object({
  ok: z.boolean(),
  sent: z.boolean().optional(),
  state: KillMirrorSchema.shape.state.optional(),
  at: z.number().optional(),
  error: z.string().optional(),
});

export type KillView = z.infer<typeof KillViewSchema>;

interface ContractEntry<K extends string> {
  gate: RuntimeGate;
  req: z.ZodType<{ type: K }>;
  res: z.ZodType;
}

function contract<T extends { [K in keyof T]: ContractEntry<K & string> }>(table: T): T {
  return table;
}

export const RUNTIME_CONTRACT = contract({
  resolve_allow: {
    gate: "extension-page",
    req: z.strictObject({
      type: z.literal("resolve_allow"),
      id: z.string().min(1),
      allow: z.boolean(),
    }),
    res: Acknowledged,
  },
  get_allowlist: {
    gate: "extension-page",
    req: z.strictObject({ type: z.literal("get_allowlist") }),
    res: z.object({ ok: z.literal(true), list: z.array(z.string()) }),
  },
  add_allow: {
    gate: "extension-page",
    req: z.strictObject({ type: z.literal("add_allow"), glob: z.string().min(1) }),
    res: z.object({ ok: z.literal(true), list: z.array(z.string()) }),
  },
  remove_allow: {
    gate: "extension-page",
    req: z.strictObject({ type: z.literal("remove_allow"), glob: z.string().min(1) }),
    res: z.object({
      ok: z.literal(true),
      list: z.array(z.string()),
      permissionRemoved: z.boolean(),
      permissionError: z.string().optional(),
    }),
  },
  get_status: {
    gate: "extension-page",
    req: z.strictObject({ type: z.literal("get_status") }),
    res: z.object({ ok: z.literal(true), nativeConnected: z.boolean() }),
  },
  get_enrollment: {
    gate: "extension-page",
    req: z.strictObject({ type: z.literal("get_enrollment") }),
    res: EnrollmentStatusSchema,
  },
  // The trusted-client admin surface is relayed to the host as control frames.
  // The name is validated like a host-side label so a malformed value never
  // reaches the wire.
  get_clients: {
    gate: "extension-page",
    req: z.strictObject({ type: z.literal("get_clients") }),
    res: z.object({
      ok: z.literal(true),
      enrolled: z.boolean(),
      clients: z.array(TrustedClientSchema),
    }),
  },
  revoke_client: {
    gate: "extension-page",
    req: z.strictObject({
      type: z.literal("revoke_client"),
      name: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/),
    }),
    res: Acknowledged,
  },
  get_kill: {
    gate: "extension-page",
    req: z.strictObject({ type: z.literal("get_kill") }),
    res: KillViewSchema,
  },
  // Engage-only by shape: the host refuses a release from the extension
  // (release lives in the CLI), so `on` is pinned to true and a release
  // cannot even be expressed at this boundary.
  set_kill: {
    gate: "extension-page",
    req: z.strictObject({ type: z.literal("set_kill"), on: z.literal(true) }),
    res: KillViewSchema,
  },
  get_audit: {
    gate: "extension-page",
    req: z.strictObject({ type: z.literal("get_audit") }),
    res: z.object({ ok: z.literal(true), entries: z.array(AuditEntrySchema) }),
  },
  // The popup found a pendingAllow record it cannot parse and asks the worker
  // to re-derive the mirror through its one serialized store path; a
  // popup-side remove could race a freshly minted live request.
  sweep_pending: {
    gate: "extension-page",
    req: z.strictObject({ type: z.literal("sweep_pending") }),
    res: Acknowledged,
  },
  enroll_pair: {
    gate: "extension-page",
    req: z.strictObject({ type: z.literal("enroll_pair") }),
    res: Acknowledged,
  },
  enroll_verify: {
    gate: "extension-page",
    req: z.strictObject({ type: z.literal("enroll_verify") }),
    res: Acknowledged,
  },
  enroll_approve: {
    gate: "extension-page",
    req: z.strictObject({ type: z.literal("enroll_approve") }),
    res: Acknowledged,
  },
  enroll_reject: {
    gate: "extension-page",
    req: z.strictObject({ type: z.literal("enroll_reject") }),
    res: Acknowledged,
  },
  enroll_revoke: {
    gate: "extension-page",
    req: z.strictObject({ type: z.literal("enroll_revoke") }),
    res: Acknowledged,
  },
  // Confirm-window only: any other page reading or answering a pending
  // confirmation would recreate the toast-autoclick hole this surface closes.
  confirm_ready: {
    gate: "confirm-window",
    req: z.strictObject({ type: z.literal("confirm_ready"), id: z.string().min(1) }),
    res: z.object({ ok: z.literal(true), payload: ConfirmPayloadSchema.nullable() }),
  },
  confirm_resolve: {
    gate: "confirm-window",
    req: z.strictObject({
      type: z.literal("confirm_resolve"),
      id: z.string().min(1),
      approved: z.boolean(),
    }),
    res: Acknowledged,
  },
  // The panic exit: deny everything pending and engage the kill switch as one
  // worker-side step. It carries no id on purpose: after "kill everything" no
  // pending confirmation may survive, whichever window asked.
  confirm_deny_kill: {
    gate: "confirm-window",
    req: z.strictObject({ type: z.literal("confirm_deny_kill") }),
    res: KillViewSchema,
  },
  // Enum-pinned here, at the trust boundary, so the relay can never put an
  // out-of-enum string on the wire.
  lang_choose: {
    gate: "extension-page",
    req: z.strictObject({ type: z.literal("lang_choose"), value: z.enum(UI_LANGUAGES) }),
    res: z.object({ ok: z.literal(true), sent: z.boolean() }),
  },
});

type Contract = typeof RUNTIME_CONTRACT;

export type RuntimeMsgType = keyof Contract;

export type RuntimeRequest<K extends RuntimeMsgType = RuntimeMsgType> = z.infer<Contract[K]["req"]>;

export const RuntimeMsgSchema = z.union(Object.values(RUNTIME_CONTRACT).map((entry) => entry.req));

export type RuntimeMsg = z.infer<typeof RuntimeMsgSchema>;

export type RuntimeResponse<K extends RuntimeMsgType = RuntimeMsgType> =
  | Contract[K]["res"]["_zod"]["output"]
  | Refusal;

/** What a sender may receive for one message type: its declared answer or a
 * refusal. The one place the refusal arm is attached. */
export function runtimeResponseSchema<K extends RuntimeMsgType>(
  type: K,
): z.ZodType<RuntimeResponse<K>> {
  return z.union([RUNTIME_CONTRACT[type].res, RefusalSchema]);
}

// The enrollment actions change the extension's trust anchor; the panels that
// offer them take exactly this set.
export const ENROLLMENT_ACTION_TYPES = [
  "enroll_pair",
  "enroll_verify",
  "enroll_approve",
  "enroll_reject",
  "enroll_revoke",
] as const satisfies readonly RuntimeMsgType[];

export type EnrollmentActionType = (typeof ENROLLMENT_ACTION_TYPES)[number];
