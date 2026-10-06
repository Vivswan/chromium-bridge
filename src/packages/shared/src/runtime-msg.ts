// The runtime-message contract between the extension's pages and its service
// worker. Every message declares its request, its response, and which sender
// may issue it, in one table, and the gate refusal is an arm of every
// response: a sender gets the declared answer or `{ ok: false, error }`, never
// silence and never an undeclared shape.

import { z } from "zod";
import { ConfirmPayloadSchema } from "./confirm";
import { AuditEntrySchema, KillMirrorSchema } from "./enclave";
import {
  EnrollOptionsFrameSchema,
  PresenceRequestFrameSchema,
  RegistrationRowSchema,
  TrustedClientSchema,
} from "./envelope.gen";
import { PolicyOverlaySchema, PolicyValuesSchema } from "./policy.gen";
import { UI_LANGUAGES } from "./settings";
import { PresenceAnswerSchema, RegistrationResponseSchema } from "./webauthn";

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
  lastError: z.string().optional(),
  paused: z.boolean().optional(),
  // An unpair's host-key deletion is still awaiting the next host connection.
  hostRevokePending: z.boolean().optional(),
};

const pinIdentity = { keyId: z.string(), fingerprint: z.string() };

export const EnrollmentStatusSchema = z.union([
  // Enrollment is required on every platform, so an unpaired or pending extension is always blocked.
  z.object({ ...enrollmentBase, state: z.literal("unpaired"), blocked: z.literal(true) }),
  z.object({
    ...enrollmentBase,
    state: z.literal("pending"),
    blocked: z.literal(true),
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

// The browser-registration rows the host reports (its registration_status_result), one per known browser.
const RegistrationViewSchema = z.object({
  ok: z.literal(true),
  browsers: z.array(RegistrationRowSchema),
});

/** The policy posture the worker enforces (policy-sync.ts), as the editor renders it: only `active`
 * carries values, so a blocked or pre-cutover page can never show a policy as editable. */
export const PolicyPostureSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("preCutover") }),
  z.strictObject({ kind: z.literal("active"), effective: PolicyValuesSchema }),
  z.strictObject({ kind: z.literal("blocked"), reason: z.string() }),
]);

export type PolicyPosture = z.infer<typeof PolicyPostureSchema>;

/** The extension's own note of the last credential this browser enrolled (written by the worker when the
 * host's enroll_result says ok). The host's trust record is the authority; this only lets the options page
 * show that an enrollment happened, and when. */
export const WebAuthnEnrollmentSchema = z.strictObject({
  credentialId: z.string().min(1),
  enrolledAt: z.number(),
});

export type WebAuthnEnrollment = z.infer<typeof WebAuthnEnrollmentSchema>;

/** Where the worker keeps that note; storage.local is confined to extension contexts, and the options page
 * refreshes on this key. */
export const WEBAUTHN_ENROLLMENT_KEY = "webauthnEnrollment";

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
  // Engage-only by shape: `on` is pinned to true, so this message cannot express a release. Releasing is
  // kill_release below, whose answer is the host's presence request, never a state.
  set_kill: {
    gate: "extension-page",
    req: z.strictObject({ type: z.literal("set_kill"), on: z.literal(true) }),
    res: KillViewSchema,
  },
  // Release restores capability, so the host answers with a presence request instead of acting: the page
  // runs the tap for it and answers through webauthn_presence_assert (or webauthn_presence_confirm when the
  // request admits no credential); the kill_status_result that follows the host's verdict updates the mirror.
  kill_release: {
    gate: "extension-page",
    req: z.strictObject({ type: z.literal("kill_release") }),
    res: z.object({ ok: z.literal(true), request: PresenceRequestFrameSchema }),
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
  // The WebAuthn ceremonies run in the options page (a service worker has no navigator.credentials); the
  // worker relays the host's frames. begin returns the creation options the page hands the authenticator,
  // pending returns the host-pushed request awaiting a tap (null when none), and the two response
  // messages carry the authenticator's answer back for the worker to post.
  webauthn_enroll_begin: {
    gate: "extension-page",
    req: z.strictObject({ type: z.literal("webauthn_enroll_begin") }),
    res: z.object({ ok: z.literal(true), options: EnrollOptionsFrameSchema }),
  },
  webauthn_enroll_finish: {
    gate: "extension-page",
    req: z.strictObject({
      type: z.literal("webauthn_enroll_finish"),
      ...RegistrationResponseSchema.shape,
    }),
    res: z.object({ ok: z.literal(true), credentialId: z.string().min(1) }),
  },
  webauthn_presence_pending: {
    gate: "extension-page",
    req: z.strictObject({ type: z.literal("webauthn_presence_pending") }),
    res: z.object({ ok: z.literal(true), request: PresenceRequestFrameSchema.nullable() }),
  },
  webauthn_enrollment: {
    gate: "extension-page",
    req: z.strictObject({ type: z.literal("webauthn_enrollment") }),
    res: z.object({ ok: z.literal(true), enrollment: WebAuthnEnrollmentSchema.nullable() }),
  },
  webauthn_presence_assert: {
    gate: "extension-page",
    req: z.strictObject({
      type: z.literal("webauthn_presence_assert"),
      ...PresenceAnswerSchema.shape,
    }),
    res: Acknowledged,
  },
  // The window's answer to the pending request, for a browser with no enrolled credential: the host accepts
  // it only when no credential could have answered (software_confirmation_not_allowed otherwise).
  webauthn_presence_confirm: {
    gate: "extension-page",
    req: z.strictObject({
      type: z.literal("webauthn_presence_confirm"),
      nonce: z.string().min(1),
    }),
    res: Acknowledged,
  },
  // Forget this browser's enrolled authenticators: the host acts on its own label and needs no proof.
  webauthn_forget: {
    gate: "extension-page",
    req: z.strictObject({ type: z.literal("webauthn_forget") }),
    res: Acknowledged,
  },
  // The host-registration panel: the per-browser manifest rows the host's doctor diagnoses, and the repair
  // `doctor --fix` runs, both answered with the fresh rows (a repair that failed is a refusal; the panel re-asks).
  get_registration: {
    gate: "extension-page",
    req: z.strictObject({ type: z.literal("get_registration") }),
    res: RegistrationViewSchema,
  },
  repair_registration: {
    gate: "extension-page",
    req: z.strictObject({ type: z.literal("repair_registration") }),
    res: RegistrationViewSchema,
  },
  // The policy editor reads the posture the worker enforces and tightens it through the host's unsigned
  // restriction lane. The overlay is strict-parsed here, at the trust boundary, so a field the catalogue does
  // not own never reaches the wire; the host's seam decides the direction and refuses a relaxation.
  get_policy: {
    gate: "extension-page",
    req: z.strictObject({ type: z.literal("get_policy") }),
    res: z.object({ ok: z.literal(true), posture: PolicyPostureSchema }),
  },
  restrict_policy: {
    gate: "extension-page",
    req: z.strictObject({ type: z.literal("restrict_policy"), overlay: PolicyOverlaySchema }),
    res: Acknowledged,
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
