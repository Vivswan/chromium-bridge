// Runtime messages the service worker accepts from the popup / options page
// and the confirmation window (runtime.onMessage). The router
// (lib/background/messages.ts) parses every inbound message against this
// union before acting - an unrecognized or malformed message is refused, not
// interpreted. Nothing here is accepted from content scripts except the
// screenshot-free basics the router explicitly allows; the enrollment and
// confirmation actions additionally require an extension-page sender.

import { z } from "zod";

import { UI_LANGUAGES } from "./settings";

// The enrollment actions change the extension's trust anchor, so the router
// additionally requires them to come from the extension's own pages.
export const ENROLLMENT_ACTION_TYPES = [
  "enroll_pair",
  "enroll_verify",
  "enroll_approve",
  "enroll_reject",
  "enroll_revoke",
] as const;

export type EnrollmentActionType = (typeof ENROLLMENT_ACTION_TYPES)[number];

export const RuntimeMsgSchema = z.discriminatedUnion("type", [
  // Resolve a pending allowlist approval from the popup.
  z.strictObject({ type: z.literal("resolve_allow"), id: z.string().min(1), allow: z.boolean() }),
  z.strictObject({ type: z.literal("get_allowlist") }),
  z.strictObject({ type: z.literal("add_allow"), glob: z.string().min(1) }),
  z.strictObject({ type: z.literal("remove_allow"), glob: z.string().min(1) }),
  z.strictObject({ type: z.literal("get_status") }),
  z.strictObject({ type: z.literal("get_enrollment") }),
  // The ADR-0025 trusted-client admin surface: read the list, revoke one.
  // Both are relayed to the native host as control frames; the router
  // additionally requires an extension-page sender (a content script must
  // never enumerate or mutate the trust set). The name is validated like a
  // host-side label so a malformed value never reaches the wire.
  z.strictObject({ type: z.literal("get_clients") }),
  z.strictObject({
    type: z.literal("revoke_client"),
    name: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/),
  }),
  // The ADR-0030 kill switch. get_kill returns the SW-only mirror plus a live
  // host query when the port is up; set_kill relays kill_engage to the native
  // host, which performs the transition and answers with the resulting state.
  // ENGAGE-ONLY by shape (ADR-0032 decision 6): the host refuses kill_release
  // from the extension - release lives in the desktop app and `chromium-bridge
  // unkill` - so `on` is pinned to the literal `true` and a release request
  // cannot even be expressed at this boundary. The router requires an
  // extension-page sender for BOTH (the top-level gate): a page or content
  // script can neither read nor engage the switch.
  z.strictObject({ type: z.literal("get_kill") }),
  z.strictObject({ type: z.literal("set_kill"), on: z.literal(true) }),
  // The ADR-0030 read-only audit panel: the SW's local audit ring.
  z.strictObject({ type: z.literal("get_audit") }),
  // The popup found a pendingAllow record it cannot parse (an old-shape or
  // corrupted ghost): ask the SW to re-derive the mirror through its one
  // serialized store path. The popup never writes the record itself - an
  // uncoordinated popup-side remove could race the SW minting a LIVE request
  // and delete it out from under its resolver.
  z.strictObject({ type: z.literal("sweep_pending") }),
  // The ADR-0021 pairing ceremony actions.
  z.strictObject({ type: z.literal("enroll_pair") }),
  z.strictObject({ type: z.literal("enroll_verify") }),
  z.strictObject({ type: z.literal("enroll_approve") }),
  z.strictObject({ type: z.literal("enroll_reject") }),
  z.strictObject({ type: z.literal("enroll_revoke") }),
  // The off-DOM confirmation window (ADR-0027). Accepted only from extension
  // pages: a content script must never be able to read or answer a pending
  // confirmation (that would recreate the toast-autoclick hole this surface
  // closes).
  z.strictObject({ type: z.literal("confirm_ready"), id: z.string().min(1) }),
  z.strictObject({
    type: z.literal("confirm_resolve"),
    id: z.string().min(1),
    approved: z.boolean(),
  }),
  // The confirm window's panic exit (ADR-0030): deny EVERYTHING pending
  // (active, queued, and newly arriving confirmations) and engage the kill
  // switch, as one service-worker-side step so the deny can never be
  // reordered after (or torn from) the engage. Deliberately carries no id:
  // after "kill everything" no pending confirmation may survive, whichever
  // window asked. Confirm-window senders only, like the other confirm_*.
  z.strictObject({ type: z.literal("confirm_deny_kill") }),
  // The user chose a display language in the options picker (ADR-0032
  // decision 7): the SW relays it to the host as `lang_set` when the live
  // connection has already pushed `lang_current` (never-speak-first). The
  // value is enum-pinned HERE, at the trust boundary, so the relay can never
  // put an out-of-enum string on the wire.
  z.strictObject({ type: z.literal("lang_choose"), value: z.enum(UI_LANGUAGES) }),
]);

export type RuntimeMsg = z.infer<typeof RuntimeMsgSchema>;

export function isEnrollmentAction(type: RuntimeMsg["type"]): type is EnrollmentActionType {
  return (ENROLLMENT_ACTION_TYPES as readonly string[]).includes(type);
}
