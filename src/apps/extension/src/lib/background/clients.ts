// The extension half of the trusted-client admin exchange: the options page asks (via the runtime message
// router) for the host's trusted-client allowlist, or revokes one entry, and this module relays the request to
// the native host as a control frame (client_list / client_revoke) and reads the host's result frame back for
// the caller. port.ts drives `collaborator`; messages.ts routes the options-page actions here. This module never
// imports port.ts, so there is no import cycle. Listing and deletion only remove or show capability, so neither
// is presence-gated.

import { type AdminInboundFrame, AdminInboundFrameSchema } from "@chromium-bridge/shared/enclave";
import {
  ClientListResultSchema,
  type ClientListWire,
  ClientRevokeResultSchema,
  type ClientRevokeWire,
} from "@chromium-bridge/shared/generated/envelope";
import type { RuntimeResponse } from "@chromium-bridge/shared/runtime-msg";
import type { PortCollaborator } from "./connection";
import { exchange } from "./exchange";

type ClientListView = RuntimeResponse<"get_clients">;
type RevokeClientView = RuntimeResponse<"revoke_client">;

/** True for the two admin result frame tags. */
export function isAdminFrame(msg: unknown): msg is AdminInboundFrame {
  return AdminInboundFrameSchema.safeParse(msg).success;
}

const list = exchange<AdminInboundFrame>("a client-list request is already in flight");
const revoke = exchange<AdminInboundFrame>("a revoke request is already in flight");

export const collaborator: PortCollaborator = {
  onAttach(c) {
    list.attach(c);
    revoke.attach(c);
  },
  onDetach() {
    list.detach();
    revoke.detach();
  },
  onFrame(msg) {
    if (!isAdminFrame(msg)) return false;
    handleAdminFrame(msg);
    return true;
  },
};

/** Ask the host for the trusted-client allowlist. */
export function requestClientList(): Promise<ClientListView> {
  return list.request({ type: "client_list" } satisfies ClientListWire, {
    read(frame): ClientListView {
      const parsed = ClientListResultSchema.safeParse(frame);
      if (!parsed.success) return { ok: false, error: "malformed client_list_result from host" };
      const { ok, enrolled, clients, error } = parsed.data;
      return ok ? { ok, enrolled, clients } : { ok, error: error ?? "unknown host error" };
    },
  }).view;
}

/** Revoke one trusted client by name. The host rewrites the allowlist and bumps the revocation epoch in one
 * critical section, so a live broker drops that client's connections. The name was already validated by the
 * runtime-message schema; the host re-validates it at its own boundary. */
export function revokeTrustedClient(name: string): Promise<RevokeClientView> {
  return revoke.request({ type: "client_revoke", name } satisfies ClientRevokeWire, {
    read(frame): RevokeClientView {
      const parsed = ClientRevokeResultSchema.safeParse(frame);
      if (!parsed.success) return { ok: false, error: "malformed client_revoke_result from host" };
      return parsed.data.ok
        ? { ok: true }
        : { ok: false, error: parsed.data.error ?? "unknown host error" };
    },
  }).view;
}

/** Route one inbound admin result frame to its waiting request. Unsolicited frames (nothing outstanding: a
 * replay, or an injected frame the host-side filter somehow missed) are dropped without touching any state. */
export function handleAdminFrame(msg: AdminInboundFrame): void {
  const answered = msg.type === "client_list_result" ? list.answer(msg) : revoke.answer(msg);
  if (!answered) console.warn(`[bb] dropping unsolicited ${msg.type}`);
}
