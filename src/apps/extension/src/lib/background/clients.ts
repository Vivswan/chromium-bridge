// The extension half of the trusted-client admin exchange: the options page asks (via the runtime message
// router) for the host's trusted-client allowlist, revokes one entry, or pairs one, and this module relays the
// request to the native host as a control frame (client_list / client_revoke / client_pair) and reads the host's
// result frame back for the caller. port.ts drives `collaborator`; messages.ts routes the options-page actions
// here. This module never imports port.ts, so there is no import cycle. Listing and deletion only remove or show
// capability, so neither is presence-gated; pairing grants it, so it is the presence exchange's act (beginAct):
// its presence_request lands in lib/webauthn, and the client_pair_result arriving here is handed back through
// claimAct.

import { type AdminInboundFrame, AdminInboundFrameSchema } from "@genkan/shared/enclave";
import {
  ClientListResultSchema,
  type ClientListWire,
  ClientPairResultSchema,
  ClientRevokeResultSchema,
  type ClientRevokeWire,
} from "@genkan/shared/generated/envelope";
import type { RuntimeResponse } from "@genkan/shared/runtime-msg";
import { handOverVerdict } from "../webauthn/exchange";
import type { PortCollaborator } from "./connection";
import { exchange } from "./exchange";

type ClientListView = RuntimeResponse<"get_clients">;
type RevokeClientView = RuntimeResponse<"revoke_client">;

/** True for the client-admin result frame tags. */
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

/** Route one inbound admin result frame to its waiting request or act. Unsolicited frames (nothing
 * outstanding: a replay, or an injected frame the host-side filter somehow missed) are dropped without touching
 * any state. */
export function handleAdminFrame(msg: AdminInboundFrame): void {
  let answered: boolean;
  switch (msg.type) {
    case "client_list_result":
      answered = list.answer(msg);
      break;
    case "client_revoke_result":
      answered = revoke.answer(msg);
      break;
    case "client_pair_result":
      answered = handOverVerdict(msg.type, ClientPairResultSchema, msg);
      break;
  }
  if (!answered) console.warn(`[genkan] dropping unsolicited ${msg.type}`);
}
