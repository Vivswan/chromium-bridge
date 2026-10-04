// The extension half of the trusted-client admin exchange: the options page
// asks (via the runtime message router) for the host's trusted-client
// allowlist, or revokes one entry, and this module relays the request to the
// native host as a control frame (client_list / client_revoke) and correlates
// the host's result frame back to the caller.
//
// port.ts drives `collaborator` (the connection, then every admin result
// frame); messages.ts routes the options-page actions here. This module never
// imports port.ts, so there is no import cycle - the same shape as
// enrollment.ts.
//
// Fail-closed posture (inherits the #61 timeout rule): every request carries
// a deadline, and an unanswered request resolves to a refusal, never a hang.
// One request of each kind may be outstanding at a time; the host replies in
// order on a single pipe, so this stays trivially correlatable without ids.

import { type AdminInboundFrame, AdminInboundFrameSchema } from "@chromium-bridge/shared/enclave";
import {
  ClientListResultSchema,
  type ClientListWire,
  ClientRevokeResultSchema,
  type ClientRevokeWire,
} from "@chromium-bridge/shared/envelope.gen";
import type { RuntimeResponse } from "@chromium-bridge/shared/runtime-msg";
import type { Connection, PortCollaborator } from "./connection";
import { inLife } from "./in-life";

/** How long the host has to answer an admin control frame before the request
 * fails closed. Generous for a local round-trip; nothing here can raise a
 * presence prompt (deletion and listing only remove or show capability, so
 * they are deliberately not presence-gated). */
const ADMIN_REQUEST_TIMEOUT_MS = 10_000;

type ClientListView = RuntimeResponse<"get_clients">;
type RevokeClientView = RuntimeResponse<"revoke_client">;

/** True for the two admin result frame tags. */
export function isAdminFrame(msg: unknown): msg is AdminInboundFrame {
  return AdminInboundFrameSchema.safeParse(msg).success;
}

const conn = inLife<Connection | null>(() => null);

export const collaborator: PortCollaborator = {
  onAttach(c) {
    conn.value = c;
  },
  onDetach() {
    conn.value = null;
    // The host died with the port; its replies can never arrive.
    failPending("native host disconnected");
  },
  onFrame(msg) {
    if (!isAdminFrame(msg)) return false;
    handleAdminFrame(msg);
    return true;
  },
};

interface Pending<T> {
  resolve: (v: T) => void;
  timer: ReturnType<typeof setTimeout>;
}

const pendingList = inLife<Pending<ClientListView> | null>(() => null);
const pendingRevoke = inLife<Pending<RevokeClientView> | null>(() => null);

function failPending(reason: string): void {
  if (pendingList.value) {
    clearTimeout(pendingList.value.timer);
    pendingList.value.resolve({ ok: false, error: reason });
    pendingList.value = null;
  }
  if (pendingRevoke.value) {
    clearTimeout(pendingRevoke.value.timer);
    pendingRevoke.value.resolve({ ok: false, error: reason });
    pendingRevoke.value = null;
  }
}

/** Ask the host for the trusted-client allowlist. */
export function requestClientList(): Promise<ClientListView> {
  const live = conn.value;
  if (!live) return Promise.resolve({ ok: false, error: "native host not connected" });
  if (pendingList.value) {
    return Promise.resolve({ ok: false, error: "a client-list request is already in flight" });
  }
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      pendingList.value = null;
      resolve({ ok: false, error: "no reply from the native host (timed out)" });
    }, ADMIN_REQUEST_TIMEOUT_MS);
    pendingList.value = { resolve, timer };
    if (!live.post({ type: "client_list" } satisfies ClientListWire)) {
      clearTimeout(timer);
      pendingList.value = null;
      resolve({ ok: false, error: "failed to send the request to the native host" });
    }
  });
}

/** Revoke one trusted client by name. The host rewrites the allowlist and bumps
 * the revocation epoch in one critical section, so a live broker drops that
 * client's connections. The name was already validated by the runtime-message
 * schema; the host re-validates it at its own boundary. */
export function revokeTrustedClient(name: string): Promise<RevokeClientView> {
  const live = conn.value;
  if (!live) return Promise.resolve({ ok: false, error: "native host not connected" });
  if (pendingRevoke.value) {
    return Promise.resolve({ ok: false, error: "a revoke request is already in flight" });
  }
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      pendingRevoke.value = null;
      resolve({ ok: false, error: "no reply from the native host (timed out)" });
    }, ADMIN_REQUEST_TIMEOUT_MS);
    pendingRevoke.value = { resolve, timer };
    if (!live.post({ type: "client_revoke", name } satisfies ClientRevokeWire)) {
      clearTimeout(timer);
      pendingRevoke.value = null;
      resolve({ ok: false, error: "failed to send the request to the native host" });
    }
  });
}

/** Route one inbound admin result frame to its waiting request. Unsolicited
 * frames (nothing outstanding - a replay, or an injected frame the host-side
 * filter somehow missed) are dropped without touching any state. */
export function handleAdminFrame(msg: AdminInboundFrame): void {
  if (msg.type === "client_list_result") {
    const current = pendingList.value;
    if (!current) {
      console.warn("[bb] dropping unsolicited client_list_result");
      return;
    }
    pendingList.value = null;
    clearTimeout(current.timer);
    const parsed = ClientListResultSchema.safeParse(msg);
    if (!parsed.success) {
      current.resolve({ ok: false, error: "malformed client_list_result from host" });
      return;
    }
    const { ok, enrolled, clients, error } = parsed.data;
    current.resolve(ok ? { ok, enrolled, clients } : { ok, error: error ?? "unknown host error" });
    return;
  }
  // client_revoke_result
  const current = pendingRevoke.value;
  if (!current) {
    console.warn("[bb] dropping unsolicited client_revoke_result");
    return;
  }
  pendingRevoke.value = null;
  clearTimeout(current.timer);
  const parsed = ClientRevokeResultSchema.safeParse(msg);
  if (!parsed.success) {
    current.resolve({ ok: false, error: "malformed client_revoke_result from host" });
    return;
  }
  current.resolve(
    parsed.data.ok ? { ok: true } : { ok: false, error: parsed.data.error ?? "unknown host error" },
  );
}
