// The extension half of the ADR-0025 trusted-client admin exchange: the
// options page asks (via the runtime message router) for the host's
// trusted-client allowlist, or revokes one entry, and this module relays the
// request to the native host as a control frame (client_list /
// client_revoke) and correlates the host's result frame back to the caller.
//
// port.ts hands this module the native-messaging port (attachPort) and every
// admin result frame; messages.ts routes the options-page actions here. This
// module never imports port.ts, so there is no import cycle - the same shape
// as enrollment.ts.
//
// Fail-closed posture (inherits the #61 timeout rule): every request carries
// a deadline, and an unanswered request resolves to a refusal, never a hang.
// One request of each kind may be outstanding at a time; the host replies in
// order on a single pipe, so this stays trivially correlatable without ids.

import {
  type AdminInboundFrame,
  AdminInboundFrameSchema,
  ClientListResultSchema,
  ClientRevokeResultSchema,
  type TrustedClient,
} from "@chromium-bridge/shared";

export type { TrustedClient };

/** How long the host has to answer an admin control frame before the request
 * fails closed. Generous for a local round-trip; nothing here can raise a
 * presence prompt (deletion and listing are deliberately not presence-gated,
 * see ADR-0021/0025). */
const ADMIN_REQUEST_TIMEOUT_MS = 10_000;

export interface ClientListView {
  ok: boolean;
  enrolled?: boolean;
  clients?: TrustedClient[];
  error?: string;
}

export interface RevokeClientView {
  ok: boolean;
  error?: string;
}

/** True for the two ADR-0025 admin result frame tags. */
export function isAdminFrame(msg: unknown): msg is AdminInboundFrame {
  return AdminInboundFrameSchema.safeParse(msg).success;
}

// The port sender, registered by port.ts while a port is up. Null = not
// connected.
let postFrame: ((frame: object) => boolean) | null = null;

export function attachPort(post: (frame: object) => boolean): void {
  postFrame = post;
}

export function detachPort(): void {
  postFrame = null;
  // The host died with the port; its replies can never arrive.
  failPending("native host disconnected");
}

interface Pending<T> {
  resolve: (v: T) => void;
  timer: ReturnType<typeof setTimeout>;
}

let pendingList: Pending<ClientListView> | null = null;
let pendingRevoke: Pending<RevokeClientView> | null = null;

function failPending(reason: string): void {
  if (pendingList) {
    clearTimeout(pendingList.timer);
    pendingList.resolve({ ok: false, error: reason });
    pendingList = null;
  }
  if (pendingRevoke) {
    clearTimeout(pendingRevoke.timer);
    pendingRevoke.resolve({ ok: false, error: reason });
    pendingRevoke = null;
  }
}

/** Ask the host for the trusted-client allowlist. */
export function requestClientList(): Promise<ClientListView> {
  if (!postFrame) return Promise.resolve({ ok: false, error: "native host not connected" });
  if (pendingList) {
    return Promise.resolve({ ok: false, error: "a client-list request is already in flight" });
  }
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      pendingList = null;
      resolve({ ok: false, error: "no reply from the native host (timed out)" });
    }, ADMIN_REQUEST_TIMEOUT_MS);
    pendingList = { resolve, timer };
    if (!postFrame?.({ type: "client_list" })) {
      clearTimeout(timer);
      pendingList = null;
      resolve({ ok: false, error: "failed to send the request to the native host" });
    }
  });
}

/** Revoke one trusted client by name. The host rewrites the allowlist and
 * bumps the revocation epoch in one critical section, so a live broker drops
 * that client's connections (ADR-0025). The name was already validated by the
 * runtime-message schema; the host re-validates it at its own boundary. */
export function revokeTrustedClient(name: string): Promise<RevokeClientView> {
  if (!postFrame) return Promise.resolve({ ok: false, error: "native host not connected" });
  if (pendingRevoke) {
    return Promise.resolve({ ok: false, error: "a revoke request is already in flight" });
  }
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      pendingRevoke = null;
      resolve({ ok: false, error: "no reply from the native host (timed out)" });
    }, ADMIN_REQUEST_TIMEOUT_MS);
    pendingRevoke = { resolve, timer };
    if (!postFrame?.({ type: "client_revoke", name })) {
      clearTimeout(timer);
      pendingRevoke = null;
      resolve({ ok: false, error: "failed to send the request to the native host" });
    }
  });
}

/** Route one inbound admin result frame to its waiting request. Unsolicited
 * frames (nothing outstanding - a replay, or an injected frame the host-side
 * filter somehow missed) are dropped without touching any state. */
export function handleAdminFrame(msg: AdminInboundFrame): void {
  if (msg.type === "client_list_result") {
    const current = pendingList;
    if (!current) {
      console.warn("[bb] dropping unsolicited client_list_result");
      return;
    }
    pendingList = null;
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
  const current = pendingRevoke;
  if (!current) {
    console.warn("[bb] dropping unsolicited client_revoke_result");
    return;
  }
  pendingRevoke = null;
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
