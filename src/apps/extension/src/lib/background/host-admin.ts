// The options page's two host-admin exchanges that clients.ts and kill.ts do not own: the browser-registration
// rows (status, and the repair that `doctor --fix` runs) and the policy restriction lane. One request per reply
// tag may be outstanding; the host answers in order on the single pipe, so a reply correlates by arrival with
// no ids, and an unanswered request resolves to a refusal at its deadline or on disconnect, never a hang.
// port.ts drives `collaborator`; messages.ts routes the options-page actions here.

import {
  PolicyRestrictResultSchema,
  type PolicyRestrictWire,
  type RegistrationRepairWire,
  RegistrationStatusResultSchema,
  type RegistrationStatusWire,
} from "@chromium-bridge/shared/envelope.gen";
import {
  type HostAdminInboundFrame,
  HostAdminInboundFrameSchema,
} from "@chromium-bridge/shared/host-admin";
import type { PolicyOverlay } from "@chromium-bridge/shared/policy.gen";
import type { Refusal, RuntimeResponse } from "@chromium-bridge/shared/runtime-msg";
import type { Connection, PortCollaborator } from "./connection";
import { inLife } from "./in-life";

/** How long the host has to answer before a request fails closed. A repair writes manifests and wrapper
 * scripts for every detected browser, still a local operation; nothing here can raise a presence prompt. */
const HOST_ADMIN_REQUEST_TIMEOUT_MS = 10_000;

type RegistrationView = RuntimeResponse<"get_registration">;
type RestrictView = RuntimeResponse<"restrict_policy">;

/** True for the two host-admin result frame tags. */
export function isHostAdminFrame(msg: unknown): msg is HostAdminInboundFrame {
  return HostAdminInboundFrameSchema.safeParse(msg).success;
}

const conn = inLife<Connection | null>(() => null);

export const collaborator: PortCollaborator = {
  onAttach(c) {
    conn.value = c;
  },
  onDetach() {
    conn.value = null;
    // The host died with the port; its replies can never arrive.
    registration.fail("native host disconnected");
    restriction.fail("native host disconnected");
  },
  onFrame(msg) {
    if (!isHostAdminFrame(msg)) return false;
    handleHostAdminFrame(msg);
    return true;
  },
};

interface Pending<S> {
  resolve: (v: S | Refusal) => void;
  timer: ReturnType<typeof setTimeout>;
}

const refusal = (error: string): Refusal => ({ ok: false, error });

/** The outstanding request for one reply tag: opened by a request, settled by the reply, the deadline, or the
 * disconnect, whichever comes first, and never more than one at a time. `S` is the success arm; every failure
 * is the contract's refusal, so the slot owns that guarantee and no caller restates it. */
function slot<S extends { ok: true }>(inFlightError: string) {
  let pending: Pending<S> | null = null;
  return {
    request(frame: object): Promise<S | Refusal> {
      const live = conn.value;
      if (!live) return Promise.resolve(refusal("native host not connected"));
      if (pending) return Promise.resolve(refusal(inFlightError));
      return new Promise<S | Refusal>((resolve) => {
        const timer = setTimeout(() => {
          pending = null;
          resolve(refusal("no reply from the native host (timed out)"));
        }, HOST_ADMIN_REQUEST_TIMEOUT_MS);
        pending = { resolve, timer };
        if (!live.post(frame)) {
          clearTimeout(timer);
          pending = null;
          resolve(refusal("failed to send the request to the native host"));
        }
      });
    },
    claim(): ((v: S | Refusal) => void) | null {
      const current = pending;
      if (!current) return null;
      pending = null;
      clearTimeout(current.timer);
      return current.resolve;
    },
    fail(reason: string): void {
      this.claim()?.(refusal(reason));
    },
  };
}

// Status and repair share one slot: the host answers both with registration_status_result.
const registration = slot<Extract<RegistrationView, { ok: true }>>(
  "a registration request is already in flight",
);
const restriction = slot<Extract<RestrictView, { ok: true }>>(
  "a policy restriction is already in flight",
);

/** Ask the host for every known browser's native-messaging registration. */
export function requestRegistrationStatus(): Promise<RegistrationView> {
  return registration.request({ type: "registration_status" } satisfies RegistrationStatusWire);
}

/** Re-register the detected browsers (what `doctor --fix` does) and get the fresh rows back. A repair that
 * failed on any target answers a refusal naming the target, and the panel asks for the rows again. */
export function repairRegistration(): Promise<RegistrationView> {
  return registration.request({ type: "registration_repair" } satisfies RegistrationRepairWire);
}

/** Tighten the effective policy by `overlay` through the host's unsigned restriction lane. The overlay was
 * strict-parsed by the runtime-message schema; the host's seam re-checks the direction and refuses a relaxation. */
export function restrictPolicy(overlay: PolicyOverlay): Promise<RestrictView> {
  return restriction.request({ type: "policy_restrict", overlay } satisfies PolicyRestrictWire);
}

/** Route one inbound result frame to its waiting request. Unsolicited frames (nothing outstanding: a replay,
 * or an injected frame the host-side filter somehow missed) are dropped without touching any state. The
 * readers are ok-split unions, so a mixture the typed producer cannot emit fails the parse here. */
export function handleHostAdminFrame(msg: HostAdminInboundFrame): void {
  if (msg.type === "registration_status_result") {
    const resolve = registration.claim();
    if (!resolve) {
      console.warn("[bb] dropping unsolicited registration_status_result");
      return;
    }
    const parsed = RegistrationStatusResultSchema.safeParse(msg);
    if (!parsed.success) {
      resolve(refusal("malformed registration_status_result from host"));
      return;
    }
    const frame = parsed.data;
    resolve(frame.ok ? { ok: true, browsers: frame.browsers } : refusal(frame.error));
    return;
  }
  const resolve = restriction.claim();
  if (!resolve) {
    console.warn("[bb] dropping unsolicited policy_restrict_result");
    return;
  }
  const parsed = PolicyRestrictResultSchema.safeParse(msg);
  if (!parsed.success) {
    resolve(refusal("malformed policy_restrict_result from host"));
    return;
  }
  const frame = parsed.data;
  resolve(frame.ok ? { ok: true } : refusal(frame.error));
}
