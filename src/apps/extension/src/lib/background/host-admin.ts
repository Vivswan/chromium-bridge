// The options page's two host-admin exchanges that clients.ts and kill.ts do not own: the browser-registration
// rows (status, and the repair that `doctor --fix` runs) and the policy restriction lane. port.ts drives
// `collaborator`; messages.ts routes the options-page actions here. A repair writes manifests and wrapper
// scripts for every detected browser, still a local operation; nothing here can raise a presence prompt.

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
import type { PortCollaborator } from "./connection";
import { exchange } from "./exchange";

type RegistrationView = RuntimeResponse<"get_registration">;
type RestrictView = RuntimeResponse<"restrict_policy">;

/** True for the two host-admin result frame tags. */
export function isHostAdminFrame(msg: unknown): msg is HostAdminInboundFrame {
  return HostAdminInboundFrameSchema.safeParse(msg).success;
}

// Status and repair share one exchange: the host answers both with registration_status_result.
const registration = exchange<HostAdminInboundFrame>("a registration request is already in flight");
const restriction = exchange<HostAdminInboundFrame>("a policy restriction is already in flight");

export const collaborator: PortCollaborator = {
  onAttach(c) {
    registration.attach(c);
    restriction.attach(c);
  },
  onDetach() {
    registration.detach();
    restriction.detach();
  },
  onFrame(msg) {
    if (!isHostAdminFrame(msg)) return false;
    handleHostAdminFrame(msg);
    return true;
  },
};

const refusal = (error: string): Refusal => ({ ok: false, error });

// The readers are ok-split unions, so a mixture the typed producer cannot emit fails the parse here.
const readRegistration = {
  read(frame: HostAdminInboundFrame): RegistrationView {
    const parsed = RegistrationStatusResultSchema.safeParse(frame);
    if (!parsed.success) return refusal("malformed registration_status_result from host");
    return parsed.data.ok
      ? { ok: true, browsers: parsed.data.browsers }
      : refusal(parsed.data.error);
  },
};

/** Ask the host for every known browser's native-messaging registration. */
export function requestRegistrationStatus(): Promise<RegistrationView> {
  return registration.request(
    { type: "registration_status" } satisfies RegistrationStatusWire,
    readRegistration,
  ).view;
}

/** Re-register the detected browsers (what `doctor --fix` does) and get the fresh rows back. A repair that
 * failed on any target answers a refusal naming the target, and the panel asks for the rows again. */
export function repairRegistration(): Promise<RegistrationView> {
  return registration.request(
    { type: "registration_repair" } satisfies RegistrationRepairWire,
    readRegistration,
  ).view;
}

/** Tighten the effective policy by `overlay` through the host's unsigned restriction lane. The overlay was
 * strict-parsed by the runtime-message schema; the host's seam re-checks the direction and refuses a relaxation. */
export function restrictPolicy(overlay: PolicyOverlay): Promise<RestrictView> {
  return restriction.request({ type: "policy_restrict", overlay } satisfies PolicyRestrictWire, {
    read(frame): RestrictView {
      const parsed = PolicyRestrictResultSchema.safeParse(frame);
      if (!parsed.success) return refusal("malformed policy_restrict_result from host");
      return parsed.data.ok ? { ok: true } : refusal(parsed.data.error);
    },
  }).view;
}

/** Route one inbound result frame to its waiting request. Unsolicited frames (nothing outstanding: a replay,
 * or an injected frame the host-side filter somehow missed) are dropped without touching any state. */
export function handleHostAdminFrame(msg: HostAdminInboundFrame): void {
  const answered =
    msg.type === "registration_status_result" ? registration.answer(msg) : restriction.answer(msg);
  if (!answered) console.warn(`[bb] dropping unsolicited ${msg.type}`);
}
