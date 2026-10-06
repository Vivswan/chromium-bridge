// The options page's host-admin exchanges that clients.ts and kill.ts do not own: the browser-registration
// rows (status, and the repair that `doctor --fix` runs), the policy restriction lane, and the host's audit
// trail (what `chromium-bridge audit` reads). port.ts drives `collaborator`; messages.ts routes the
// options-page actions here. A repair writes manifests and wrapper scripts for the detected browsers, or for
// the browsers the page names, still a local operation in this account's scope; nothing here can raise a
// presence prompt.

import {
  AuditReadResultSchema,
  type AuditReadWire,
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
type HostAuditView = RuntimeResponse<"get_host_audit">;

/** True for the host-admin result frame tags. */
export function isHostAdminFrame(msg: unknown): msg is HostAdminInboundFrame {
  return HostAdminInboundFrameSchema.safeParse(msg).success;
}

// Status and repair share one exchange: the host answers both with registration_status_result.
const registration = exchange<HostAdminInboundFrame>("a registration request is already in flight");
const restriction = exchange<HostAdminInboundFrame>("a policy restriction is already in flight");
const auditTrail = exchange<HostAdminInboundFrame>("an audit read is already in flight");

export const collaborator: PortCollaborator = {
  onAttach(c) {
    registration.attach(c);
    restriction.attach(c);
    auditTrail.attach(c);
  },
  onDetach() {
    registration.detach();
    restriction.detach();
    auditTrail.detach();
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

/** Re-register the detected browsers (what `doctor --fix` does), or exactly the named ones (`--browser`), and
 * get the fresh rows back. A repair that failed on any target answers a refusal naming the target, and the
 * panel asks for the rows again. */
export function repairRegistration(browsers?: readonly string[]): Promise<RegistrationView> {
  const frame: RegistrationRepairWire = browsers
    ? { type: "registration_repair", browsers: [...browsers] }
    : { type: "registration_repair" };
  return registration.request(frame, readRegistration).view;
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

/** Read the newest records of the host's audit trail, the page `chromium-bridge audit` prints by default (the
 * host applies the CLI's default page size when no limit travels). An unreadable trail is the host's error. */
export function requestHostAudit(): Promise<HostAuditView> {
  return auditTrail.request({ type: "audit_read" } satisfies AuditReadWire, {
    read(frame): HostAuditView {
      const parsed = AuditReadResultSchema.safeParse(frame);
      if (!parsed.success) return refusal("malformed audit_read_result from host");
      if (!parsed.data.ok) return refusal(parsed.data.error);
      const { entries, older, path } = parsed.data;
      return { ok: true, entries, older, path };
    },
  }).view;
}

/** Route one inbound result frame to its waiting request. Unsolicited frames (nothing outstanding: a replay,
 * or an injected frame the host-side filter somehow missed) are dropped without touching any state. */
export function handleHostAdminFrame(msg: HostAdminInboundFrame): void {
  const slot = {
    registration_status_result: registration,
    policy_restrict_result: restriction,
    audit_read_result: auditTrail,
  }[msg.type];
  if (!slot.answer(msg)) console.warn(`[bb] dropping unsolicited ${msg.type}`);
}
