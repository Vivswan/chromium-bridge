// The inbound classifiers for the options page's host-admin exchanges: the browser-registration rows, the
// policy lanes (restrict, set, rollback, history), the host's audit trail, and the doctor report. Kept apart
// from the client-admin classifier in enclave.ts because clients.ts routes every frame that classifier admits
// to the client exchanges, so a tag shared with it would land in the wrong handler. scripts/check-envelope.ts
// holds these arrays to the generated reader plan.

import { z } from "zod";

export const REGISTRATION_FRAME_TYPES = ["registration_status_result"] as const;

export const POLICY_LANE_FRAME_TYPES = [
  "policy_restrict_result",
  "policy_set_result",
  "policy_rollback_result",
  "policy_history_result",
] as const;

export const AUDIT_READ_FRAME_TYPES = ["audit_read_result"] as const;

export const DOCTOR_FRAME_TYPES = ["doctor_report_result"] as const;

export const HostAdminInboundFrameSchema = z.looseObject({
  type: z.enum([
    ...REGISTRATION_FRAME_TYPES,
    ...POLICY_LANE_FRAME_TYPES,
    ...AUDIT_READ_FRAME_TYPES,
    ...DOCTOR_FRAME_TYPES,
  ]),
});

export type HostAdminInboundFrame = z.infer<typeof HostAdminInboundFrameSchema>;
