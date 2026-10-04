// The inbound classifiers for the options page's two host-admin exchanges: the browser-registration rows and
// the policy restriction lane. Kept apart from the client-admin classifier in enclave.ts because clients.ts
// routes every frame that classifier admits to the two client exchanges, so a tag shared with it would land
// in the wrong handler. scripts/check-envelope.ts holds both arrays to the generated reader plan.

import { z } from "zod";

export const REGISTRATION_FRAME_TYPES = ["registration_status_result"] as const;

export const POLICY_RESTRICT_FRAME_TYPES = ["policy_restrict_result"] as const;

export const HostAdminInboundFrameSchema = z.looseObject({
  type: z.enum([...REGISTRATION_FRAME_TYPES, ...POLICY_RESTRICT_FRAME_TYPES]),
});

export type HostAdminInboundFrame = z.infer<typeof HostAdminInboundFrameSchema>;
