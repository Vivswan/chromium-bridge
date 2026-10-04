// The WebAuthn control-frame side the generator cannot own: the inbound classifier the service worker routes
// on, and the page<->worker shapes the runtime-message contract embeds. The frame validators themselves are
// generated (envelope.gen.ts from WebAuthnControl in protocol/control.rs, the verdict frames as ok-split
// unions from the asymmetry table).

import { z } from "zod";

// Classification only: the four host->extension WebAuthn frames. The three extension->host frames
// (enroll_begin, enroll_finish, presence_assert) are outbound only and never classify inbound.
// scripts/check-envelope.ts holds this array to the generated reader plan.
export const WEBAUTHN_FRAME_TYPES = [
  "enroll_options",
  "enroll_result",
  "presence_request",
  "presence_result",
] as const;

export const WebAuthnInboundFrameSchema = z.looseObject({
  type: z.enum(WEBAUTHN_FRAME_TYPES),
});

export type WebAuthnInboundFrame = z.infer<typeof WebAuthnInboundFrameSchema>;

// ---- page <-> worker shapes ---------------------------------------------------------

/** Which surface a presence tap lands on, from the page's own feature probe (never the host's claim). The
 * label the user sees is keyed on this: a software confirmation must never be presented as a hardware one. */
export const PRESENCE_SURFACES = [
  "platform_authenticator",
  "security_key",
  "software_confirmation",
] as const;

export type PresenceSurface = (typeof PRESENCE_SURFACES)[number];

/** The `navigator.credentials.create` response fields the host parses (enroll_finish). */
export const RegistrationResponseSchema = z.strictObject({
  attestation_object: z.string().min(1),
  client_data_json: z.string().min(1),
});

export type RegistrationResponse = z.infer<typeof RegistrationResponseSchema>;

/** The `navigator.credentials.get` response fields the host verifies (presence_assert). */
export const AssertionResponseSchema = z.strictObject({
  credential_id: z.string().min(1),
  authenticator_data: z.string().min(1),
  client_data_json: z.string().min(1),
  signature: z.string().min(1),
});

export type AssertionResponse = z.infer<typeof AssertionResponseSchema>;

/** The page's answer to one presence request: the request's nonce it answered plus the authenticator's
 * response, so an answer to a superseded request can never consume the newer one. */
export const PresenceAnswerSchema = z.strictObject({
  nonce: z.string().min(1),
  ...AssertionResponseSchema.shape,
});

export type PresenceAnswer = z.infer<typeof PresenceAnswerSchema>;
