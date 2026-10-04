// The WebAuthn control-frame side the generator cannot own: the inbound classifier the service worker routes
// on, the ok-split refinements over the two result readers, and the page<->worker shapes the runtime-message
// contract embeds. The frame validators themselves are generated (envelope.gen.ts from WebAuthnControl in
// protocol/control.rs).

import { z } from "zod";
import { EnrollResultFrameSchema, PresenceResultFrameSchema } from "./envelope.gen";

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

// ---- the ok-split refinements over the generated result readers ------------------
//
// On the wire every verdict field is an Option, so the generated shape validates per field and would pass
// frames EnrollOutcome::into_frame / PresenceOutcome::into_frame (protocol/control.rs) can never emit. A
// refinement never shows up in a derived schema, so scripts/check-envelope.ts pins each in FRAME_REFINEMENTS
// by count and by probe, the same way as the policy_current ok-split in enclave.ts.
//   enroll_result    ok: true  -> REQUIRES credential_id; never reason
//                    ok: false -> REQUIRES reason; never credential_id
//   presence_result  ok: true  -> never reason
//                    ok: false -> REQUIRES reason

function okSplit<T extends { ok: boolean }>(
  tag: string,
  frame: T,
  ctx: z.RefinementCtx,
  onOk: { required?: keyof T & string; forbidden: readonly (keyof T & string)[] },
  onRefused: { required: keyof T & string; forbidden: readonly (keyof T & string)[] },
): void {
  const arm = frame.ok ? onOk : onRefused;
  if (arm.required !== undefined && frame[arm.required] === undefined) {
    ctx.addIssue({
      code: "custom",
      path: [arm.required],
      message: `${tag} ok:${frame.ok} always carries ${arm.required} (ok-split)`,
    });
  }
  for (const field of arm.forbidden) {
    if (frame[field] !== undefined) {
      ctx.addIssue({
        code: "custom",
        path: [field],
        message: `${tag} ok:${frame.ok} never carries ${field} (ok-split)`,
      });
    }
  }
}

export const EnrollResultSchema = EnrollResultFrameSchema.superRefine((frame, ctx) =>
  okSplit(
    "enroll_result",
    frame,
    ctx,
    { required: "credential_id", forbidden: ["reason"] },
    { required: "reason", forbidden: ["credential_id"] },
  ),
);

export type EnrollResult = z.infer<typeof EnrollResultSchema>;

export const PresenceResultSchema = PresenceResultFrameSchema.superRefine((frame, ctx) =>
  okSplit(
    "presence_result",
    frame,
    ctx,
    { forbidden: ["reason"] },
    { required: "reason", forbidden: [] },
  ),
);

export type PresenceResult = z.infer<typeof PresenceResultSchema>;

/** The verdicts as discriminated unions: what the refinements above guarantee, in a type consumers can
 * branch on without re-checking optional fields. `null` is a frame outside the producer's two shapes. */
export type EnrollVerdict = { ok: true; credentialId: string } | { ok: false; reason: string };
export type PresenceVerdict = { ok: true } | { ok: false; reason: string };

export function parseEnrollResult(frame: unknown): EnrollVerdict | null {
  const parsed = EnrollResultSchema.safeParse(frame);
  if (!parsed.success) return null;
  const { ok, credential_id, reason } = parsed.data;
  if (ok) return credential_id === undefined ? null : { ok: true, credentialId: credential_id };
  return reason === undefined ? null : { ok: false, reason };
}

export function parsePresenceResult(frame: unknown): PresenceVerdict | null {
  const parsed = PresenceResultSchema.safeParse(frame);
  if (!parsed.success) return null;
  const { ok, reason } = parsed.data;
  if (ok) return { ok: true };
  return reason === undefined ? null : { ok: false, reason };
}

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
