// GENERATED from the Rust core wire types (src/packages/core/src/protocol.rs and
// protocol/control.rs; AdminControl embeds allowlist::ClientEntry, PolicyControl embeds
// policy::PolicyOverlay) by scripts/gen-envelope.ts - DO NOT EDIT. Edit the Rust types or
// src/packages/shared/src/envelope-asymmetries.ts, then run `moon run gen`.
//
// Per envelope and per host->extension control frame: the FAITHFUL base (*WireSchema: strict objects,
// required fields required, no defaults; rules G1-G7 in scripts/gen-envelope.ts) and the ENFORCED validator
// the extension runs, which is the base plus exactly the asymmetry table (direction and reason per entry in
// envelope-asymmetries.ts; proved per entry by scripts/check-envelope.ts, `moon run check-envelope`). The
// policy_current reader is completed by the ok-split refinement in enclave.ts. The extension->host writer
// schemas exist for their inferred types only (constructor-site `satisfies`); the enforcing reader for those
// frames is the Rust serde parser.

import { z } from "zod";
import { OpArgsSchema } from "./ops.gen";
import { PolicyOverlaySchema } from "./policy.gen";

// The request envelope (BridgeReq) and the response envelope (BridgeResp): the faithful bases, then the
// enforced validators the extension runs (the base plus the asymmetry table; strict like the host).
export const BridgeReqWireSchema = z
  .object({
    "args": z.unknown(),
    "browser": z.union([z.string(), z.null()]).optional(),
    "id": z.number().int().gte(0),
    "op": z.string(),
  })
  .strict();

export const BridgeRespWireSchema = z
  .object({
    "data": z.unknown().optional(),
    "error": z.union([z.string(), z.null()]).optional(),
    "id": z.number().int().gte(0),
    "ok": z.boolean(),
  })
  .strict();

export const BridgeReqSchema = z
  .object({
    "args": OpArgsSchema,
    "browser": z
      .string()
      .min(1)
      .max(32)
      .regex(/^[A-Za-z0-9._-]+$/)
      .optional(),
    "id": z.union([z.number().int().gte(0), z.string()]),
    "op": z.string().min(1),
  })
  .strict();

export type BridgeReqEnvelope = z.infer<typeof BridgeReqSchema>;

export const BridgeRespSchema = z
  .object({
    "data": z.unknown().optional(),
    "error": z.string().optional(),
    "id": z.union([z.number().int().gte(0), z.string()]),
    "ok": z.boolean(),
  })
  .strict();

export type BridgeResp = z.infer<typeof BridgeRespSchema>;

// One trusted-client entry (allowlist::ClientEntry), embedded in client_list_result's `clients` array.
export const ClientEntryWireSchema = z
  .object({
    "added_unix": z.number().int().gte(0),
    "anchor": z.union([
      z.object({ "kind": z.literal("hash"), "value": z.string() }).strict(),
      z.object({ "kind": z.literal("signer"), "value": z.string() }).strict(),
    ]),
    "name": z.string(),
  })
  .strict();

export const TrustedClientSchema = z
  .object({
    "added_unix": z.number().int().gte(0),
    "anchor": z
      .object({ "kind": z.enum(["hash", "signer"]), "value": z.string().min(1) })
      .catchall(z.unknown()),
    "name": z.string().min(1),
  })
  .catchall(z.unknown());

export type TrustedClient = z.infer<typeof TrustedClientSchema>;

// The host->extension control frames: the faithful base, then the enforced reader (the base plus the
// asymmetry table, read loose under its loose-frames rule).
export const EnclaveProofWireSchema = z
  .object({
    "key_id": z.string(),
    "pubkey": z.string(),
    "sig": z.string(),
    "type": z.literal("enclave_proof"),
  })
  .strict();

export const EnclaveProofFrameSchema = z
  .object({
    "key_id": z.string().min(1),
    "pubkey": z.string().min(1),
    "sig": z.string().min(1),
    "type": z.literal("enclave_proof"),
  })
  .catchall(z.unknown());

export type EnclaveProofFrame = z.infer<typeof EnclaveProofFrameSchema>;

export const EnclaveErrorWireSchema = z
  .object({ "reason": z.string(), "type": z.literal("enclave_error") })
  .strict();

export const EnclaveErrorFrameSchema = z
  .object({ "reason": z.string(), "type": z.literal("enclave_error") })
  .catchall(z.unknown());

export type EnclaveErrorFrame = z.infer<typeof EnclaveErrorFrameSchema>;

export const PresenceProofWireSchema = z
  .object({
    "key_id": z.string(),
    "pubkey": z.string(),
    "sig": z.string(),
    "type": z.literal("presence_proof"),
  })
  .strict();

export const PresenceProofFrameSchema = z
  .object({
    "key_id": z.string().min(1),
    "pubkey": z.string().min(1),
    "sig": z.string().min(1),
    "type": z.literal("presence_proof"),
  })
  .catchall(z.unknown());

export type PresenceProofFrame = z.infer<typeof PresenceProofFrameSchema>;

export const PresenceErrorWireSchema = z
  .object({ "reason": z.string(), "type": z.literal("presence_error") })
  .strict();

export const PresenceErrorFrameSchema = z
  .object({ "reason": z.string(), "type": z.literal("presence_error") })
  .catchall(z.unknown());

export type PresenceErrorFrame = z.infer<typeof PresenceErrorFrameSchema>;

export const ClientListResultWireSchema = z
  .object({
    "clients": z.array(ClientEntryWireSchema),
    "enrolled": z.boolean(),
    "error": z.union([z.string(), z.null()]).optional(),
    "ok": z.boolean(),
    "type": z.literal("client_list_result"),
  })
  .strict();

export const ClientListResultSchema = z
  .object({
    "clients": z.array(TrustedClientSchema),
    "enrolled": z.boolean(),
    "error": z.string().optional(),
    "ok": z.boolean(),
    "type": z.literal("client_list_result"),
  })
  .catchall(z.unknown());

export type ClientListResult = z.infer<typeof ClientListResultSchema>;

export const ClientRevokeResultWireSchema = z
  .object({
    "error": z.union([z.string(), z.null()]).optional(),
    "ok": z.boolean(),
    "type": z.literal("client_revoke_result"),
  })
  .strict();

export const ClientRevokeResultSchema = z
  .object({
    "error": z.string().optional(),
    "ok": z.boolean(),
    "type": z.literal("client_revoke_result"),
  })
  .catchall(z.unknown());

export type ClientRevokeResult = z.infer<typeof ClientRevokeResultSchema>;

export const KillStatusResultWireSchema = z
  .object({
    "error": z.union([z.string(), z.null()]).optional(),
    "killed": z.union([z.boolean(), z.null()]).optional(),
    "ok": z.boolean(),
    "type": z.literal("kill_status_result"),
  })
  .strict();

export const KillStatusResultSchema = z
  .object({
    "error": z.string().optional(),
    "killed": z.boolean().optional(),
    "ok": z.boolean(),
    "type": z.literal("kill_status_result"),
  })
  .catchall(z.unknown());

export type KillStatusResult = z.infer<typeof KillStatusResultSchema>;

export const PolicyCurrentWireSchema = z
  .object({
    "baseline": z.union([z.string(), z.null()]).optional(),
    "error": z.union([z.string(), z.null()]).optional(),
    "ok": z.boolean(),
    "overlay": z
      .union([
        z
          .object({
            "cdpMode": z.union([z.boolean(), z.null()]).optional(),
            "clickToastTimeoutMs": z.union([z.number().int().gte(0), z.null()]).optional(),
            "confirmGraceMs": z.union([z.number().int().gte(0), z.null()]).optional(),
            "confirmHighRiskClick": z.union([z.boolean(), z.null()]).optional(),
            "confirmPageEval": z.union([z.boolean(), z.null()]).optional(),
            "confirmTabClose": z.union([z.boolean(), z.null()]).optional(),
            "disabledTools": z.union([z.array(z.string()), z.null()]).optional(),
            "evalMask": z.union([z.boolean(), z.null()]).optional(),
            "evalToastTimeoutMs": z.union([z.number().int().gte(0), z.null()]).optional(),
            "fileUploadEnabled": z.union([z.boolean(), z.null()]).optional(),
            "handleDialogEnabled": z.union([z.boolean(), z.null()]).optional(),
            "hostReverifyMs": z.union([z.number().int().gte(0), z.null()]).optional(),
            "pageEvalEnabled": z.union([z.boolean(), z.null()]).optional(),
            "touchIdConfirm": z.union([z.boolean(), z.null()]).optional(),
            "warnPreciseSnapshot": z.union([z.boolean(), z.null()]).optional(),
          })
          .strict(),
        z.null(),
      ])
      .optional(),
    "sig": z.union([z.string(), z.null()]).optional(),
    "type": z.literal("policy_current"),
  })
  .strict();

export const PolicyCurrentFrameShapeSchema = z
  .object({
    "baseline": z.string().min(1).optional(),
    "error": z.string().optional(),
    "ok": z.boolean(),
    "overlay": PolicyOverlaySchema.optional(),
    "sig": z.string().min(1).optional(),
    "type": z.literal("policy_current"),
  })
  .catchall(z.unknown());

export type PolicyCurrentFrameShape = z.infer<typeof PolicyCurrentFrameShapeSchema>;

export const LangCurrentWireSchema = z
  .object({
    "seq": z.number().int().gte(0),
    "type": z.literal("lang_current"),
    "value": z.string(),
  })
  .strict();

export const LangCurrentFrameSchema = z
  .object({
    "seq": z.number().int().gte(0),
    "type": z.literal("lang_current"),
    "value": z.string(),
  })
  .catchall(z.unknown());

export type LangCurrentFrame = z.infer<typeof LangCurrentFrameSchema>;

// Which control-frame tags have a generated reader above, and which are bare classification tags.
// scripts/check-envelope.ts holds the extension's inbound classifiers to these.
export const GENERATED_WIRE_FRAMES = {
  enclave: ["enclave_proof", "enclave_error", "presence_proof", "presence_error"],
  admin: ["client_list_result", "client_revoke_result", "kill_status_result"],
  policy: ["policy_current", "lang_current"],
} as const;

export const BARE_TAG_FRAMES = {
  enclave: ["enclave_revoked"],
  admin: [],
  policy: [],
} as const;

// The extension->host writer frames (the extension constructs these; the enforcing reader is the Rust
// serde parser). Emitted for their inferred types: constructor sites claim conformance with `satisfies`,
// so a drifted field or tag is a compile error. Never used as runtime parsers.
export const EnclaveChallengeWireSchema = z
  .object({
    "context": z.union([z.string(), z.null()]).optional(),
    "nonce": z.string(),
    "type": z.literal("enclave_challenge"),
  })
  .strict();

export type EnclaveChallengeWire = z.infer<typeof EnclaveChallengeWireSchema>;

export const EnclaveRevokeWireSchema = z.object({ "type": z.literal("enclave_revoke") }).strict();

export type EnclaveRevokeWire = z.infer<typeof EnclaveRevokeWireSchema>;

export const PresenceChallengeWireSchema = z
  .object({
    "context": z.union([z.string(), z.null()]).optional(),
    "nonce": z.string(),
    "type": z.literal("presence_challenge"),
  })
  .strict();

export type PresenceChallengeWire = z.infer<typeof PresenceChallengeWireSchema>;

export const ClientListWireSchema = z.object({ "type": z.literal("client_list") }).strict();

export type ClientListWire = z.infer<typeof ClientListWireSchema>;

export const ClientRevokeWireSchema = z
  .object({ "name": z.string(), "type": z.literal("client_revoke") })
  .strict();

export type ClientRevokeWire = z.infer<typeof ClientRevokeWireSchema>;

export const KillStatusWireSchema = z.object({ "type": z.literal("kill_status") }).strict();

export type KillStatusWire = z.infer<typeof KillStatusWireSchema>;

export const KillEngageWireSchema = z.object({ "type": z.literal("kill_engage") }).strict();

export type KillEngageWire = z.infer<typeof KillEngageWireSchema>;

export const KillReleaseWireSchema = z.object({ "type": z.literal("kill_release") }).strict();

export type KillReleaseWire = z.infer<typeof KillReleaseWireSchema>;

export const AuditEventWireSchema = z
  .object({
    "cid": z.union([z.string(), z.null()]).optional(),
    "detail": z.union([z.string(), z.null()]).optional(),
    "kind": z.string(),
    "name": z.union([z.string(), z.null()]).optional(),
    "outcome": z.union([z.string(), z.null()]).optional(),
    "tool": z.union([z.string(), z.null()]).optional(),
    "type": z.literal("audit_event"),
  })
  .strict();

export type AuditEventWire = z.infer<typeof AuditEventWireSchema>;

export const PolicyGetWireSchema = z.object({ "type": z.literal("policy_get") }).strict();

export type PolicyGetWire = z.infer<typeof PolicyGetWireSchema>;

export const LangSetWireSchema = z
  .object({ "type": z.literal("lang_set"), "value": z.string() })
  .strict();

export type LangSetWire = z.infer<typeof LangSetWireSchema>;

export const LangGetWireSchema = z.object({ "type": z.literal("lang_get") }).strict();

export type LangGetWire = z.infer<typeof LangGetWireSchema>;

// Which extension->host frames have a generated writer schema above.
export const GENERATED_WRITER_FRAMES = {
  enclave: ["enclave_challenge", "enclave_revoke", "presence_challenge"],
  admin: [
    "client_list",
    "client_revoke",
    "kill_status",
    "kill_engage",
    "kill_release",
    "audit_event",
  ],
  policy: ["policy_get", "lang_set", "lang_get"],
} as const;
