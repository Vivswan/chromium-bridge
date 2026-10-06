// GENERATED from the Rust core wire types (src/packages/core/src/protocol.rs and
// protocol/control.rs; AdminControl embeds allowlist::ClientEntry, PolicyControl embeds
// policy::PolicyOverlay, WebAuthnControl carries the WebAuthn ceremonies) by scripts/gen-envelope.ts -
// DO NOT EDIT. Edit the Rust types or
// src/packages/shared/src/envelope-asymmetries.ts, then run `moon run gen`.
//
// Per envelope, per server->extension signal frame, and per host->extension control frame: the FAITHFUL base
// (*WireSchema: strict objects, required fields required, no defaults; rules G1-G7 in scripts/gen-envelope.ts)
// and the ENFORCED validator the extension runs, which is the base plus exactly the asymmetry table
// (direction and reason per entry in envelope-asymmetries.ts; proved per entry by scripts/check-envelope.ts,
// `moon run check-envelope`). The extension->host writer schemas exist for their inferred types only
// (constructor-site `satisfies`); the enforcing reader for those frames is the Rust serde parser.

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

// The server->extension signal frames (BridgeSignal), one strict reader per variant: the faithful base,
// then the enforced validator the extension runs.
export const BridgeCancelWireSchema = z
  .object({ "id": z.number().int().gte(0), "type": z.literal("cancel") })
  .strict();

export const BridgeCancelSchema = z
  .object({ "id": z.union([z.number().int().gte(0), z.string()]), "type": z.literal("cancel") })
  .strict();

export type BridgeCancel = z.infer<typeof BridgeCancelSchema>;

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
    "name": z.string(),
  })
  .catchall(z.unknown());

export type TrustedClient = z.infer<typeof TrustedClientSchema>;

// One browser's registration row (protocol::control::RegistrationRow), embedded in registration_status_result's `browsers` array.
export const RegistrationRowWireSchema = z
  .object({
    "browser": z.string(),
    "detected": z.boolean(),
    "location": z.string(),
    "state": z.union([
      z.object({ "kind": z.literal("missing") }).strict(),
      z.object({ "kind": z.literal("ok") }).strict(),
      z.object({ "detail": z.string(), "kind": z.literal("stale") }).strict(),
      z.object({ "detail": z.string(), "kind": z.literal("foreign") }).strict(),
      z.object({ "detail": z.string(), "kind": z.literal("unreadable") }).strict(),
    ]),
  })
  .strict();

export const RegistrationRowSchema = z
  .object({
    "browser": z.string(),
    "detected": z.boolean(),
    "location": z.string(),
    "state": z.union([
      z.object({ "kind": z.literal("missing") }).catchall(z.unknown()),
      z.object({ "kind": z.literal("ok") }).catchall(z.unknown()),
      z.object({ "detail": z.string(), "kind": z.literal("stale") }).catchall(z.unknown()),
      z.object({ "detail": z.string(), "kind": z.literal("foreign") }).catchall(z.unknown()),
      z.object({ "detail": z.string(), "kind": z.literal("unreadable") }).catchall(z.unknown()),
    ]),
  })
  .catchall(z.unknown());

export type RegistrationRow = z.infer<typeof RegistrationRowSchema>;

// One line of the host's audit trail (protocol::control::AuditTrailEntry), embedded in audit_read_result's `entries` array.
export const AuditTrailEntryWireSchema = z.union([
  z
    .object({
      "entry": z.literal("record"),
      "fields": z.string(),
      "kind": z.string(),
      "ts_ms": z.number().int().gte(0),
    })
    .strict(),
  z.object({ "entry": z.literal("unrecognized"), "text": z.string() }).strict(),
]);

export const AuditTrailEntrySchema = z.union([
  z
    .object({
      "entry": z.literal("record"),
      "fields": z.string(),
      "kind": z.string(),
      "ts_ms": z.number().int().gte(0),
    })
    .catchall(z.unknown()),
  z.object({ "entry": z.literal("unrecognized"), "text": z.string() }).catchall(z.unknown()),
]);

export type AuditTrailEntry = z.infer<typeof AuditTrailEntrySchema>;

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

export const RegistrationStatusResultWireSchema = z
  .object({
    "browsers": z.union([z.array(RegistrationRowWireSchema), z.null()]).optional(),
    "error": z.union([z.string(), z.null()]).optional(),
    "ok": z.boolean(),
    "type": z.literal("registration_status_result"),
  })
  .strict();

export const RegistrationStatusResultSchema = z.discriminatedUnion("ok", [
  z
    .object({
      "browsers": z.array(RegistrationRowSchema),
      "error": z.undefined().optional(),
      "ok": z.literal(true),
      "type": z.literal("registration_status_result"),
    })
    .catchall(z.unknown()),
  z
    .object({
      "browsers": z.undefined().optional(),
      "error": z.string(),
      "ok": z.literal(false),
      "type": z.literal("registration_status_result"),
    })
    .catchall(z.unknown()),
]);

export type RegistrationStatusResult = z.infer<typeof RegistrationStatusResultSchema>;

export const AuditReadResultWireSchema = z
  .object({
    "entries": z.union([z.array(AuditTrailEntryWireSchema), z.null()]).optional(),
    "error": z.union([z.string(), z.null()]).optional(),
    "ok": z.boolean(),
    "older": z.union([z.number().int().gte(0), z.null()]).optional(),
    "path": z.union([z.string(), z.null()]).optional(),
    "type": z.literal("audit_read_result"),
  })
  .strict();

export const AuditReadResultSchema = z.discriminatedUnion("ok", [
  z
    .object({
      "entries": z.array(AuditTrailEntrySchema),
      "error": z.undefined().optional(),
      "ok": z.literal(true),
      "older": z.number().int().gte(0),
      "path": z.string(),
      "type": z.literal("audit_read_result"),
    })
    .catchall(z.unknown()),
  z
    .object({
      "entries": z.undefined().optional(),
      "error": z.string(),
      "ok": z.literal(false),
      "older": z.undefined().optional(),
      "path": z.undefined().optional(),
      "type": z.literal("audit_read_result"),
    })
    .catchall(z.unknown()),
]);

export type AuditReadResult = z.infer<typeof AuditReadResultSchema>;

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
            "presenceConfirm": z.union([z.boolean(), z.null()]).optional(),
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

export const PolicyCurrentFrameSchema = z.discriminatedUnion("ok", [
  z
    .object({
      "baseline": z.string().min(1),
      "error": z.undefined().optional(),
      "ok": z.literal(true),
      "overlay": PolicyOverlaySchema.optional(),
      "sig": z.string().min(1).optional(),
      "type": z.literal("policy_current"),
    })
    .catchall(z.unknown()),
  z
    .object({
      "baseline": z.undefined().optional(),
      "error": z.string(),
      "ok": z.literal(false),
      "overlay": z.undefined().optional(),
      "sig": z.undefined().optional(),
      "type": z.literal("policy_current"),
    })
    .catchall(z.unknown()),
]);

export type PolicyCurrentFrame = z.infer<typeof PolicyCurrentFrameSchema>;

export const PolicyRestrictResultWireSchema = z
  .object({
    "error": z.union([z.string(), z.null()]).optional(),
    "ok": z.boolean(),
    "type": z.literal("policy_restrict_result"),
  })
  .strict();

export const PolicyRestrictResultSchema = z.discriminatedUnion("ok", [
  z
    .object({
      "error": z.undefined().optional(),
      "ok": z.literal(true),
      "type": z.literal("policy_restrict_result"),
    })
    .catchall(z.unknown()),
  z
    .object({
      "error": z.string(),
      "ok": z.literal(false),
      "type": z.literal("policy_restrict_result"),
    })
    .catchall(z.unknown()),
]);

export type PolicyRestrictResult = z.infer<typeof PolicyRestrictResultSchema>;

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

export const EnrollOptionsWireSchema = z
  .object({
    "challenge": z.string(),
    "exclude_credential_ids": z.array(z.string()),
    "nonce": z.string(),
    "type": z.literal("enroll_options"),
    "user_id": z.string(),
    "user_name": z.string(),
  })
  .strict();

export const EnrollOptionsFrameSchema = z
  .object({
    "challenge": z.string().min(1),
    "exclude_credential_ids": z.array(z.string()),
    "nonce": z.string(),
    "type": z.literal("enroll_options"),
    "user_id": z.string(),
    "user_name": z.string(),
  })
  .catchall(z.unknown());

export type EnrollOptionsFrame = z.infer<typeof EnrollOptionsFrameSchema>;

export const EnrollResultWireSchema = z
  .object({
    "credential_id": z.union([z.string(), z.null()]).optional(),
    "ok": z.boolean(),
    "reason": z.union([z.string(), z.null()]).optional(),
    "type": z.literal("enroll_result"),
  })
  .strict();

export const EnrollResultFrameSchema = z.discriminatedUnion("ok", [
  z
    .object({
      "credential_id": z.string().min(1),
      "ok": z.literal(true),
      "reason": z.undefined().optional(),
      "type": z.literal("enroll_result"),
    })
    .catchall(z.unknown()),
  z
    .object({
      "credential_id": z.undefined().optional(),
      "ok": z.literal(false),
      "reason": z.string(),
      "type": z.literal("enroll_result"),
    })
    .catchall(z.unknown()),
]);

export type EnrollResultFrame = z.infer<typeof EnrollResultFrameSchema>;

export const PresenceRequestWireSchema = z
  .object({
    "action": z.string(),
    "allowed_credential_ids": z.array(z.string()),
    "challenge": z.string(),
    "nonce": z.string(),
    "type": z.literal("presence_request"),
  })
  .strict();

export const PresenceRequestFrameSchema = z
  .object({
    "action": z.string().min(1),
    "allowed_credential_ids": z.array(z.string()),
    "challenge": z.string().min(1),
    "nonce": z.string(),
    "type": z.literal("presence_request"),
  })
  .catchall(z.unknown());

export type PresenceRequestFrame = z.infer<typeof PresenceRequestFrameSchema>;

export const PresenceResultWireSchema = z
  .object({
    "ok": z.boolean(),
    "reason": z.union([z.string(), z.null()]).optional(),
    "type": z.literal("presence_result"),
  })
  .strict();

export const PresenceResultFrameSchema = z.discriminatedUnion("ok", [
  z
    .object({
      "ok": z.literal(true),
      "reason": z.undefined().optional(),
      "type": z.literal("presence_result"),
    })
    .catchall(z.unknown()),
  z
    .object({ "ok": z.literal(false), "reason": z.string(), "type": z.literal("presence_result") })
    .catchall(z.unknown()),
]);

export type PresenceResultFrame = z.infer<typeof PresenceResultFrameSchema>;

export const BrowserRevokeResultWireSchema = z
  .object({
    "ok": z.boolean(),
    "reason": z.union([z.string(), z.null()]).optional(),
    "type": z.literal("browser_revoke_result"),
  })
  .strict();

export const BrowserRevokeResultFrameSchema = z.discriminatedUnion("ok", [
  z
    .object({
      "ok": z.literal(true),
      "reason": z.undefined().optional(),
      "type": z.literal("browser_revoke_result"),
    })
    .catchall(z.unknown()),
  z
    .object({
      "ok": z.literal(false),
      "reason": z.string(),
      "type": z.literal("browser_revoke_result"),
    })
    .catchall(z.unknown()),
]);

export type BrowserRevokeResultFrame = z.infer<typeof BrowserRevokeResultFrameSchema>;

// Which control-frame tags have a generated reader above, and which are bare classification tags.
// scripts/check-envelope.ts holds the extension's inbound classifiers to these.
export const GENERATED_WIRE_FRAMES = {
  enclave: ["enclave_proof", "enclave_error"],
  admin: [
    "client_list_result",
    "client_revoke_result",
    "kill_status_result",
    "registration_status_result",
    "audit_read_result",
  ],
  policy: ["policy_current", "policy_restrict_result", "lang_current"],
  webauthn: [
    "enroll_options",
    "enroll_result",
    "presence_request",
    "presence_result",
    "browser_revoke_result",
  ],
} as const;

export const BARE_TAG_FRAMES = {
  enclave: ["enclave_revoked"],
  admin: [],
  policy: [],
  webauthn: [],
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

export const AuditReadWireSchema = z
  .object({
    "limit": z.union([z.number().int().gte(0), z.null()]).optional(),
    "type": z.literal("audit_read"),
  })
  .strict();

export type AuditReadWire = z.infer<typeof AuditReadWireSchema>;

export const RegistrationStatusWireSchema = z
  .object({ "type": z.literal("registration_status") })
  .strict();

export type RegistrationStatusWire = z.infer<typeof RegistrationStatusWireSchema>;

export const RegistrationRepairWireSchema = z
  .object({
    "browsers": z.union([z.array(z.string()), z.null()]).optional(),
    "type": z.literal("registration_repair"),
  })
  .strict();

export type RegistrationRepairWire = z.infer<typeof RegistrationRepairWireSchema>;

export const PolicyGetWireSchema = z.object({ "type": z.literal("policy_get") }).strict();

export type PolicyGetWire = z.infer<typeof PolicyGetWireSchema>;

export const PolicyRestrictWireSchema = z
  .object({
    "overlay": z
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
        "presenceConfirm": z.union([z.boolean(), z.null()]).optional(),
        "warnPreciseSnapshot": z.union([z.boolean(), z.null()]).optional(),
      })
      .strict(),
    "type": z.literal("policy_restrict"),
  })
  .strict();

export type PolicyRestrictWire = z.infer<typeof PolicyRestrictWireSchema>;

export const LangSetWireSchema = z
  .object({ "type": z.literal("lang_set"), "value": z.string() })
  .strict();

export type LangSetWire = z.infer<typeof LangSetWireSchema>;

export const LangGetWireSchema = z.object({ "type": z.literal("lang_get") }).strict();

export type LangGetWire = z.infer<typeof LangGetWireSchema>;

export const EnrollBeginWireSchema = z.object({ "type": z.literal("enroll_begin") }).strict();

export type EnrollBeginWire = z.infer<typeof EnrollBeginWireSchema>;

export const EnrollFinishWireSchema = z
  .object({
    "attestation_object": z.string(),
    "client_data_json": z.string(),
    "type": z.literal("enroll_finish"),
  })
  .strict();

export type EnrollFinishWire = z.infer<typeof EnrollFinishWireSchema>;

export const PresenceAssertWireSchema = z
  .object({
    "authenticator_data": z.string(),
    "client_data_json": z.string(),
    "credential_id": z.string(),
    "signature": z.string(),
    "type": z.literal("presence_assert"),
  })
  .strict();

export type PresenceAssertWire = z.infer<typeof PresenceAssertWireSchema>;

export const PresenceConfirmWireSchema = z
  .object({ "nonce": z.string(), "type": z.literal("presence_confirm") })
  .strict();

export type PresenceConfirmWire = z.infer<typeof PresenceConfirmWireSchema>;

export const BrowserRevokeWireSchema = z.object({ "type": z.literal("browser_revoke") }).strict();

export type BrowserRevokeWire = z.infer<typeof BrowserRevokeWireSchema>;

// Which extension->host frames have a generated writer schema above.
export const GENERATED_WRITER_FRAMES = {
  enclave: ["enclave_challenge", "enclave_revoke"],
  admin: [
    "client_list",
    "client_revoke",
    "kill_status",
    "kill_engage",
    "kill_release",
    "audit_event",
    "audit_read",
    "registration_status",
    "registration_repair",
  ],
  policy: ["policy_get", "policy_restrict", "lang_set", "lang_get"],
  webauthn: [
    "enroll_begin",
    "enroll_finish",
    "presence_assert",
    "presence_confirm",
    "browser_revoke",
  ],
} as const;
