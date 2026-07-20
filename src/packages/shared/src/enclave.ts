// Shapes for the ADR-0021 enclave enrollment ceremony and the ADR-0025
// revocation/admin exchange: the control frames exchanged with the native
// host over the native-messaging port, and the records the extension persists
// in chrome.storage.local.
//
// The canonical frame contract is the Rust control-frame enums
// (EnclaveControl / AdminControl in src/packages/core/src/protocol.rs,
// ADR-0028). The base wire schemas are GENERATED from them
// (envelope-wire.gen.ts, `moon run gen`); this module layers the extension's
// DELIBERATE parser asymmetries on top, each pinned in RECONCILED_FIELDS
// (json-schema-normalize.ts), held to exactly that list by the parity gate
// (scripts/check-envelope-parity.ts), and exercised behaviorally in
// tests/envelope-wire.gen.test.ts.
//
// ASYMMETRY (loose frames, rule R5): the generated bases are strict (the
// host refuses unknown fields on these security frames), but the extension
// reads them loose - .catchall(z.unknown()) below - because the host may add
// fields and the security decision is made from the validated fields plus
// the cryptographic verification in background/enclave-verify.ts, never from
// a frame merely having the right shape. Storage records are strict: a
// record with unexpected fields is treated as absent, which fails closed at
// the enrollment gate.

import { z } from "zod";
import {
  ClientEntryWireSchema,
  ClientListResultWireSchema,
  ClientRevokeResultWireSchema,
  EnclaveErrorWireSchema,
  EnclaveProofWireSchema,
  KillStatusResultWireSchema,
  PresenceErrorWireSchema,
  PresenceProofWireSchema,
} from "./envelope-wire.gen";

export const ENCLAVE_FRAME_TYPES = [
  "enclave_challenge",
  "enclave_proof",
  "enclave_error",
  // ADR-0025: extension -> host key-deletion request, and the host-originated
  // "the key is gone" notice/ack. Both classify as ceremony traffic; the
  // handlers drop the directions that make no sense inbound.
  "enclave_revoke",
  "enclave_revoked",
] as const;

// Classification only: is this native-messaging frame ceremony traffic
// (carries `type`) rather than a bridge request (carries `op`)? A frame that
// classifies as enclave traffic but fails its per-type schema is still
// ceremony traffic - it is handled (and refused) there, never dispatched.
export const EnclaveInboundFrameSchema = z.looseObject({
  type: z.enum(ENCLAVE_FRAME_TYPES),
});

export type EnclaveInboundFrame = z.infer<typeof EnclaveInboundFrameSchema>;

// A proof answering an outstanding challenge: the enclave signature over the
// nonce+context, the key's fingerprint, and the public key (X9.63, base64).
// ASYMMETRY (sig/key_id/pubkey): refuse the empty string early on the key
// material the host always sends non-empty; the Rust side leaves that to the
// consumer (signature verification). Plus R5 loose (module doc).
export const EnclaveProofFrameSchema = EnclaveProofWireSchema.extend({
  sig: z.string().min(1),
  key_id: z.string().min(1),
  pubkey: z.string().min(1),
}).catchall(z.unknown());

export type EnclaveProofFrame = z.infer<typeof EnclaveProofFrameSchema>;

// `reason` is required on both sides (the host always names its denial);
// only the R5 looseness (module doc) distinguishes this from the base.
export const EnclaveErrorFrameSchema = EnclaveErrorWireSchema.catchall(z.unknown());

export type EnclaveErrorFrame = z.infer<typeof EnclaveErrorFrameSchema>;

// ---- ADR-0031: per-action user-presence frames (host-handled) -----------------

// The host's answers to a presence_challenge (the request is outbound only
// and never classifies inbound). Distinct from the enrollment ceremony
// frames on purpose: they are correlated by the confirmation provider, not
// the enrollment state machine, and the signature they carry covers the
// PRESENCE domain ("chromium-bridge-presence-v1"), never the enrollment one.
export const PRESENCE_FRAME_TYPES = ["presence_proof", "presence_error"] as const;

export const PresenceInboundFrameSchema = z.looseObject({
  type: z.enum(PRESENCE_FRAME_TYPES),
});

export type PresenceInboundFrame = z.infer<typeof PresenceInboundFrameSchema>;

// The signed per-action approval: same encoding as an enclave_proof, under
// the presence domain. MUST be verified against the PINNED key.
// ASYMMETRY (sig/key_id/pubkey): non-empty early, like EnclaveProofFrameSchema.
export const PresenceProofFrameSchema = PresenceProofWireSchema.extend({
  sig: z.string().min(1),
  key_id: z.string().min(1),
  pubkey: z.string().min(1),
}).catchall(z.unknown());

export type PresenceProofFrame = z.infer<typeof PresenceProofFrameSchema>;

// Stable reasons: the enclave reason codes plus "bridge_killed" and "busy".
// Every reason is a denial; there is no fallback surface (no-downgrade rule).
// Required, like enclave_error: the host always names its denial.
export const PresenceErrorFrameSchema = PresenceErrorWireSchema.catchall(z.unknown());

export type PresenceErrorFrame = z.infer<typeof PresenceErrorFrameSchema>;

// ---- ADR-0025: trusted-client admin frames (host-handled) --------------------

export const ADMIN_RESULT_FRAME_TYPES = ["client_list_result", "client_revoke_result"] as const;

// Classification for the admin replies the host sends back. Requests
// (client_list / client_revoke) are outbound only and never classify inbound.
export const AdminInboundFrameSchema = z.looseObject({
  type: z.enum(ADMIN_RESULT_FRAME_TYPES),
});

export type AdminInboundFrame = z.infer<typeof AdminInboundFrameSchema>;

// One trusted MCP client, in the host's on-disk entry shape. The anchor is
// the authorization key (attested image hash or macOS signing Team ID); the
// name is a human-facing label.
export const TrustedClientSchema = ClientEntryWireSchema.extend({
  // ASYMMETRY (name): non-empty early (a validated client label).
  name: z.string().min(1),
  // ASYMMETRY (anchor): the Rust side is serde adjacently-tagged (one strict
  // object variant per kind); this side spells the same instance set as a
  // single loose object with a two-value kind enum plus the non-empty guard
  // on value (pinned as ANCHOR_FIELD in json-schema-normalize.ts).
  anchor: z.looseObject({
    kind: z.enum(["hash", "team_id"]),
    value: z.string().min(1),
  }),
  // ASYMMETRY (added_unix): u64 + #[serde(default)] on the Rust side (absent
  // reads as 0 there); here absence stays absent - no invented value - and
  // the integer is hardened to the JS-safe non-negative range (same idiom as
  // the envelope id). Unix seconds, for the audit/status surface.
  added_unix: z.int().nonnegative().optional(),
}).catchall(z.unknown());

export type TrustedClient = z.infer<typeof TrustedClientSchema>;

export const ClientListResultSchema = ClientListResultWireSchema.extend({
  clients: z.array(TrustedClientSchema),
  // ASYMMETRY (error): no null arm (serde's Option; writers omit absent errors).
  error: z.string().optional(),
}).catchall(z.unknown());

export type ClientListResult = z.infer<typeof ClientListResultSchema>;

export const ClientRevokeResultSchema = ClientRevokeResultWireSchema.extend({
  // ASYMMETRY (error): no null arm, as above.
  error: z.string().optional(),
}).catchall(z.unknown());

export type ClientRevokeResult = z.infer<typeof ClientRevokeResultSchema>;

// ---- ADR-0030: kill-switch frames and the SW-only mirror ---------------------

// The host's answer to kill_status / kill_engage / kill_release, ALSO pushed
// unsolicited at host startup and on observed transitions. `ok: false` (state
// unreadable host-side) deliberately carries no `killed` claim; the extension
// treats it as unknown and fails closed.
export const KillStatusResultSchema = KillStatusResultWireSchema.extend({
  // ASYMMETRY (killed): no null arm (serde's Option<bool>).
  killed: z.boolean().optional(),
  // ASYMMETRY (error): no null arm, as above.
  error: z.string().optional(),
}).catchall(z.unknown());

export type KillStatusResult = z.infer<typeof KillStatusResultSchema>;

/** Classification only: is this frame the kill-status result? */
export function isKillStatusFrame(msg: unknown): msg is KillStatusResult {
  return KillStatusResultSchema.safeParse(msg).success;
}

// The extension-side mirror of the host's kill state, persisted in the #32
// SW-only trusted storage. STRICT: a record with unexpected fields (or a
// non-record value) is tampering evidence and the gate refuses on it rather
// than treating it as absent - absent means "never heard from the host"
// (allowed locally; the host side enforces), so mapping garbage to absent
// would fail OPEN.
export const KillMirrorSchema = z.strictObject({
  state: z.enum(["alive", "killed", "unknown"]),
  at: z.number(),
});

export type KillMirror = z.infer<typeof KillMirrorSchema>;

// ---- ADR-0030: the extension-side audit ring ---------------------------------

// The audit kinds the extension records locally (and forwards to the host's
// on-disk trail via the audit_event control frame, which the host accepts
// only for the extension-owned confirm_*/enroll_* kinds).
export const AUDIT_EVENT_KINDS = [
  "confirm_shown",
  "confirm_allowed",
  "confirm_denied",
  "enroll_approved",
  "enroll_rejected",
  "enroll_revoked",
  "client_revoked",
  "kill_engaged",
  "kill_released",
  "kill_status_changed",
] as const;

export type AuditEventKind = (typeof AUDIT_EVENT_KINDS)[number];

// One entry of the ring in trusted storage. Strict, like every stored trust
// record: an entry that fails this shape is dropped on read (the ring is
// display-only, so dropping is safe and fail-closed for the panel).
export const AuditEntrySchema = z.strictObject({
  at: z.number(),
  kind: z.enum(AUDIT_EVENT_KINDS),
  outcome: z.string().max(256).optional(),
  tool: z.string().max(256).optional(),
  name: z.string().max(256).optional(),
  detail: z.string().max(512).optional(),
});

export type AuditEntry = z.infer<typeof AuditEntrySchema>;

const KEY_ID_HEX = /^[0-9a-f]{64}$/;

// The pinned enrollment key: the extension-side trust anchor.
export const EnclavePinSchema = z.strictObject({
  // Lowercase-hex SHA-256 of the pubkey (the fingerprint).
  keyId: z.string().regex(KEY_ID_HEX),
  // Base64 of the 65-byte X9.63 point.
  pubkeyB64: z.string().min(1),
  pinnedAt: z.number(),
});

export type EnclavePin = z.infer<typeof EnclavePinSchema>;

// A ceremony proof that verified but has not been user-approved yet.
export const PendingPairingSchema = z.strictObject({
  keyId: z.string().regex(KEY_ID_HEX),
  pubkeyB64: z.string().min(1),
  at: z.number(),
});

export type PendingPairing = z.infer<typeof PendingPairingSchema>;

// Set when a pinned-key verification failed: the bridge fails closed until
// the user revokes the pin and re-pairs.
export const CompromisedMarkSchema = z.strictObject({
  reason: z.string().min(1),
  at: z.number(),
});

export type CompromisedMark = z.infer<typeof CompromisedMarkSchema>;
