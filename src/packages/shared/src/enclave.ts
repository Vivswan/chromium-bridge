// Shapes for the ADR-0021 enclave enrollment ceremony, the ADR-0025
// revocation/admin exchange, and the ADR-0032 policy/language sync: the
// control frames exchanged with the native host over the native-messaging
// port, and the records the extension persists in chrome.storage.local.
//
// The canonical frame contract is the Rust control-frame enums
// (EnclaveControl / AdminControl / PolicyControl in
// src/packages/core/src/protocol.rs, ADR-0028). The base wire schemas are
// GENERATED from them (envelope-wire.gen.ts, `moon run gen`); this module
// layers the extension's DELIBERATE parser asymmetries on top, each pinned
// in RECONCILED_FIELDS (json-schema-normalize.ts), held to exactly that
// list by the parity gate (scripts/check-envelope-parity.ts), and exercised
// behaviorally in tests/envelope-wire.gen.test.ts.
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
import { AUDIT_FORWARDED_KINDS } from "./audit.gen";
import { ENCLAVE_FIXTURE_KEY_ID } from "./enclave.gen";
import {
  ClientEntryWireSchema,
  ClientListResultWireSchema,
  ClientRevokeResultWireSchema,
  EnclaveErrorWireSchema,
  EnclaveProofWireSchema,
  KillStatusResultWireSchema,
  LangCurrentWireSchema,
  PolicyCurrentWireSchema,
  PresenceErrorWireSchema,
  PresenceProofWireSchema,
} from "./envelope-wire.gen";
import { POLICY_REVISION_MAX, PolicyOverlaySchema, PolicyValuesSchema } from "./policy.gen";

// ---- extension->host writer frames (generated, compile-time only) ------------

// The frames the extension CONSTRUCTS. The enforcing reader is the Rust
// serde parser (deny_unknown_fields); these generated types give every
// constructor site compile-time conformance (`satisfies`), so a drifted
// field or a typo'd tag is a compile error, not a frame the host silently
// refuses (or forwards to its death) at runtime. Types only - the outbound
// path gains no runtime validation, so no new parser asymmetries; writer
// coverage is pinned by scripts/check-envelope-parity.ts.
export type {
  AuditEventWire,
  ClientListWire,
  ClientRevokeWire,
  EnclaveChallengeWire,
  EnclaveRevokeWire,
  KillEngageWire,
  KillReleaseWire,
  KillStatusWire,
  LangGetWire,
  LangSetWire,
  LegacySettingsWire,
  PolicyGetWire,
  PresenceChallengeWire,
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
// PRESENCE domain (PRESENCE_DOMAIN in enclave.gen.ts), never the enrollment
// one.
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

// ---- ADR-0032: policy and language frames (host-handled) ----------------------

// The two host->extension pushes (also the replies to policy_get / lang_*).
// The four extension->host frames are outbound only and never classify
// inbound; their writer types ride the export block above.
export const POLICY_FRAME_TYPES = ["policy_current", "lang_current"] as const;

export const PolicyInboundFrameSchema = z.looseObject({
  type: z.enum(POLICY_FRAME_TYPES),
});

export type PolicyInboundFrame = z.infer<typeof PolicyInboundFrameSchema>;

// The policy state push (ADR-0032 decision 4). This validator covers ONLY
// the frame envelope: `baseline` stays an opaque base64 string here - the
// consumer verifies the signature over the decoded bytes against its pinned
// key FIRST and strict-parses those same bytes with the generated
// PolicyDocSchema only after the signature holds (or, unpinned, as the
// entry point). Never parse the document at this layer.
// ASYMMETRY (baseline/sig): no null arm (serde's Option; writers omit
// absent fields), non-empty early - signed artifacts the host only ever
// sends whole.
// ASYMMETRY (overlay): no null arm; the GENERATED strict PolicyOverlaySchema
// (policy.gen.ts), which deliberately stays STRICT inside this R5-loose
// frame (the pinned STRICT_ZOD_NODES exception in json-schema-normalize.ts):
// an overlay field the catalogue does not own is a policy claim nobody owns
// and fails the whole frame, fail closed.
export const PolicyCurrentFrameSchema = PolicyCurrentWireSchema.extend({
  baseline: z.string().min(1).optional(),
  sig: z.string().min(1).optional(),
  overlay: PolicyOverlaySchema.optional(),
  // ASYMMETRY (reason): the host frame field is Option<String> (any string or
  // absent); the extension pins it to the structured {absent,damaged,unreadable}
  // enum (ADR-0032 D-P4-2). The Phase-4 send-once MUST gate on
  // `ok === false && reason === "absent"`, so a value outside the enum, or a
  // missing field (an old host), reads as "not the absent signal" - never
  // send - which is fail closed.
  reason: z.enum(["absent", "damaged", "unreadable"]).optional(),
  // ASYMMETRY (error): no null arm, as above.
  error: z.string().optional(),
})
  .catchall(z.unknown())
  // ASYMMETRY (ok-split, superRefine): pinned in FRAME_REFINEMENTS
  // (scripts/check-envelope-parity.ts) - a refinement never shows up in
  // z.toJSONSchema, so the structural gate cannot see it and pins it there
  // instead. On the wire every field is an Option, so the base validates
  // per-field and would pass shapes PolicyStatus::into_frame (protocol.rs)
  // can never emit. The refinement encodes the only two real host shapes:
  // `ok: true` REQUIRES `baseline` (sig/overlay optional) and never carries
  // `reason` or `error`; `ok: false` REQUIRES `error` (reason optional - an
  // old host omits it) and never carries `baseline`, `sig`, or `overlay`.
  // In particular, the send-once condition above can never be satisfied (or
  // confused) by a frame that also claims success.
  .superRefine((frame, ctx) => {
    const [required, forbidden] = frame.ok
      ? (["baseline", ["reason", "error"]] as const)
      : (["error", ["baseline", "sig", "overlay"]] as const);
    if (frame[required] === undefined) {
      ctx.addIssue({
        code: "custom",
        path: [required],
        message: `policy_current ok:${frame.ok} always carries ${required} (ok-split)`,
      });
    }
    for (const field of forbidden) {
      if (frame[field] !== undefined) {
        ctx.addIssue({
          code: "custom",
          path: [field],
          message: `policy_current ok:${frame.ok} never carries ${field} (ok-split)`,
        });
      }
    }
  });

export type PolicyCurrentFrame = z.infer<typeof PolicyCurrentFrameSchema>;

// The shared-language push (ADR-0032 decision 7). `value` is checked against
// the locale enum by the consumer (an unknown value is refused there and the
// previous value stands); the frame layer only pins the shape.
// ASYMMETRY (seq): u64 on the Rust side, hardened to the JS-safe
// non-negative range (the id idiom) so both parsers read the same number.
export const LangCurrentFrameSchema = LangCurrentWireSchema.extend({
  seq: z.int().nonnegative(),
}).catchall(z.unknown());

export type LangCurrentFrame = z.infer<typeof LangCurrentFrameSchema>;

// The key-id shape a trust record may carry: lowercase-hex SHA-256 of a
// pubkey (the enrollment fingerprint). Declared here so the stored policy
// scope below can reuse it; `trustedKeyId` further deny-lists the fixture key
// for the PIN records lower down. Exported so policy-sync's durable prior-pin
// validator reuses this ONE definition rather than keeping a second copy that
// could drift.
export const KEY_ID_HEX = /^[0-9a-f]{64}$/;

// The extension-side stored effective policy (ADR-0032 decisions 3/4): the
// ratcheted effective values the extension last applied, the ratchet anchor
// (the accepted baseline's revision and its exact bytes, base64, for the
// byte-identical replay check), and the ratchet SCOPE it is bound to. STRICT
// like every stored trust record. The consumer discriminates the three read
// outcomes explicitly - absent, valid, corrupt - and does NOT collapse
// corrupt into absent: post-cutover a corrupt record latches the dispatch
// barrier closed (the kill-mirror STRICT precedent), because treating it as
// absent would let an older genuine baseline replay as first-ever while the
// snapshot fell to POLICY_DEFAULTS. POLICY_DEFAULTS is the deny baseline on
// the four capability grants but is NOT the restrictive pole on every field
// (hostReverifyMs 0 is the zero-top MOST permissive value, disabledTools is
// empty, confirmGraceMs is a middling 60s), so it is safe as a fallback ONLY
// because the barrier refuses every request whenever it is the answer - never
// because the values themselves are maximally restrictive. Per-field salvage
// is likewise forbidden (it would hand a corrupted store a relaxation lever).
export const StoredPolicyStateSchema = z.strictObject({
  // The pinned enrollment keyId this ratchet state is bound to, or null for
  // the unpinned lane (finding 2 / ADR-0032 decision 3). Every read re-checks
  // it against the CURRENT pin: a record whose scope no longer matches is
  // inert (deny baseline, closed barrier), so a push that raced a re-pair can
  // never enforce, and an old baseline captured under a since-revoked pin
  // cannot replay once a DIFFERENT key is pinned. NOT `trustedKeyId`: the
  // golden-fixture key is a legitimate scope in tests (the vectors are signed
  // by it), and deny-listing it would read every such record as corrupt.
  scope: z.string().regex(KEY_ID_HEX).nullable(),
  effective: PolicyValuesSchema,
  revision: z.int().nonnegative().max(POLICY_REVISION_MAX),
  baselineB64: z.string().min(1),
  at: z.number(),
});

export type StoredPolicyState = z.infer<typeof StoredPolicyStateSchema>;

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

// The audit kinds the extension records locally. The forwarded prefix is the
// GENERATED host whitelist (audit.gen.ts <- audit.rs EXTENSION_AUDIT_KINDS):
// those kinds also reach the host's on-disk trail via the audit_event control
// frame. The rest are local-only - the host audits those events
// authoritatively when it HANDLES them, so the ring keeps them for the panel
// and background/audit-log.ts never forwards them.
export const AUDIT_EVENT_KINDS = [
  ...AUDIT_FORWARDED_KINDS,
  "client_revoked",
  "kill_engaged",
  "kill_released",
  "kill_status_changed",
  // ADR-0032 phase 3, local-only (not in the host whitelist, so never
  // forwarded): a policy push refused after crypto/ratchet reasoning
  // (attack-shaped evidence, not benign version skew), and the policy-side
  // compromise mark a bad baseline signature latches. The host audits its own
  // policy writes authoritatively; these record the EXTENSION's refusals.
  "policy_refused",
  "policy_compromised",
  // ADR-0032 phase 4, local-only: the one-time legacy_settings bag send (the
  // decision-8 migration offer). The host audits the receipt authoritatively
  // when it records the pending import; this records the EXTENSION's send.
  "legacy_settings_sent",
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
  // Per-confirmation correlation id (ADR-0030): minted once per confirmation
  // and stamped on both its confirm_shown and its later verdict, so a reader
  // joins a verdict to exactly its own shown row. Pre-surface (panic-latch)
  // denials carry their own fresh cid that matches no shown row, so they
  // resolve none - never leave a new record cid-less, or it falls to the
  // subject fallback and can close an unrelated legacy row.
  cid: z.string().max(256).optional(),
});

export type AuditEntry = z.infer<typeof AuditEntrySchema>;

// A key identity a trust record may carry: well-formed (KEY_ID_HEX above),
// and never the deny-listed golden-fixture key (its private scalar is public,
// so a record
// naming it is planted or corrupt; failing the parse makes the record read
// as absent, which fails closed at the enrollment gate). Paired with
// keyRecordIsWhole (background/enclave-pin.ts), which recomputes
// SHA-256(pubkey) === keyId and is what stops the OTHER spelling of this
// attack - the fixture pubkey stored under a different keyId (the pin
// verifier never re-derives the fingerprint). Neither check is redundant.
const trustedKeyId = z
  .string()
  .regex(KEY_ID_HEX)
  .refine((id) => id !== ENCLAVE_FIXTURE_KEY_ID, {
    message: "the public golden-fixture key is never enrollable",
  });

// The pinned enrollment key: the extension-side trust anchor.
export const EnclavePinSchema = z.strictObject({
  // Lowercase-hex SHA-256 of the pubkey (the fingerprint).
  keyId: trustedKeyId,
  // Base64 of the 65-byte X9.63 point.
  pubkeyB64: z.string().min(1),
  pinnedAt: z.number(),
});

export type EnclavePin = z.infer<typeof EnclavePinSchema>;

// A ceremony proof that verified but has not been user-approved yet.
export const PendingPairingSchema = z.strictObject({
  keyId: trustedKeyId,
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
