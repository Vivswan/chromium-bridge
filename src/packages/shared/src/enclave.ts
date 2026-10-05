// The control-frame side the generator cannot own: the inbound classifiers the extension routes on, and the
// records the extension persists in chrome.storage.local. The frame validators themselves are generated (envelope.gen.ts: the Rust
// control-frame enums plus the asymmetry table in envelope-asymmetries.ts).
//
// Storage records are strict: a record with unexpected fields is treated as absent, which fails closed at the
// enrollment gate.

import { z } from "zod";
import { AUDIT_FORWARDED_KINDS } from "./audit.gen";
import { ENCLAVE_FIXTURE_KEY_ID } from "./enclave.gen";
import { KillStatusResultSchema } from "./envelope.gen";
import { POLICY_REVISION_MAX, PolicyValuesSchema } from "./policy.gen";

// ---- inbound classifiers ------------------------------------------------------
//
// Classification only: is this native-messaging frame control traffic (carries `type`) rather than a bridge
// request (carries `op`)? A frame that classifies but fails its per-type reader is still control traffic - it is
// handled (and refused) there, never dispatched. scripts/check-envelope.ts holds each array to the generated
// reader plan: every classified tag is a Rust frame with a reader or a bare tag, except the pinned outbound
// exceptions it names.

export const ENCLAVE_FRAME_TYPES = [
  "enclave_challenge",
  "enclave_proof",
  "enclave_error",
  // The extension->host key-deletion request and the host-originated "the key is gone" notice both classify
  // as ceremony traffic; the handlers drop the directions that make no sense inbound.
  "enclave_revoke",
  "enclave_revoked",
] as const;

export const EnclaveInboundFrameSchema = z.looseObject({
  type: z.enum(ENCLAVE_FRAME_TYPES),
});

export type EnclaveInboundFrame = z.infer<typeof EnclaveInboundFrameSchema>;

// The admin replies the host sends back. Requests (client_list / client_revoke) are outbound only and never
// classify inbound; kill_status_result classifies by full parse (isKillStatusFrame).
export const ADMIN_RESULT_FRAME_TYPES = ["client_list_result", "client_revoke_result"] as const;

export const AdminInboundFrameSchema = z.looseObject({
  type: z.enum(ADMIN_RESULT_FRAME_TYPES),
});

export type AdminInboundFrame = z.infer<typeof AdminInboundFrameSchema>;

/** Classification only: is this frame the kill-status result? `ok: false` (state unreadable host-side)
 * deliberately carries no `killed` claim; the extension treats it as unknown and fails closed. */
export function isKillStatusFrame(msg: unknown): msg is z.infer<typeof KillStatusResultSchema> {
  return KillStatusResultSchema.safeParse(msg).success;
}

// The two host->extension policy pushes (also the replies to policy_get / lang_*). The four extension->host
// frames are outbound only and never classify inbound.
export const POLICY_FRAME_TYPES = ["policy_current", "lang_current"] as const;

export const PolicyInboundFrameSchema = z.looseObject({
  type: z.enum(POLICY_FRAME_TYPES),
});

export type PolicyInboundFrame = z.infer<typeof PolicyInboundFrameSchema>;

// ---- stored trust records --------------------------------------------------------

// The key-id shape a trust record may carry: lowercase-hex SHA-256 of a pubkey (the enrollment fingerprint).
// Exported so policy-sync's durable prior-pin validator reuses this ONE definition.
export const KEY_ID_HEX = /^[0-9a-f]{64}$/;

// The stored effective policy: the ratcheted values last applied, the ratchet anchor (the accepted baseline's
// revision and exact bytes, for the byte-identical replay check), and the scope it is bound to. STRICT like
// every stored trust record, and policy-sync.ts keeps corrupt DISTINCT from absent: post-cutover a corrupt
// record resolves to compromised and an absent one to awaitingBaseline, each a blocked posture carrying a
// reason and no values, so no default is ever enforced in their place. Reading corrupt as absent would let an
// older genuine baseline replay as first-ever, and per-field salvage would hand a corrupted store a relaxation
// lever, so the stored-policy reader returns null on any failure.
export const StoredPolicyStateSchema = z.strictObject({
  // The pinned enrollment keyId this ratchet state is bound to, or null for the unpinned lane. Every read
  // re-checks it against the CURRENT pin, so a record whose scope no longer matches is inert (deny baseline,
  // closed barrier): a push that raced a re-pair can never enforce, and a baseline captured under a
  // since-revoked pin cannot replay once a DIFFERENT key is pinned. NOT `trustedKeyId`: the golden-fixture key
  // is a legitimate scope in tests (the vectors are signed by it), and deny-listing it would read every such
  // record as corrupt.
  scope: z.string().regex(KEY_ID_HEX).nullable(),
  effective: PolicyValuesSchema,
  revision: z.int().nonnegative().max(POLICY_REVISION_MAX),
  baselineB64: z.string().min(1),
  at: z.number(),
});

export type StoredPolicyState = z.infer<typeof StoredPolicyStateSchema>;

// The extension-side mirror of the host's kill state, persisted in the extension-context-only trusted storage
// (trusted-storage.ts; content scripts excluded). STRICT: a record with unexpected fields (or a non-record
// value) is tampering evidence and the gate refuses on it rather than treating it as absent - absent means
// "never heard from the host" (allowed locally; the host side enforces), so mapping garbage to absent would
// fail OPEN.
export const KillMirrorSchema = z.strictObject({
  state: z.enum(["alive", "killed", "unknown"]),
  at: z.number(),
});

export type KillMirror = z.infer<typeof KillMirrorSchema>;

// The audit kinds the extension records locally. The forwarded prefix is the GENERATED host whitelist
// (audit.gen.ts <- audit.rs EXTENSION_AUDIT_KINDS): those kinds also reach the host's on-disk trail via the
// audit_event control frame. The rest are local-only - the host audits those events authoritatively when it
// HANDLES them, so the ring keeps them for the panel and background/audit-log.ts never forwards them.
export const AUDIT_EVENT_KINDS = [
  ...AUDIT_FORWARDED_KINDS,
  "client_revoked",
  "kill_engaged",
  // Write-dead (the extension lost its release lane; the host refuses kill_release), READ-LIVE: retained so
  // historical audit entries carrying it still render through the kind-to-locale mapping.
  "kill_released",
  "kill_status_changed",
  // Local-only (not in the host whitelist, so never forwarded): a policy push refused after crypto/ratchet
  // reasoning (attack-shaped evidence, not benign version skew), and the policy-side compromise mark a bad
  // baseline signature latches. The host audits its own policy writes authoritatively; these record the
  // EXTENSION's refusals.
  "policy_refused",
  "policy_compromised",
] as const;

export type AuditEventKind = (typeof AUDIT_EVENT_KINDS)[number];

// One entry of the ring in trusted storage. Strict, like every stored trust record: an entry that fails this
// shape is dropped on read (the ring is display-only, so dropping is safe and fail-closed for the panel).
export const AuditEntrySchema = z.strictObject({
  at: z.number(),
  kind: z.enum(AUDIT_EVENT_KINDS),
  outcome: z.string().max(256).optional(),
  tool: z.string().max(256).optional(),
  name: z.string().max(256).optional(),
  detail: z.string().max(512).optional(),
  // Per-confirmation correlation id: minted once per confirmation and stamped on both its confirm_shown and
  // its later verdict, so a reader joins a verdict to exactly its own shown row. Pre-surface (panic-latch)
  // denials carry their own fresh cid that matches no shown row, so they resolve none - never leave a new
  // record cid-less, or it falls to the subject fallback and can close an unrelated legacy row.
  cid: z.string().max(256).optional(),
});

export type AuditEntry = z.infer<typeof AuditEntrySchema>;

// A key identity a trust record may carry: well-formed (KEY_ID_HEX above), and never the deny-listed
// golden-fixture key (its private scalar is public, so a record naming it is planted or corrupt; failing the
// parse makes the record read as absent, which fails closed at the enrollment gate). Paired with
// keyRecordIsWhole (background/enclave-pin.ts), which recomputes SHA-256(pubkey) === keyId and is what stops
// the OTHER spelling of this attack - the fixture pubkey stored under a different keyId (the pin verifier never
// re-derives the fingerprint). Neither check is redundant.
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

// Set when a pinned-key verification failed: the bridge fails closed until the user revokes the pin and
// re-pairs.
export const CompromisedMarkSchema = z.strictObject({
  reason: z.string().min(1),
  at: z.number(),
});

export type CompromisedMark = z.infer<typeof CompromisedMarkSchema>;
