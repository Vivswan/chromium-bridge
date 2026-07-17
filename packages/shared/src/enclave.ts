// Shapes for the ADR-0021 enclave enrollment ceremony: the control frames
// exchanged with the native host over the native-messaging port, and the
// records the extension persists in chrome.storage.local.
//
// Frames are loose objects (the host may add fields; unknown extras are
// ignored), because the security decision is made from the validated fields
// plus the cryptographic verification in background/enclave-verify.ts - never
// from a frame merely having the right shape. Storage records are strict: a
// record with unexpected fields is treated as absent, which fails closed at
// the enrollment gate.

import { z } from "zod";

export const ENCLAVE_FRAME_TYPES = ["enclave_challenge", "enclave_proof", "enclave_error"] as const;

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
export const EnclaveProofFrameSchema = z.looseObject({
  type: z.literal("enclave_proof"),
  sig: z.string().min(1),
  key_id: z.string().min(1),
  pubkey: z.string().min(1),
});

export type EnclaveProofFrame = z.infer<typeof EnclaveProofFrameSchema>;

export const EnclaveErrorFrameSchema = z.looseObject({
  type: z.literal("enclave_error"),
  reason: z.string().optional(),
});

export type EnclaveErrorFrame = z.infer<typeof EnclaveErrorFrameSchema>;

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
