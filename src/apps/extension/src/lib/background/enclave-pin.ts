// Storage for the extension-side trust anchor of enrollment: the pinned
// enrollment public key, plus the ceremony's intermediate records. Everything
// lives in browser.storage.local (extension-private, survives service-worker
// restarts), mirroring allowlist-store.ts. The single-use challenge nonce is
// deliberately NOT here: it stays in service-worker memory only (see
// enrollment.ts), so a persisted copy can never be replayed against.
//
// Record shapes are the Zod schemas in @genkan/shared (enclave.ts
// there); every read parses against them, and key records additionally pass
// the cryptographic self-check below. Anything that fails either is treated
// as absent - which fails closed at the enrollment gate.

import {
  type CompromisedMark,
  CompromisedMarkSchema,
  type EnclavePin,
  EnclavePinSchema,
  type PendingPairing,
  PendingPairingSchema,
} from "@genkan/shared/enclave";
import { browser } from "wxt/browser";
import { z } from "zod";
import { readKey, readKeyOr, type Stored } from "../shared/read-key";
import { computeKeyId, parsePubkey } from "./enclave-verify";

const PIN_KEY = "enclavePin";
const PENDING_KEY = "enclavePending";
const COMPROMISED_KEY = "enclaveCompromised";
const PAUSED_KEY = "enclavePairingPaused";
const LAST_ERROR_KEY = "enclaveLastError";
const LAST_VERIFIED_KEY = "enclaveLastVerifiedAt";
const HOST_REVOKE_PENDING_KEY = "enclaveHostRevokePending";

/** A stored key record counts only if it is cryptographically whole: the
 * pubkey decodes to a real 65-byte X9.63 point and its SHA-256 equals the
 * stored keyId. A corrupt or hand-edited record is treated as absent (which
 * fails closed at the gate), never as a pin. Paired with trustedKeyId in
 * the shared schemas (enclave.ts), which deny-lists the golden-fixture
 * keyId; this check is what stops the fixture PUBKEY planted under a
 * different keyId, because the pin verifier trusts the stored fingerprint
 * without re-deriving it. Neither check is redundant. */
async function keyRecordIsWhole(rec: { keyId: string; pubkeyB64: string }): Promise<boolean> {
  try {
    const pub = parsePubkey(rec.pubkeyB64);
    if ((await computeKeyId(pub)) !== rec.keyId) {
      console.warn("[genkan] stored enclave key record fails fingerprint check; ignoring it");
      return false;
    }
  } catch (e) {
    console.warn("[genkan] stored enclave key record does not decode; ignoring it", e);
    return false;
  }
  return true;
}

/** The pin read, as the three states the storage can actually be in: no
 * record at all, a record that fails the schema or the cryptographic
 * self-check ([`keyRecordIsWhole`]), or a whole pin. `corrupt` and `absent`
 * are distinguishable AT THE TYPE LEVEL here so the collapse below is a
 * visible decision, never an accident of parsing. Exported for tests and
 * for a future consumer that needs the distinction; every production read
 * today goes through [`getPin`] (the collapse). */
export type PinRead = Stored<EnclavePin>;

/** Read the pinned enrollment key three ways. Absent means the storage key
 * is missing; anything present that fails the strict schema or the
 * fingerprint self-check is corrupt (already warned about by
 * keyRecordIsWhole), never folded into absent by THIS reader. */
export async function readPin(): Promise<PinRead> {
  const stored = await readKey(PIN_KEY, EnclavePinSchema);
  if (stored.state !== "valid") return stored;
  return (await keyRecordIsWhole(stored.value)) ? stored : { state: "corrupt" };
}

/** THE DOCUMENTED COLLAPSE: every consumer routes a
 * corrupt pin record exactly like an absent one - the unsigned/unpaired
 * lane, which fails closed at the enrollment gate and refuses signed-lane
 * trust. A corrupt record is NOT tampering evidence worth latching on (a
 * same-user writer who can corrupt this key could equally delete it), so
 * collapsing it to null grants nothing; it only denies. Consumers that ever
 * need the distinction read [`readPin`] instead. */
export function pinOrNull(read: PinRead): EnclavePin | null {
  return read.state === "valid" ? read.value : null;
}

/** The collapsed read every gate/ratchet/lane consumer uses: `pinOrNull`
 * over [`readPin`], see the collapse contract there. */
export async function getPin(): Promise<EnclavePin | null> {
  return pinOrNull(await readPin());
}

export async function setPin(pin: EnclavePin): Promise<void> {
  await browser.storage.local.set({ [PIN_KEY]: pin });
}

export async function getPending(): Promise<PendingPairing | null> {
  const stored = await readKey(PENDING_KEY, PendingPairingSchema);
  if (stored.state === "valid" && (await keyRecordIsWhole(stored.value))) return stored.value;
  return null;
}

export async function setPending(p: PendingPairing): Promise<void> {
  await browser.storage.local.set({ [PENDING_KEY]: p });
}

export async function clearPending(): Promise<void> {
  await browser.storage.local.remove(PENDING_KEY);
}

export function getCompromised(): Promise<CompromisedMark | null> {
  return readKeyOr(COMPROMISED_KEY, CompromisedMarkSchema, null);
}

export async function setCompromised(mark: CompromisedMark): Promise<void> {
  await browser.storage.local.set({ [COMPROMISED_KEY]: mark });
}

/** While paused, the background never auto-issues a pairing challenge (the
 * user rejected a fingerprint or revoked the pin; restarting the ceremony is
 * a manual act from the options page). Purely a prompt-suppression flag: the
 * gate stays closed either way. */
export function getPaused(): Promise<boolean> {
  return readKeyOr(PAUSED_KEY, z.literal(true), false);
}

export async function setPaused(paused: boolean): Promise<void> {
  if (paused) await browser.storage.local.set({ [PAUSED_KEY]: true });
  else await browser.storage.local.remove(PAUSED_KEY);
}

export function getLastError(): Promise<string | null> {
  return readKeyOr(LAST_ERROR_KEY, z.string().min(1), null);
}

export async function setLastError(msg: string): Promise<void> {
  await browser.storage.local.set({ [LAST_ERROR_KEY]: msg });
}

export async function clearLastError(): Promise<void> {
  await browser.storage.local.remove(LAST_ERROR_KEY);
}

export function getLastVerifiedAt(): Promise<number | null> {
  return readKeyOr(LAST_VERIFIED_KEY, z.number(), null);
}

export async function setLastVerifiedAt(at: number): Promise<void> {
  await browser.storage.local.set({ [LAST_VERIFIED_KEY]: at });
}

/** A revoke here must also delete the HOST's enclave key: unpairing from either
 * side must leave no usable credential behind. The request rides a control
 * frame on the native-messaging port; this durable flag survives MV3 SW death
 * and port gaps, and every port connect resends the request until it is
 * settled: cleared by the host's `enclave_revoked` acknowledgement, or
 * superseded when a fresh pairing is pinned (the frame names no key, so past a
 * re-pair it would delete the newly minted key - see enrollment.ts). */
export function getHostRevokePending(): Promise<boolean> {
  return readKeyOr(HOST_REVOKE_PENDING_KEY, z.literal(true), false);
}

export async function setHostRevokePending(on: boolean): Promise<void> {
  if (on) await browser.storage.local.set({ [HOST_REVOKE_PENDING_KEY]: true });
  else await browser.storage.local.remove(HOST_REVOKE_PENDING_KEY);
}

/** Revoke: forget the pin and every ceremony record. The host-revoke-pending
 * flag deliberately survives this: it is the durable carrier of the
 * still-unacknowledged key-deletion request. */
export async function clearAll(): Promise<void> {
  await browser.storage.local.remove([
    PIN_KEY,
    PENDING_KEY,
    COMPROMISED_KEY,
    LAST_ERROR_KEY,
    LAST_VERIFIED_KEY,
  ]);
}
