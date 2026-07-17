// Storage for the extension-side trust anchor of ADR-0021: the pinned
// enrollment public key, plus the ceremony's intermediate records. Everything
// lives in chrome.storage.local (extension-private, survives service-worker
// restarts), mirroring allowlist-store.ts. The single-use challenge nonce is
// deliberately NOT here: it stays in service-worker memory only
// (see enrollment.ts), so a persisted copy can never be replayed against.

import { computeKeyId, parsePubkey } from "./enclave-verify";

export interface EnclavePin {
  keyId: string; // lowercase-hex SHA-256 of the pubkey (the fingerprint)
  pubkeyB64: string; // base64 of the 65-byte X9.63 point
  pinnedAt: number;
}

/** A ceremony proof that verified but has not been user-approved yet. */
export interface PendingPairing {
  keyId: string;
  pubkeyB64: string;
  at: number;
}

/** Set when a pinned-key verification failed: the bridge fails closed until
 * the user revokes the pin and re-pairs. */
export interface CompromisedMark {
  reason: string;
  at: number;
}

const PIN_KEY = "enclavePin";
const PENDING_KEY = "enclavePending";
const COMPROMISED_KEY = "enclaveCompromised";
const PAUSED_KEY = "enclavePairingPaused";
const LAST_ERROR_KEY = "enclaveLastError";
const LAST_VERIFIED_KEY = "enclaveLastVerifiedAt";

const KEY_ID_HEX = /^[0-9a-f]{64}$/;

async function read(key: string): Promise<unknown> {
  const { [key]: v } = await chrome.storage.local.get(key);
  return v;
}

/** A stored key record counts only if it is cryptographically whole: the
 * pubkey decodes to a real 65-byte X9.63 point and its SHA-256 equals the
 * stored keyId. A corrupt or hand-edited record is treated as absent (which
 * fails closed at the gate), never as a pin. */
async function validKeyRecord(v: unknown): Promise<boolean> {
  const rec = v as { keyId?: unknown; pubkeyB64?: unknown } | undefined;
  if (
    !rec ||
    typeof rec.keyId !== "string" ||
    !KEY_ID_HEX.test(rec.keyId) ||
    typeof rec.pubkeyB64 !== "string"
  ) {
    return false;
  }
  try {
    const pub = parsePubkey(rec.pubkeyB64);
    if ((await computeKeyId(pub)) !== rec.keyId) {
      console.warn("[bb] stored enclave key record fails fingerprint check; ignoring it");
      return false;
    }
  } catch (e) {
    console.warn("[bb] stored enclave key record does not decode; ignoring it", e);
    return false;
  }
  return true;
}

export async function getPin(): Promise<EnclavePin | null> {
  const v = (await read(PIN_KEY)) as Partial<EnclavePin> | undefined;
  if (v && typeof v.pinnedAt === "number" && (await validKeyRecord(v))) {
    return v as EnclavePin;
  }
  return null;
}

export async function setPin(pin: EnclavePin): Promise<void> {
  await chrome.storage.local.set({ [PIN_KEY]: pin });
}

export async function getPending(): Promise<PendingPairing | null> {
  const v = (await read(PENDING_KEY)) as Partial<PendingPairing> | undefined;
  if (v && typeof v.at === "number" && (await validKeyRecord(v))) {
    return v as PendingPairing;
  }
  return null;
}

export async function setPending(p: PendingPairing): Promise<void> {
  await chrome.storage.local.set({ [PENDING_KEY]: p });
}

export async function clearPending(): Promise<void> {
  await chrome.storage.local.remove(PENDING_KEY);
}

export async function getCompromised(): Promise<CompromisedMark | null> {
  const v = (await read(COMPROMISED_KEY)) as Partial<CompromisedMark> | undefined;
  if (v && typeof v.reason === "string" && typeof v.at === "number") {
    return v as CompromisedMark;
  }
  return null;
}

export async function setCompromised(mark: CompromisedMark): Promise<void> {
  await chrome.storage.local.set({ [COMPROMISED_KEY]: mark });
}

/** While paused, the background never auto-issues a pairing challenge (the
 * user rejected a fingerprint or revoked the pin; restarting the ceremony is
 * a manual act from the options page). Purely a prompt-suppression flag: the
 * gate stays closed either way. */
export async function getPaused(): Promise<boolean> {
  return (await read(PAUSED_KEY)) === true;
}

export async function setPaused(paused: boolean): Promise<void> {
  if (paused) await chrome.storage.local.set({ [PAUSED_KEY]: true });
  else await chrome.storage.local.remove(PAUSED_KEY);
}

export async function getLastError(): Promise<string | null> {
  const v = await read(LAST_ERROR_KEY);
  return typeof v === "string" && v ? v : null;
}

export async function setLastError(msg: string): Promise<void> {
  await chrome.storage.local.set({ [LAST_ERROR_KEY]: msg });
}

export async function clearLastError(): Promise<void> {
  await chrome.storage.local.remove(LAST_ERROR_KEY);
}

export async function getLastVerifiedAt(): Promise<number | null> {
  const v = await read(LAST_VERIFIED_KEY);
  return typeof v === "number" ? v : null;
}

export async function setLastVerifiedAt(at: number): Promise<void> {
  await chrome.storage.local.set({ [LAST_VERIFIED_KEY]: at });
}

/** Revoke: forget the pin and every ceremony record. */
export async function clearAll(): Promise<void> {
  await chrome.storage.local.remove([
    PIN_KEY,
    PENDING_KEY,
    COMPROMISED_KEY,
    LAST_ERROR_KEY,
    LAST_VERIFIED_KEY,
  ]);
}
