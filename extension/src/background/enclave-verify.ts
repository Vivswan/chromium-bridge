// WebCrypto verification for the Secure Enclave enrollment ceremony
// (ADR-0021). Pure module: no chrome.* usage, so bun unit-tests it with
// self-checking offline vectors.
//
// The wire contract is owned by the host (src/protocol.rs, EnclaveControl).
// A proof's `sig` is base64 of the raw 64-byte IEEE P1363 r||s ECDSA
// P-256/SHA-256 signature over
//
//   UTF8("chromium-bridge-enclave-v1") || 0x00 || UTF8(nonce) || 0x00 || UTF8(context or "")
//
// `pubkey` is base64 of the 65-byte X9.63 uncompressed point (0x04||X||Y)
// and `key_id` is the lowercase-hex SHA-256 of those 65 bytes (also the
// fingerprint the user compares against `chromium-bridge pair` output).

export const CHALLENGE_DOMAIN = "chromium-bridge-enclave-v1";
// Host-enforced bounds on challenge fields (src/enclave.rs); we stay inside
// them and reject anything outside before touching the crypto.
export const MAX_NONCE_BYTES = 256;
export const MAX_CONTEXT_BYTES = 4096;

const PUBKEY_LEN = 65; // X9.63 uncompressed P-256 point
const SIG_LEN = 64; // IEEE P1363 r||s

const utf8 = new TextEncoder();

/** A fresh single-use challenge nonce: 32 CSPRNG bytes as lowercase hex
 * (64 ASCII chars, NUL-free, well under the host's 256-byte bound). */
export function generateNonce(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return hexEncode(bytes);
}

export function hexEncode(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** Strict base64 decode. Throws on anything atob would silently mangle, and
 * on non-canonical encodings (padding bits set), so every stored/compared
 * base64 string has exactly one accepted spelling. */
export function base64Decode(s: string): Uint8Array {
  if (s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) {
    throw new Error("invalid base64");
  }
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  if (base64Encode(out) !== s) throw new Error("non-canonical base64");
  return out;
}

export function base64Encode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** Build the exact byte string a proof signs. Throws when nonce/context
 * violate the host's bounds (empty, NUL bytes, oversize): a challenge we
 * would not have issued must never verify. */
export function buildChallengeMessage(nonce: string, context?: string): Uint8Array {
  const nonceB = utf8.encode(nonce);
  if (nonceB.length === 0) throw new Error("nonce must be non-empty");
  if (nonceB.length > MAX_NONCE_BYTES) throw new Error("nonce too long");
  if (nonceB.includes(0)) throw new Error("nonce must be NUL-free");
  const ctxB = utf8.encode(context ?? "");
  if (ctxB.length > MAX_CONTEXT_BYTES) throw new Error("context too long");
  if (ctxB.includes(0)) throw new Error("context must be NUL-free");
  const domainB = utf8.encode(CHALLENGE_DOMAIN);
  const msg = new Uint8Array(domainB.length + 1 + nonceB.length + 1 + ctxB.length);
  // The two NUL separators are already 0 in the fresh Uint8Array.
  msg.set(domainB, 0);
  msg.set(nonceB, domainB.length + 1);
  msg.set(ctxB, domainB.length + 1 + nonceB.length + 1);
  return msg;
}

/** Decode and validate a proof's `pubkey` field: exactly 65 bytes with the
 * 0x04 uncompressed-point prefix. Curve membership is enforced by importKey. */
export function parsePubkey(pubkeyB64: string): Uint8Array {
  const bytes = base64Decode(pubkeyB64);
  if (bytes.length !== PUBKEY_LEN) throw new Error(`pubkey must be ${PUBKEY_LEN} bytes`);
  if (bytes[0] !== 0x04) throw new Error("pubkey must be an uncompressed X9.63 point");
  return bytes;
}

/** Decode and validate a proof's `sig` field: exactly the raw 64-byte P1363
 * form (the host converts Security.framework's DER output before sending). */
export function parseSig(sigB64: string): Uint8Array {
  const bytes = base64Decode(sigB64);
  if (bytes.length !== SIG_LEN) throw new Error(`sig must be ${SIG_LEN} bytes`);
  return bytes;
}

/** key_id = lowercase-hex SHA-256 of the 65 raw pubkey bytes. */
export async function computeKeyId(pubkey: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", pubkey as BufferSource);
  return hexEncode(new Uint8Array(digest));
}

/** Fingerprint grouped in 4-char blocks, matching the host CLI's display so
 * the user can compare the two side by side. */
export function fingerprintDisplay(keyIdHex: string): string {
  return keyIdHex.replace(/(.{4})(?=.)/g, "$1 ");
}

async function verifySignature(
  pubkey: Uint8Array,
  sig: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    "raw",
    pubkey as BufferSource,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    sig as BufferSource,
    message as BufferSource,
  );
}

/** The three string fields of an `enclave_proof` frame. */
export interface ProofFields {
  sig: string;
  key_id: string;
  pubkey: string;
}

export type PairingVerifyResult =
  | { ok: true; pubkeyB64: string; keyId: string }
  | { ok: false; reason: string };

/** Pairing-time (ceremony) verification. The proof is checked for internal
 * consistency (key_id matches pubkey) and a valid signature by its OWN
 * embedded key. The returned key material is trustworthy ONLY because the
 * user then compares its fingerprint against the `chromium-bridge pair`
 * terminal output before it is pinned; outside the ceremony, use
 * verifyProofAgainstPin. */
export async function verifyPairingProof(
  proof: ProofFields,
  nonce: string,
  context?: string,
): Promise<PairingVerifyResult> {
  let pubkey: Uint8Array;
  let sig: Uint8Array;
  let message: Uint8Array;
  try {
    pubkey = parsePubkey(proof.pubkey);
    sig = parseSig(proof.sig);
    message = buildChallengeMessage(nonce, context);
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : String(e) };
  }
  const keyId = await computeKeyId(pubkey);
  if (proof.key_id !== keyId) {
    return { ok: false, reason: "key_id does not match pubkey" };
  }
  const valid = await verifySignature(pubkey, sig, message).catch(() => false);
  if (!valid) return { ok: false, reason: "signature verification failed" };
  return { ok: true, pubkeyB64: proof.pubkey, keyId };
}

export type PinVerifyResult = { ok: true } | { ok: false; reason: string };

/** Steady-state verification: the signature is verified against the PINNED
 * key only, never against the proof's own pubkey field. A proof whose
 * key_id/pubkey differ from the pin is rejected before any crypto runs;
 * a proof that names the pinned key but was signed by another one fails the
 * signature check, because the pinned bytes are what gets imported. */
export async function verifyProofAgainstPin(
  proof: ProofFields,
  nonce: string,
  context: string | undefined,
  pinnedPubkeyB64: string,
  pinnedKeyId: string,
): Promise<PinVerifyResult> {
  let pinned: Uint8Array;
  let sig: Uint8Array;
  let message: Uint8Array;
  try {
    pinned = parsePubkey(pinnedPubkeyB64);
    sig = parseSig(proof.sig);
    message = buildChallengeMessage(nonce, context);
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : String(e) };
  }
  if (proof.key_id !== pinnedKeyId || proof.pubkey !== pinnedPubkeyB64) {
    return { ok: false, reason: "proof key does not match the pinned key" };
  }
  const valid = await verifySignature(pinned, sig, message).catch(() => false);
  if (!valid) {
    return { ok: false, reason: "signature verification failed against the pinned key" };
  }
  return { ok: true };
}
