import { describe, expect, test } from "vitest";
import {
  base64Decode,
  base64Encode,
  buildChallengeMessage,
  CHALLENGE_DOMAIN,
  computeKeyId,
  fingerprintDisplay,
  generateNonce,
  parsePubkey,
  parseSig,
  verifyPairingProof,
  verifyProofAgainstPin,
} from "@/lib/background/enclave-verify";

// Self-checking vectors: bun's WebCrypto plays the host's Secure Enclave.
// crypto.subtle.sign for ECDSA emits exactly the raw 64-byte IEEE P1363 r||s
// form the host sends (it converts Security.framework's DER itself), and
// crypto.subtle.exportKey("raw") emits the 65-byte X9.63 point, so the test
// key is bit-compatible with the wire contract.

interface TestKey {
  kp: CryptoKeyPair;
  raw: Uint8Array;
  pubkeyB64: string;
  keyId: string;
}

async function genKey(): Promise<TestKey> {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  return { kp, raw, pubkeyB64: base64Encode(raw), keyId: await computeKeyId(raw) };
}

async function signB64(key: TestKey, message: Uint8Array): Promise<string> {
  const sig = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      key.kp.privateKey,
      message as BufferSource,
    ),
  );
  expect(sig.length).toBe(64);
  return base64Encode(sig);
}

async function makeProof(key: TestKey, nonce: string, context?: string) {
  return {
    sig: await signB64(key, buildChallengeMessage(nonce, context)),
    key_id: key.keyId,
    pubkey: key.pubkeyB64,
  };
}

describe("buildChallengeMessage", () => {
  test("produces exactly domain || NUL || nonce || NUL || context", () => {
    const msg = buildChallengeMessage("abc", "ctx");
    const expected = [
      ...new TextEncoder().encode(CHALLENGE_DOMAIN),
      0,
      0x61,
      0x62,
      0x63,
      0,
      0x63,
      0x74,
      0x78,
    ];
    expect(Array.from(msg)).toEqual(expected);
  });

  test("absent context signs the same bytes as empty context", () => {
    expect(Array.from(buildChallengeMessage("n"))).toEqual(
      Array.from(buildChallengeMessage("n", "")),
    );
  });

  test("enforces the host's bounds before any crypto", () => {
    expect(() => buildChallengeMessage("")).toThrow("non-empty");
    expect(() => buildChallengeMessage("a\0b")).toThrow("NUL");
    expect(() => buildChallengeMessage("a".repeat(257))).toThrow("too long");
    expect(() => buildChallengeMessage("n", "c\0")).toThrow("NUL");
    expect(() => buildChallengeMessage("n", "c".repeat(4097))).toThrow("too long");
  });
});

describe("generateNonce", () => {
  test("64 lowercase hex chars, fresh each call", () => {
    const a = generateNonce();
    const b = generateNonce();
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(b).toMatch(/^[0-9a-f]{64}$/);
    expect(a).not.toBe(b);
  });
});

describe("field parsing", () => {
  test("parsePubkey accepts a real 65-byte X9.63 point", async () => {
    const key = await genKey();
    expect(Array.from(parsePubkey(key.pubkeyB64))).toEqual(Array.from(key.raw));
  });

  test("parsePubkey rejects wrong length and wrong prefix", async () => {
    const key = await genKey();
    expect(() => parsePubkey(base64Encode(key.raw.slice(0, 64)))).toThrow("65 bytes");
    const compressedish = new Uint8Array(key.raw);
    compressedish[0] = 0x02;
    expect(() => parsePubkey(base64Encode(compressedish))).toThrow("uncompressed");
  });

  test("parseSig rejects anything but 64 bytes", () => {
    expect(() => parseSig(base64Encode(new Uint8Array(63)))).toThrow("64 bytes");
    expect(() => parseSig(base64Encode(new Uint8Array(65)))).toThrow("64 bytes");
    expect(parseSig(base64Encode(new Uint8Array(64))).length).toBe(64);
  });

  test("base64Decode is strict", () => {
    expect(() => base64Decode("not base64!!")).toThrow("base64");
    expect(() => base64Decode("abc")).toThrow("base64"); // bad length
    // Non-canonical: "AB==" decodes to one byte whose canonical form is "AA==".
    expect(() => base64Decode("AB==")).toThrow("non-canonical");
    expect(Array.from(base64Decode("AQID"))).toEqual([1, 2, 3]);
  });

  test("computeKeyId matches the SHA-256 known-answer vector", async () => {
    // SHA-256 of the empty string.
    expect(await computeKeyId(new Uint8Array(0))).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  test("fingerprintDisplay groups in 4-char blocks", () => {
    expect(fingerprintDisplay("aabbccddee")).toBe("aabb ccdd ee");
  });
});

describe("verifyPairingProof (ceremony bootstrap)", () => {
  test("accepts a proof signed by its own embedded key", async () => {
    const key = await genKey();
    const res = await verifyPairingProof(await makeProof(key, "nonce1", "ctx"), "nonce1", "ctx");
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.keyId).toBe(key.keyId);
      expect(res.pubkeyB64).toBe(key.pubkeyB64);
    }
  });

  test("rejects a proof over a different nonce (single-use freshness)", async () => {
    const key = await genKey();
    const res = await verifyPairingProof(await makeProof(key, "nonce1"), "nonce2");
    expect(res.ok).toBe(false);
  });

  test("rejects a proof over a different context", async () => {
    const key = await genKey();
    const res = await verifyPairingProof(await makeProof(key, "n", "ctxA"), "n", "ctxB");
    expect(res.ok).toBe(false);
  });

  test("rejects a key_id that does not match the pubkey", async () => {
    const key = await genKey();
    const proof = await makeProof(key, "n");
    proof.key_id = "0".repeat(64);
    const res = await verifyPairingProof(proof, "n");
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toContain("key_id");
  });

  test("rejects a tampered signature", async () => {
    const key = await genKey();
    const proof = await makeProof(key, "n");
    const sig = base64Decode(proof.sig);
    sig[10] = (sig[10] ?? 0) ^ 0x01;
    proof.sig = base64Encode(sig);
    const res = await verifyPairingProof(proof, "n");
    expect(res.ok).toBe(false);
  });
});

describe("verifyProofAgainstPin (steady state)", () => {
  test("accepts the pinned key's proof", async () => {
    const key = await genKey();
    const res = await verifyProofAgainstPin(
      await makeProof(key, "n", "c"),
      "n",
      "c",
      key.pubkeyB64,
      key.keyId,
    );
    expect(res.ok).toBe(true);
  });

  test("rejects a proof from a non-pinned key", async () => {
    const pinned = await genKey();
    const other = await genKey();
    const res = await verifyProofAgainstPin(
      await makeProof(other, "n"),
      "n",
      undefined,
      pinned.pubkeyB64,
      pinned.keyId,
    );
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toContain("pinned");
  });

  test("verifies against the PINNED bytes, not the proof's pubkey field", async () => {
    // The attacker copies the pinned key's identifiers into the frame but can
    // only sign with their own key. Field comparison passes; the signature
    // must still be checked against the pin and fail.
    const pinned = await genKey();
    const attacker = await genKey();
    const proof = {
      sig: await signB64(attacker, buildChallengeMessage("n")),
      key_id: pinned.keyId,
      pubkey: pinned.pubkeyB64,
    };
    const res = await verifyProofAgainstPin(proof, "n", undefined, pinned.pubkeyB64, pinned.keyId);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toContain("signature");
  });

  test("rejects a replay over a stale nonce", async () => {
    const key = await genKey();
    const proof = await makeProof(key, "old-nonce");
    const res = await verifyProofAgainstPin(
      proof,
      "fresh-nonce",
      undefined,
      key.pubkeyB64,
      key.keyId,
    );
    expect(res.ok).toBe(false);
  });
});
