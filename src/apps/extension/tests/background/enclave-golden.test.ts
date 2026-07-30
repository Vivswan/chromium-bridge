// Golden-vector replay: the cross-language enclave crypto contract, pinned.
//
// The fixture (enclave-fixture.gen.ts, "@chromium-bridge/shared/testing") is
// generated from the Rust core by `moon run gen`: message bytes built by
// challenge_message/presence_message and deterministic software-P256
// signatures routed through the host's DER -> P1363 converter. Replaying it
// through the extension's WebCrypto verifier means either side drifting from
// the shared byte contract breaks a gate: a Rust-side change regenerates the
// fixture (check-gen fails until it does), and a TS verifier that no longer
// reconstructs or accepts those exact bytes fails here.
//
// The fixture key's private scalar is public repo data, so it is deny-listed
// as an ENROLLMENT identity (ENCLAVE_FIXTURE_KEY_ID): pairing-time
// verification and the stored trust-record schemas must refuse it outright.
// Steady-state pin verification stays pure - it verifies against whatever
// pin the caller supplies - which is what lets this suite replay the vectors
// at all: in production no fixture pin can exist, because every path that
// creates one is denied.

import {
  CHALLENGE_DOMAIN,
  ENCLAVE_FIXTURE_KEY_ID,
  EnclavePinSchema,
  MAX_CONTEXT_BYTES,
  MAX_NONCE_BYTES,
  PendingPairingSchema,
  PRESENCE_DOMAIN,
} from "@chromium-bridge/shared";
import { ENCLAVE_GOLDEN_FIXTURE } from "@chromium-bridge/shared/testing";
import { describe, expect, test } from "vitest";
import {
  base64Decode,
  base64Encode,
  buildChallengeMessage,
  buildPresenceMessage,
  computeKeyId,
  parsePubkey,
  verifyPairingProof,
  verifyPresenceProofAgainstPin,
  verifyProofAgainstPin,
} from "@/lib/background/enclave-verify";

const { pubkeyB64, keyIdHex, vectors } = ENCLAVE_GOLDEN_FIXTURE;

function hexDecode(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function buildMessage(v: (typeof vectors)[number]): Uint8Array {
  const build = v.domain === "challenge" ? buildChallengeMessage : buildPresenceMessage;
  return build(v.nonce, v.context ?? undefined);
}

describe("enclave golden vectors (Rust-generated fixture)", () => {
  test("the fixture covers both domains, a None context, multi-byte UTF-8, and both bounds", () => {
    // Guard the fixture's own coverage, so trimming the Rust vector matrix
    // cannot silently weaken this suite.
    expect(vectors.some((v) => v.domain === "challenge")).toBe(true);
    expect(vectors.some((v) => v.domain === "presence")).toBe(true);
    expect(vectors.some((v) => v.context === null)).toBe(true);
    expect(vectors.some((v) => v.context === "")).toBe(true);
    const utf8 = new TextEncoder();
    // A vector where byte length and JS string length diverge: the bound
    // checks are BYTE counts, the most plausible cross-language drift point.
    expect(
      vectors.some(
        (v) =>
          utf8.encode(v.nonce).length !== v.nonce.length ||
          (v.context !== null && utf8.encode(v.context).length !== v.context.length),
      ),
    ).toBe(true);
    expect(
      vectors.some(
        (v) =>
          utf8.encode(v.nonce).length === MAX_NONCE_BYTES &&
          utf8.encode(v.context ?? "").length === MAX_CONTEXT_BYTES,
      ),
    ).toBe(true);
  });

  test("buildChallengeMessage/buildPresenceMessage reconstruct the Rust bytes exactly", () => {
    for (const v of vectors) {
      expect(base64Encode(buildMessage(v))).toBe(base64Encode(hexDecode(v.messageHex)));
    }
  });

  test("the Rust bytes are prefixed by the matching generated domain", () => {
    const utf8 = new TextEncoder();
    for (const v of vectors) {
      const domain = v.domain === "challenge" ? CHALLENGE_DOMAIN : PRESENCE_DOMAIN;
      const prefix = [...utf8.encode(domain), 0];
      expect(Array.from(hexDecode(v.messageHex).slice(0, prefix.length))).toEqual(prefix);
    }
  });

  test("the fixture key parses and its key_id is the deny-listed identity", async () => {
    const pubkey = parsePubkey(pubkeyB64);
    expect(await computeKeyId(pubkey)).toBe(keyIdHex);
    expect(keyIdHex).toBe(ENCLAVE_FIXTURE_KEY_ID);
  });

  test("every proof verifies against the fixture-pinned pubkey under its domain", async () => {
    for (const v of vectors) {
      const proof = { sig: v.sigB64, key_id: keyIdHex, pubkey: pubkeyB64 };
      const verify =
        v.domain === "challenge" ? verifyProofAgainstPin : verifyPresenceProofAgainstPin;
      const res = await verify(proof, v.nonce, v.context ?? undefined, pubkeyB64, keyIdHex);
      expect(res).toEqual({ ok: true });
    }
  });

  test("a proof never verifies under the other domain (no cross-replay)", async () => {
    for (const v of vectors) {
      const proof = { sig: v.sigB64, key_id: keyIdHex, pubkey: pubkeyB64 };
      const verifyOther =
        v.domain === "challenge" ? verifyPresenceProofAgainstPin : verifyProofAgainstPin;
      const res = await verifyOther(proof, v.nonce, v.context ?? undefined, pubkeyB64, keyIdHex);
      expect(res.ok).toBe(false);
    }
  });

  test("a tampered signature fails (the replay is not vacuous)", async () => {
    const v = vectors[0];
    if (!v) throw new Error("fixture has no vectors");
    const sig = base64Decode(v.sigB64);
    sig[7] = (sig[7] ?? 0) ^ 0x01;
    const proof = { sig: base64Encode(sig), key_id: keyIdHex, pubkey: pubkeyB64 };
    const res = await verifyProofAgainstPin(
      proof,
      v.nonce,
      v.context ?? undefined,
      pubkeyB64,
      keyIdHex,
    );
    expect(res.ok).toBe(false);
  });
});

describe("fixture key deny-list (never enrollable)", () => {
  // The attacker's capability: the fixture scalar is in the repo, so anyone
  // can sign a FRESH challenge with it. Same fixed bytes as Rust's
  // FIXTURE_KEY_BYTES (1..=32), imported into WebCrypto via JWK.
  const FIXTURE_SCALAR = new Uint8Array(Array.from({ length: 32 }, (_, i) => i + 1));

  function b64url(bytes: Uint8Array): string {
    return base64Encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  async function importFixturePrivateKey(): Promise<CryptoKey> {
    const pub = parsePubkey(pubkeyB64);
    const jwk: JsonWebKey = {
      kty: "EC",
      crv: "P-256",
      d: b64url(FIXTURE_SCALAR),
      x: b64url(pub.slice(1, 33)),
      y: b64url(pub.slice(33, 65)),
    };
    return crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, [
      "sign",
    ]);
  }

  test("checked-in proofs are refused at pairing time, before any crypto", async () => {
    for (const v of vectors) {
      if (v.domain !== "challenge") continue;
      const proof = { sig: v.sigB64, key_id: keyIdHex, pubkey: pubkeyB64 };
      const res = await verifyPairingProof(proof, v.nonce, v.context ?? undefined);
      expect(res.ok).toBe(false);
      if (!res.ok) expect(res.reason).toContain("never enrollable");
    }
  });

  test("a FRESH fixture-key signature over a new challenge is still refused", async () => {
    // Replay protection (stale nonces) is not what stops this key; the
    // identity deny-list is. Sign the extension's own fresh challenge with
    // the public scalar and watch pairing refuse it anyway.
    const key = await importFixturePrivateKey();
    const nonce = "0123456789abcdef".repeat(4);
    const message = buildChallengeMessage(nonce, "ctx-fresh");
    const sig = new Uint8Array(
      await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, message as BufferSource),
    );
    const proof = { sig: base64Encode(sig), key_id: keyIdHex, pubkey: pubkeyB64 };
    const res = await verifyPairingProof(proof, nonce, "ctx-fresh");
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toContain("never enrollable");
    // Sanity: the same fresh proof DOES verify cryptographically against an
    // explicit fixture pin, proving the refusal above is the deny-list, not
    // a broken signature.
    const pinRes = await verifyProofAgainstPin(proof, nonce, "ctx-fresh", pubkeyB64, keyIdHex);
    expect(pinRes).toEqual({ ok: true });
  });

  test("stored trust records naming the fixture key fail their schemas (read as absent)", () => {
    expect(
      EnclavePinSchema.safeParse({
        keyId: ENCLAVE_FIXTURE_KEY_ID,
        pubkeyB64,
        pinnedAt: Date.now(),
      }).success,
    ).toBe(false);
    expect(
      PendingPairingSchema.safeParse({
        keyId: ENCLAVE_FIXTURE_KEY_ID,
        pubkeyB64,
        at: Date.now(),
      }).success,
    ).toBe(false);
    // A non-fixture key of the same shape still parses: the deny-list is
    // exactly one identity wide.
    const otherId = keyIdHex.replace(/^../, keyIdHex.startsWith("00") ? "11" : "00");
    expect(
      EnclavePinSchema.safeParse({ keyId: otherId, pubkeyB64, pinnedAt: Date.now() }).success,
    ).toBe(true);
  });
});
