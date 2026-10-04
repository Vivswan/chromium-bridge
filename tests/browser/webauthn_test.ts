/**
 * WebAuthn in an ISOLATED Chrome for Testing: the facts about the browser's WebAuthn client that the host's
 * verifier (src/packages/core/src/webauthn) assumes and no unit test can see. A CDP virtual authenticator
 * stands in for Touch ID; the options page is the RP page, exactly where lib/webauthn/ceremony.ts runs.
 *
 *   1  chrome-extension:// is a WebAuthn RP     -> create succeeds with rpId = the extension id
 *   2  clientDataJSON as the host parses it     -> type, the challenge echoed base64url unpadded, origin
 *                                                  chrome-extension://<id>, no crossOrigin
 *   3  attestation "none" is honored            -> the attestationObject opens with the canonical
 *                                                  { fmt: "none", attStmt: {} } bytes
 *   4  the credential key is ES256              -> getPublicKeyAlgorithm() is -7
 *   5  authenticatorData layout                 -> rpIdHash = sha256("chrome-extension://<id>"), UP set, AT on create
 *   6  the assertion answers the same credential -> rawId matches, UP set, and the DER signature verifies under
 *                                                  the credential's key over authenticatorData || sha256(clientDataJSON),
 *                                                  exactly the bytes the host verifies (a flipped byte fails)
 *   7  the feature probe sees the authenticator  -> isUserVerifyingPlatformAuthenticatorAvailable() is true
 *
 * SAFETY: this launches a NON-HEADLESS Chrome with --load-extension, which can capture and close a real
 * session, so it refuses unless CHROME_BIN is an isolated Chrome for Testing / Chromium (tests/README.md).
 *
 * Run:  CHROME_BIN=/path/to/chrome-for-testing bun tests/browser/webauthn_test.ts
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import puppeteer, { type Browser, type Target } from "puppeteer-core";
import { assertIsolatedBrowserOrSkip, extensionDir, finishSuite } from "./browser-safety";

const EXTENSION_DIR = extensionDir();
const CHROME = process.env.CHROME_BIN ?? "";

let Pass = 0;
let Fail = 0;
function check(cond: boolean, label: string, detail?: unknown): void {
  if (cond) {
    Pass++;
    console.log(`  PASS  ${label}`);
  } else {
    Fail++;
    console.log(`  FAIL  ${label}${detail !== undefined ? ` :: ${JSON.stringify(detail)}` : ""}`);
  }
}
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Our extension's id, found by its distinctive `nativeMessaging` permission (Chrome for Testing ships
 * component extensions whose service workers also match a naive type filter). */
async function findExtensionId(browser: Browser): Promise<string> {
  for (let i = 0; i < 40; i++) {
    for (const t of browser.targets().filter((x: Target) => x.type() === "service_worker")) {
      const w = await t.worker().catch(() => null);
      if (!w) continue;
      const perms = (await w
        .evaluate(() => chrome.runtime.getManifest().permissions ?? [])
        .catch(() => [])) as string[];
      if (perms.includes("nativeMessaging")) {
        return (await w.evaluate(() => chrome.runtime.id)) as string;
      }
    }
    await sleep(500);
  }
  throw new Error("extension service worker not found");
}

const b64url = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64url");
const unb64url = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "base64url"));
const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");
async function sha256(text: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
}

/** The canonical CBOR opening of a `none` attestation object: a 3-entry map, "fmt": "none", "attStmt": {}.
 * Everything after it is "authData" and its byte string. */
const NONE_ATTESTATION_PREFIX =
  "a3" + "63666d74" + "646e6f6e65" + "6761747453746d74" + "a0" + "686175746844617461";

interface CreateResult {
  rawId: string;
  clientDataJSON: string;
  attestationObject: string;
  authenticatorData: string;
  publicKeyAlgorithm: number;
  /** The credential public key as SPKI DER, from getPublicKey(). */
  publicKey: string;
}

interface GetResult {
  rawId: string;
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
}

interface ClientData {
  type?: string;
  challenge?: string;
  origin?: string;
  crossOrigin?: boolean;
}

async function main(): Promise<void> {
  assertIsolatedBrowserOrSkip();
  for (const [label, p] of [
    ["extension dir", EXTENSION_DIR],
    ["Chrome", CHROME],
  ] as const) {
    if (!fs.existsSync(p)) {
      console.error(`missing ${label}: ${p}`);
      process.exit(2);
    }
  }

  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "bb-webauthn-"));
  let browser: Browser | null = null;
  try {
    browser = await puppeteer.launch({
      executablePath: CHROME,
      headless: false,
      userDataDir,
      ignoreDefaultArgs: [
        "--disable-extensions",
        "--enable-automation",
        "--disable-component-extensions-with-background-pages",
      ],
      args: [
        `--disable-extensions-except=${EXTENSION_DIR}`,
        `--load-extension=${EXTENSION_DIR}`,
        "--no-first-run",
        "--no-default-browser-check",
        "--no-sandbox",
        "--disable-dev-shm-usage",
      ],
      defaultViewport: null,
    });
    const extId = await findExtensionId(browser);
    const origin = `chrome-extension://${extId}`;

    const page = await browser.newPage();
    await page.goto(`${origin}/options.html`, { waitUntil: "load", timeout: 15000 });

    // Touch ID's stand-in: a CTAP2 platform ("internal") authenticator that verifies the user, with presence
    // simulated so the ceremony needs no finger.
    const cdp = await page.createCDPSession();
    await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2",
        transport: "internal",
        hasResidentKey: false,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    });

    const enrollChallenge = b64url(await sha256("enrollment statement"));
    const created = (await page.evaluate(async (challenge: string) => {
      const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON({
        rp: { id: chrome.runtime.id, name: "Chromium Bridge" },
        user: { id: "dXNlci1pZA", name: "brave", displayName: "brave" },
        challenge,
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: { residentKey: "discouraged", userVerification: "preferred" },
        attestation: "none",
      });
      const credential = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential;
      const response = credential.response as AuthenticatorAttestationResponse;
      const json = credential.toJSON();
      const attestation = json.response as AuthenticatorAttestationResponseJSON;
      const toB64url = (buf: ArrayBuffer) =>
        btoa(String.fromCharCode(...new Uint8Array(buf)))
          .replace(/\+/g, "-")
          .replace(/\//g, "_")
          .replace(/=+$/, "");
      return {
        rawId: json.rawId,
        clientDataJSON: attestation.clientDataJSON,
        attestationObject: attestation.attestationObject,
        authenticatorData: toB64url(response.getAuthenticatorData()),
        publicKeyAlgorithm: response.getPublicKeyAlgorithm(),
        publicKey: toB64url(response.getPublicKey() ?? new ArrayBuffer(0)),
      };
    }, enrollChallenge)) as CreateResult;

    // 1 + 2: the RP and the clientDataJSON the host parses.
    const createData = JSON.parse(
      new TextDecoder().decode(unb64url(created.clientDataJSON)),
    ) as ClientData;
    check(
      created.rawId.length >= 22,
      "chrome-extension origin is a WebAuthn RP: create minted a credential",
      created.rawId,
    );
    check(
      createData.type === "webauthn.create" &&
        createData.challenge === enrollChallenge &&
        createData.origin === origin &&
        createData.crossOrigin !== true,
      "create clientDataJSON: type webauthn.create, the challenge echoed base64url unpadded, origin chrome-extension://<id>",
      createData,
    );

    // 3 + 4: attestation none, ES256.
    check(
      hex(unb64url(created.attestationObject)).startsWith(NONE_ATTESTATION_PREFIX),
      "attestation 'none' is honored: the object opens with the canonical { fmt: none, attStmt: {} } bytes",
      hex(unb64url(created.attestationObject)).slice(0, 48),
    );
    check(
      created.publicKeyAlgorithm === -7,
      "the credential key is ES256 (COSE alg -7)",
      created.publicKeyAlgorithm,
    );

    // 5: the authenticatorData header the host's byte parser expects. For an extension RP Chrome's RP ID is
    // the whole origin string, not the bare id: rpIdHash = sha256("chrome-extension://<id>"), the fact
    // RpId::hash in the Rust verifier encodes.
    const rpIdHash = hex(await sha256(origin));
    const createAuth = unb64url(created.authenticatorData);
    const createFlags = createAuth[32] ?? 0;
    check(
      hex(createAuth.slice(0, 32)) === rpIdHash &&
        (createFlags & 0x01) !== 0 &&
        (createFlags & 0x40) !== 0,
      "create authenticatorData: rpIdHash = sha256(the chrome-extension origin), UP set, attested credential data present",
      { rpIdHash: hex(createAuth.slice(0, 32)), flags: createFlags.toString(16) },
    );
    const credIdLen = ((createAuth[53] ?? 0) << 8) | (createAuth[54] ?? 0);
    check(
      b64url(createAuth.slice(55, 55 + credIdLen)) === created.rawId,
      "the credential id inside attestedCredentialData is the credential's rawId",
      { credIdLen },
    );

    // 6: an assertion for the presence statement, scoped to the enrolled credential.
    const presenceChallenge = b64url(await sha256("presence statement"));
    const asserted = (await page.evaluate(
      async (challenge: string, rawId: string) => {
        const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON({
          rpId: chrome.runtime.id,
          challenge,
          allowCredentials: [{ type: "public-key", id: rawId }],
          userVerification: "preferred",
        });
        const credential = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential;
        const json = credential.toJSON();
        const assertion = json.response as AuthenticatorAssertionResponseJSON;
        return {
          rawId: json.rawId,
          clientDataJSON: assertion.clientDataJSON,
          authenticatorData: assertion.authenticatorData,
          signature: assertion.signature,
        };
      },
      presenceChallenge,
      created.rawId,
    )) as GetResult;
    const getData = JSON.parse(
      new TextDecoder().decode(unb64url(asserted.clientDataJSON)),
    ) as ClientData;
    const getAuth = unb64url(asserted.authenticatorData);
    const getFlags = getAuth[32] ?? 0;
    check(
      asserted.rawId === created.rawId &&
        getData.type === "webauthn.get" &&
        getData.challenge === presenceChallenge &&
        getData.origin === origin,
      "get answers with the enrolled credential and a webauthn.get clientDataJSON echoing the challenge",
      { rawId: asserted.rawId, getData },
    );
    check(
      getAuth.length === 37 && hex(getAuth.slice(0, 32)) === rpIdHash && (getFlags & 0x01) !== 0,
      "get authenticatorData: 37 bytes (no attested data, no extensions), rpIdHash, UP set",
      { len: getAuth.length, flags: getFlags.toString(16) },
    );
    // The exact bytes the host's verifier signs over, verified here under the credential's own key with a
    // library DER parser; the control flips one signed byte and must fail through the same call.
    const key = crypto.createPublicKey({
      key: Buffer.from(unb64url(created.publicKey)),
      format: "der",
      type: "spki",
    });
    const signed = Buffer.concat([
      Buffer.from(getAuth),
      Buffer.from(await crypto.subtle.digest("SHA-256", unb64url(asserted.clientDataJSON))),
    ]);
    const verifies = (data: Buffer): boolean =>
      crypto.verify(
        "sha256",
        data,
        { key, dsaEncoding: "der" },
        Buffer.from(unb64url(asserted.signature)),
      );
    const tampered = Buffer.from(signed);
    tampered[32] = (tampered[32] ?? 0) ^ 0x04;
    check(
      verifies(signed) && !verifies(tampered),
      "the DER signature verifies under the credential's ES256 key over authenticatorData || sha256(clientDataJSON), and fails on a flipped byte",
      { verifies: verifies(signed), tamperedVerifies: verifies(tampered) },
    );

    // 7: the probe the page's surface label keys on.
    const uvpaa = (await page.evaluate(() =>
      PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(),
    )) as boolean;
    check(
      uvpaa === true,
      "isUserVerifyingPlatformAuthenticatorAvailable() sees the platform authenticator",
      uvpaa,
    );
  } finally {
    if (browser) await browser.close().catch(() => {});
    fs.rmSync(userDataDir, { recursive: true, force: true });
  }
  finishSuite("webauthn_test", Pass, Fail);
}

main().catch((e) => {
  console.error("webauthn_test crashed:", e);
  finishSuite("webauthn_test", Pass, Fail + 1);
});
