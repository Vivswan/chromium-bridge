/**
 * The WebAuthn exchange end to end, in an ISOLATED Chrome for Testing against the REAL native host: the
 * extension's service worker relays the host's frames, the options page runs the WebAuthn calls against a CDP
 * virtual authenticator, and the host (src/packages/core/src/native_host/presence.rs) decides. Everything the
 * Rust unit tests pin with a software authenticator is replayed here with Chrome's own client:
 *
 *   1  trust on first use           -> enroll_begin on a fresh machine answers enroll_options; create + enroll_finish
 *                                     records the credential (the trail carries the host-side enroll record)
 *   2  a later enrollment            -> enroll_begin is answered presence_required beside a pushed presence_request
 *                                     naming the enrolled credential; an assertion approves it; the next
 *                                     enroll_begin consumes the approval and a second credential enrolls
 *   3  a replayed assertion          -> an earlier assertion offered for a new request is refused
 *                                     (sign_count_not_increased: the counter already moved past it)
 *   4  an un-enrolled credential      -> a credential the host never saw is refused credential_not_enrolled
 *   5  a wrong challenge             -> an assertion over another challenge is refused challenge_mismatch
 *   6  the window on an enrolled browser -> presence_confirm is refused software_confirmation_not_allowed
 *   7  the refusals are audited       -> the host's audit.log names every refusal, under the extension surface
 *
 * The host runs in control-plane mode (the kill switch is engaged first in the isolated runtime dir), so no
 * broker is needed and the WebAuthn frames are the whole conversation. The runtime dir is a throwaway under
 * XDG_RUNTIME_DIR that the host wrapper exports, so nothing touches the real one. Kill release from the
 * extension is not driven here: the extension has no release message yet (the options page is engage-only).
 *
 * SAFETY: this launches a NON-HEADLESS Chrome with --load-extension, which can capture and close a real
 * session, so it refuses unless CHROME_BIN is an isolated Chrome for Testing / Chromium (tests/README.md).
 *
 * Run:  CHROME_BIN=/path/to/chrome-for-testing bun tests/browser/presence_exchange_test.ts
 */

import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { NATIVE_HOST_ID } from "@chromium-bridge/shared/identity.gen";
import puppeteer, { type Browser, type Page, type Target } from "puppeteer-core";
import {
  assertHostIsolated,
  assertIsolatedBrowserOrSkip,
  extensionDir,
  finishSuite,
  throwawayHostEnv,
  writeHostWrapper,
} from "./browser-safety";

const EXTENSION_DIR = extensionDir();
const CHROME = process.env.CHROME_BIN ?? "";
const REPO = path.resolve(import.meta.dir, "../..");
const BIN = path.join(REPO, "target", "release", "chromium-bridge");
// The manifest key pins the extension id; the host manifest authorizes only it.
const PINNED_ID = "mkjjlmjbcljpcfkfadfmhblmmddkdihf";
const BROWSER_LABEL = "brave";

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

/** Our extension's service worker, by its distinctive `nativeMessaging` permission. */
async function waitForExtension(browser: Browser): Promise<void> {
  for (let i = 0; i < 40; i++) {
    for (const t of browser.targets().filter((x: Target) => x.type() === "service_worker")) {
      const w = await t.worker().catch(() => null);
      if (!w) continue;
      const perms = (await w
        .evaluate(() => chrome.runtime.getManifest().permissions ?? [])
        .catch(() => [])) as string[];
      if (perms.includes("nativeMessaging")) return;
    }
    await sleep(500);
  }
  throw new Error("extension service worker not found");
}

/** Register the real host in the throwaway profile through the wrapper that sets the isolated runtime dir.
 * Profile-scoped: Chrome resolves user-level manifests under <user-data-dir>/NativeMessagingHosts on macOS
 * and Linux, so no real registration is touched. */
function registerHost(userDataDir: string, env: Record<string, string>): void {
  const wrapper = writeHostWrapper(
    userDataDir,
    BIN,
    ["--native-host", "--label", BROWSER_LABEL],
    env,
  );
  const dir = path.join(userDataDir, "NativeMessagingHosts");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, `${NATIVE_HOST_ID}.json`),
    JSON.stringify({
      name: NATIVE_HOST_ID,
      description: "presence_exchange_test host",
      path: wrapper,
      type: "stdio",
      allowed_origins: [`chrome-extension://${PINNED_ID}/`],
    }),
  );
}

interface AuditRecord {
  event_kind: string;
  surface?: string;
  outcome?: string;
  detail?: string;
}

function auditRecords(work: string): AuditRecord[] {
  const file = path.join(work, "runtime", "chromium-bridge", "audit.log");
  if (!fs.existsSync(file)) return [];
  return fs
    .readFileSync(file, "utf8")
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as AuditRecord);
}

// ---- what the options page runs -----------------------------------------------------------------------------

type Reply = { ok: true; [k: string]: unknown } | { ok: false; error: string };

/** One runtime message from the options page to the service worker (the router's extension-page gate). */
function send(page: Page, msg: Record<string, unknown>): Promise<Reply> {
  return page.evaluate((m) => chrome.runtime.sendMessage(m) as Promise<Reply>, msg);
}

interface EnrollOptions {
  challenge: string;
  nonce: string;
  user_id: string;
  user_name: string;
  exclude_credential_ids: string[];
}

interface PresenceRequest {
  challenge: string;
  nonce: string;
  action: string;
  allowed_credential_ids: string[];
}

interface Created {
  rawId: string;
  attestation_object: string;
  client_data_json: string;
}

interface Asserted {
  credential_id: string;
  authenticator_data: string;
  client_data_json: string;
  signature: string;
}

/** `navigator.credentials.create` for the host's options, shaped for enroll_finish. */
function createCredential(page: Page, options: EnrollOptions): Promise<Created> {
  return page.evaluate(async (o: EnrollOptions) => {
    const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON({
      rp: { id: chrome.runtime.id, name: "Chromium Bridge" },
      user: { id: o.user_id, name: o.user_name, displayName: o.user_name },
      challenge: o.challenge,
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      excludeCredentials: o.exclude_credential_ids.map((id) => ({ type: "public-key", id })),
      authenticatorSelection: { residentKey: "discouraged", userVerification: "preferred" },
      attestation: "none",
    });
    const credential = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential;
    const json = credential.toJSON();
    const response = json.response as AuthenticatorAttestationResponseJSON;
    return {
      rawId: json.rawId,
      attestation_object: response.attestationObject,
      client_data_json: response.clientDataJSON,
    };
  }, options) as Promise<Created>;
}

type Transport = "internal" | "usb";

/** `navigator.credentials.get` over `challenge`, scoped to one credential, shaped for presence_assert. The
 * transport hint routes the request to the authenticator that holds the credential; with two virtual
 * authenticators attached Chrome needs it to dispatch at all. */
function assertCredential(
  page: Page,
  challenge: string,
  credential: { id: string; transport: Transport },
): Promise<Asserted> {
  return page.evaluate(
    async (c: string, cred: { id: string; transport: Transport }) => {
      const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON({
        rpId: chrome.runtime.id,
        challenge: c,
        allowCredentials: [{ type: "public-key", id: cred.id, transports: [cred.transport] }],
        userVerification: "preferred",
      });
      const credential = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential;
      const json = credential.toJSON();
      const response = json.response as AuthenticatorAssertionResponseJSON;
      return {
        credential_id: json.rawId,
        authenticator_data: response.authenticatorData,
        client_data_json: response.clientDataJSON,
        signature: response.signature,
      };
    },
    challenge,
    credential,
  ) as Promise<Asserted>;
}

/** The pending presence request the worker holds, polled briefly: the host's push lands a tick after the
 * enroll_begin reply. */
async function pendingRequest(page: Page): Promise<PresenceRequest | null> {
  for (let i = 0; i < 20; i++) {
    const reply = await send(page, { type: "webauthn_presence_pending" });
    if (reply.ok && reply.request) return reply.request as PresenceRequest;
    await sleep(100);
  }
  return null;
}

/** `enroll_begin` on an enrolled machine: the reply is presence_required and a request is pushed. */
async function openLaterEnrollment(
  page: Page,
): Promise<{ reply: Reply; request: PresenceRequest | null }> {
  const reply = await send(page, { type: "webauthn_enroll_begin" });
  const request = await pendingRequest(page);
  return { reply, request };
}

async function main(): Promise<void> {
  assertIsolatedBrowserOrSkip();
  for (const [label, p] of [
    ["extension dir", EXTENSION_DIR],
    ["Chrome", CHROME],
    ["release binary", BIN],
  ] as const) {
    if (!fs.existsSync(p)) {
      console.error(`missing ${label}: ${p}`);
      process.exit(2);
    }
  }
  if (process.platform === "win32") {
    console.log("SKIP: profile-scoped host manifests exist on macOS and Linux only");
    process.exit(0);
  }

  // Everything after the mkdtemp runs under the one finally, so a failed step still removes the profile, the
  // wrapper, the manifest, and the throwaway runtime dir.
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "bb-presence-"));
  const userDataDir = path.join(work, "profile");
  let browser: Browser | null = null;
  // Every exit path (a crash, Ctrl-C, the normal finish) ends the Chrome this run started and removes its dir.
  process.on("exit", () => {
    browser?.process()?.kill("SIGKILL");
    fs.rmSync(work, { recursive: true, force: true });
  });
  process.on("SIGINT", () => process.exit(130));
  try {
    fs.mkdirSync(userDataDir);
    const env = throwawayHostEnv(work);
    // The binary's own word on where its lock resolves under this environment: outside the throwaway dir is
    // the user's live runtime dir, and the run refuses before the binary writes anything.
    try {
      assertHostIsolated(BIN, env, work);
    } catch (e) {
      console.error(`REFUSING TO RUN: ${e instanceof Error ? e.message : String(e)}`);
      process.exit(1);
    }
    // The kill switch first: a killed host serves only the control plane (the WebAuthn frames among them) and
    // never dials a broker, so the exchange is the whole conversation.
    execFileSync(BIN, ["kill"], { env, stdio: "pipe", timeout: 15000 });
    registerHost(userDataDir, env);

    browser = await puppeteer.launch({
      executablePath: CHROME,
      headless: false,
      // Ctrl-C routes through the exit hook above rather than puppeteer's own handler.
      handleSIGINT: false,
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
    await waitForExtension(browser);
    const page = await browser.newPage();
    await page.goto(`chrome-extension://${PINNED_ID}/options.html`, {
      waitUntil: "load",
      timeout: 15000,
    });
    // The platform authenticator's stand-in: user-verifying, presence simulated. A security key joins it for
    // the second credential: Chrome refuses to register a credential on an authenticator that already holds
    // one the options exclude (InvalidStateError), exactly the excludeCredentials behavior the host relies on,
    // and allows one internal authenticator per environment.
    const cdp = await page.createCDPSession();
    await cdp.send("WebAuthn.enable");
    const addAuthenticator = (transport: "internal" | "usb") =>
      cdp.send("WebAuthn.addVirtualAuthenticator", {
        options: {
          protocol: "ctap2",
          transport,
          hasResidentKey: false,
          hasUserVerification: true,
          isUserVerified: true,
          automaticPresenceSimulation: true,
        },
      });
    await addAuthenticator("internal");

    // 1: trust on first use. The worker's connect-time ceremony may still be in flight on a fresh profile, so
    // the first exchange is retried while the single-flight slot is busy.
    let begin: Reply = { ok: false, error: "not sent" };
    for (let i = 0; i < 40; i++) {
      begin = await send(page, { type: "webauthn_enroll_begin" });
      if (begin.ok || !/not connected|in flight/.test(begin.error)) break;
      await sleep(250);
    }
    check(
      begin.ok,
      "fresh machine: enroll_begin answers enroll_options (trust on first use)",
      begin,
    );
    if (!begin.ok) throw new Error("cannot continue without enroll_options");
    const options = begin.options as EnrollOptions;
    check(
      options.user_name === BROWSER_LABEL && options.exclude_credential_ids.length === 0,
      "the options name this browser and exclude nothing",
      options,
    );
    const first = await createCredential(page, options);
    const finish = await send(page, {
      type: "webauthn_enroll_finish",
      attestation_object: first.attestation_object,
      client_data_json: first.client_data_json,
    });
    check(
      finish.ok && finish.credentialId === first.rawId,
      "enroll_finish records the credential Chrome minted",
      finish,
    );

    // 2: a later enrollment needs presence, then the approval is consumed by the next enroll_begin.
    const later = await openLaterEnrollment(page);
    check(
      !later.reply.ok && later.reply.error === "presence_required",
      "enrolled machine: enroll_begin is answered presence_required",
      later.reply,
    );
    check(
      later.request !== null &&
        later.request.action === `enroll a credential for browser '${BROWSER_LABEL}'` &&
        later.request.allowed_credential_ids.length === 1 &&
        later.request.allowed_credential_ids[0] === first.rawId,
      "the pushed presence_request names the enrolled credential and the enroll action",
      later.request,
    );
    if (!later.request) throw new Error("cannot continue without a presence request");
    const approval = await assertCredential(page, later.request.challenge, {
      id: first.rawId,
      transport: "internal",
    });
    const approved = await send(page, {
      type: "webauthn_presence_assert",
      nonce: later.request.nonce,
      ...approval,
    });
    check(approved.ok, "an assertion from the enrolled credential approves the request", approved);
    const second = await send(page, { type: "webauthn_enroll_begin" });
    check(
      second.ok,
      "the next enroll_begin consumes the approval and answers enroll_options",
      second,
    );
    if (!second.ok) throw new Error("cannot continue without the second enroll_options");
    const secondOptions = second.options as EnrollOptions;
    check(
      secondOptions.exclude_credential_ids.length === 1 &&
        secondOptions.exclude_credential_ids[0] === first.rawId,
      "the second options exclude the first credential",
      secondOptions,
    );
    await addAuthenticator("usb");
    const secondCredential = await createCredential(page, secondOptions);
    const secondFinish = await send(page, {
      type: "webauthn_enroll_finish",
      attestation_object: secondCredential.attestation_object,
      client_data_json: secondCredential.client_data_json,
    });
    check(
      secondFinish.ok && secondFinish.credentialId === secondCredential.rawId,
      "the second credential enrolls under the same browser",
      secondFinish,
    );

    // 3: the approval assertion, offered again for a fresh request, is a replay.
    const replayTarget = await openLaterEnrollment(page);
    if (!replayTarget.request) throw new Error("no presence request for the replay");
    const replayed = await send(page, {
      type: "webauthn_presence_assert",
      nonce: replayTarget.request.nonce,
      ...approval,
    });
    check(
      !replayed.ok && replayed.error === "sign_count_not_increased",
      "a replayed assertion is refused: the counter already moved past it",
      replayed,
    );

    // 4: a credential the host never enrolled.
    const strayChallenge = Buffer.from("stray enrollment, never shown to the host").toString(
      "base64url",
    );
    const stray = await createCredential(page, {
      challenge: strayChallenge,
      nonce: "unused",
      user_id: Buffer.from("stray").toString("base64url"),
      user_name: "stray",
      // Excluding the internal authenticator's credential routes the creation to the security key.
      exclude_credential_ids: [first.rawId],
    });
    const unenrolledTarget = await openLaterEnrollment(page);
    if (!unenrolledTarget.request) throw new Error("no presence request for the stray credential");
    const strayAssertion = await assertCredential(page, unenrolledTarget.request.challenge, {
      id: stray.rawId,
      transport: "usb",
    });
    const unenrolled = await send(page, {
      type: "webauthn_presence_assert",
      nonce: unenrolledTarget.request.nonce,
      ...strayAssertion,
    });
    check(
      !unenrolled.ok && unenrolled.error === "credential_not_enrolled",
      "an assertion from a credential the host never enrolled is refused",
      unenrolled,
    );

    // 5: the right credential and nonce over the wrong challenge.
    const mismatchTarget = await openLaterEnrollment(page);
    if (!mismatchTarget.request) throw new Error("no presence request for the challenge mismatch");
    const otherChallenge = Buffer.from("some other statement").toString("base64url");
    const overOther = await assertCredential(page, otherChallenge, {
      id: first.rawId,
      transport: "internal",
    });
    const mismatch = await send(page, {
      type: "webauthn_presence_assert",
      nonce: mismatchTarget.request.nonce,
      ...overOther,
    });
    check(
      !mismatch.ok && mismatch.error === "challenge_mismatch",
      "an assertion over another challenge is refused",
      mismatch,
    );

    // 6: the window may not vouch for a browser that has an enrolled credential.
    const windowTarget = await openLaterEnrollment(page);
    if (!windowTarget.request) throw new Error("no presence request for the window answer");
    const confirmed = await send(page, {
      type: "webauthn_presence_confirm",
      nonce: windowTarget.request.nonce,
    });
    check(
      !confirmed.ok && confirmed.error === "software_confirmation_not_allowed",
      "the window's confirmation is refused on an enrolled browser (no downgrade)",
      confirmed,
    );

    // 7: the host's trail, under the extension surface.
    const trail = auditRecords(work);
    const enrolls = trail.filter((r) => r.event_kind === "enroll" && r.outcome === "ok");
    const refusals = trail
      .filter((r) => r.event_kind === "presence_assert" && r.outcome === "refused")
      .map((r) => r.detail ?? "");
    check(
      enrolls.length === 2 && enrolls.every((r) => r.surface === "extension"),
      "audit.log carries both host-side enroll records under the extension surface",
      enrolls,
    );
    check(
      ["signCount", "not enrolled", "statement's challenge", "window confirmation"].every(
        (needle) => refusals.some((d) => d.includes(needle)),
      ),
      "audit.log names the replay, the unknown credential, the challenge mismatch, and the window refusal",
      refusals,
    );
  } finally {
    if (browser) await browser.close().catch(() => {});
  }
  finishSuite("presence_exchange_test", Pass, Fail);
}

main().catch((e) => {
  console.error("presence_exchange_test crashed:", e);
  finishSuite("presence_exchange_test", Pass, Fail + 1);
});
