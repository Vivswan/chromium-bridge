/**
 * The WebAuthn exchange end to end, in ISOLATED Chrome for Testing instances against the REAL native host: the
 * options page drives the ceremonies against CDP virtual authenticators, the extension's service worker relays
 * the host's frames, and the host (src/packages/core/src/native_host/presence.rs) decides. Two browsers share
 * the host's trust store, as two browsers on one machine do, each fronted by its own host under its own label.
 *
 *   1  trust on first use           -> browser A's "Enroll this browser" enrolls its authenticator in one click;
 *                                     the panel shows the credential, the trail carries the enroll record
 *   2  the window on a bare browser  -> browser B (no credential) releases the kill switch from its panel through
 *                                     the software confirmation the host offers it; the trail names confirm_window
 *   3  a second browser's enrollment -> B's "Enroll this browser" is met with the approval step naming the host's
 *                                     action; its authenticator, holding A's credential as a shared platform
 *                                     authenticator would, approves it, and the enrollment continues on its own
 *   4  release behind a tap          -> A releases the kill switch from its panel with its enrolled authenticator;
 *                                     the trail names the credential
 *   5  a replayed assertion          -> an earlier assertion offered for a new request is refused
 *                                     (sign_count_not_increased: the counter already moved past it)
 *   6  an un-enrolled credential      -> a credential the host never saw is refused credential_not_enrolled
 *   7  a wrong challenge             -> an assertion over another challenge is refused challenge_mismatch
 *   8  the window on an enrolled browser -> presence_confirm is refused software_confirmation_not_allowed
 *   9  the refusals are audited       -> the host's audit.log names every refusal, under the extension surface
 *
 * The host runs in control-plane mode (the kill switch is engaged first in the isolated runtime dir), so no
 * broker is needed and the control frames are the whole conversation. A release ends that mode (the host exits
 * and the next one, with no broker to dial, cannot stay up), so each release is followed by the CLI's `kill`,
 * after which the reconnecting hosts push the engaged state back to both panels. The runtime dir is a throwaway
 * under XDG_RUNTIME_DIR that the host wrapper exports, so nothing touches the real one.
 *
 * SAFETY: this launches NON-HEADLESS Chromes with --load-extension, which can capture and close a real
 * session, so it refuses unless CHROME_BIN is an isolated Chrome for Testing / Chromium (tests/README.md).
 *
 * Run:  CHROME_BIN=/path/to/chrome-for-testing bun tests/browser/presence_exchange_test.ts
 */

import { execFileSync } from "node:child_process";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { NATIVE_HOST_ID } from "@chromium-bridge/shared/identity.gen";
import { PRESENCE_REQUIRED } from "@chromium-bridge/shared/webauthn";
import puppeteer, {
  type Browser,
  type CDPSession,
  type ElementHandle,
  type Page,
  type Target,
} from "puppeteer-core";
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
const BROWSER_A = "brave";
const BROWSER_B = "chrome";

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

/** Register the real host in a throwaway profile through the wrapper that sets the isolated runtime dir and
 * names the browser the host fronts. Profile-scoped: Chrome resolves user-level manifests under
 * <user-data-dir>/NativeMessagingHosts on macOS and Linux, so no real registration is touched. */
function registerHost(userDataDir: string, env: Record<string, string>, label: string): void {
  const wrapper = writeHostWrapper(userDataDir, BIN, ["--native-host", "--label", label], env);
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

/** The host's audit spelling of a credential: `webauthn:` plus the SHA-256 of the raw id. */
function credentialFingerprint(credentialIdB64url: string): string {
  const digest = crypto
    .createHash("sha256")
    .update(Buffer.from(credentialIdB64url, "base64url"))
    .digest("hex");
  return `webauthn:${digest}`;
}

// ---- one isolated browser ------------------------------------------------------------------------------------

interface Instance {
  browser: Browser;
  page: Page;
  cdp: CDPSession;
  /** The internal (platform) virtual authenticator standing in for Touch ID. */
  authenticatorId: string;
}

async function launch(userDataDir: string): Promise<Instance> {
  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: false,
    // Ctrl-C routes through main's exit hook rather than puppeteer's own handler.
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
  // Until this returns, the browser is this helper's to close: a setup failure must not leave it running
  // behind a profile the caller's cleanup is about to delete.
  try {
    await waitForExtension(browser);
    const page = await browser.newPage();
    await page.goto(`chrome-extension://${PINNED_ID}/options.html`, {
      waitUntil: "load",
      timeout: 15000,
    });
    // The platform authenticator's stand-in: user-verifying, presence simulated, so the ceremony needs no finger.
    const cdp = await page.createCDPSession();
    await cdp.send("WebAuthn.enable");
    const { authenticatorId } = await addAuthenticator(cdp, "internal");
    return { browser, page, cdp, authenticatorId };
  } catch (e) {
    await browser.close().catch(() => {});
    throw e;
  }
}

function addAuthenticator(cdp: CDPSession, transport: "internal" | "usb") {
  return cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport,
      hasResidentKey: false,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
}

/** Put `credential` (as WebAuthn.getCredentials exported it) on `into`'s authenticator at `signCount`: the one
 * adapter behind the shared-authenticator model, both for the copy and for carrying the counter back. */
function copyCredential(
  into: Instance,
  credential: Awaited<ReturnType<typeof exportedCredentials>>[number],
  signCount: number,
) {
  const { credentialId, isResidentCredential, rpId, privateKey, userHandle } = credential;
  return into.cdp.send("WebAuthn.addCredential", {
    authenticatorId: into.authenticatorId,
    credential: {
      credentialId,
      isResidentCredential,
      privateKey,
      signCount,
      ...(rpId === undefined ? {} : { rpId }),
      ...(userHandle === undefined ? {} : { userHandle }),
    },
  });
}

async function exportedCredentials(instance: Instance) {
  const { credentials } = await instance.cdp.send("WebAuthn.getCredentials", {
    authenticatorId: instance.authenticatorId,
  });
  return credentials;
}

// ---- the options page, as the user drives it -----------------------------------------------------------------

async function waitForText(page: Page, text: string, timeoutMs = 30000): Promise<void> {
  await page.waitForFunction(
    (t: string) => document.body.innerText.includes(t),
    { timeout: timeoutMs },
    text,
  );
}

/** Whichever of `texts` appears first (a release leaves the host gone, so the alive line may be the stale one). */
async function waitForAnyText(page: Page, texts: string[], timeoutMs = 30000): Promise<string> {
  const handle = await page.waitForFunction(
    (ts: string[]) => ts.find((t) => document.body.innerText.includes(t)) ?? null,
    { timeout: timeoutMs },
    texts,
  );
  return (await handle.jsonValue()) as string;
}

/** Click the enabled button whose whole label is `label`, once it exists. */
async function clickButton(page: Page, label: string): Promise<void> {
  const handle = await page.waitForFunction(
    (l: string) =>
      [...document.querySelectorAll("button")].find(
        (b) => b.textContent?.trim() === l && !b.disabled,
      ) ?? null,
    { timeout: 30000 },
    label,
  );
  await (handle.asElement() as ElementHandle<Element>).click();
}

// The panel's English copy (src/apps/extension/src/locales/en.yml); the throwaway profile's UI language is en.
const UI = {
  killed: "Engaged - all bridge activity is refused",
  alive: ["Off - the bridge is serving", "Last known: alive (host unreachable - unverified)"],
  release: "Release kill switch",
  windowTitle: "No authenticator is enrolled from this browser",
  confirmRelease: "Confirm release",
  notEnrolled: "No authenticator enrolled from this browser.",
  enroll: "Enroll this browser",
  enrolledNow: "Enrolled. The host recorded this credential.",
  approvalTitle: "Approval needed: this machine already has an enrolled browser",
  approve: "Approve with an enrolled authenticator",
};

/** Engage the switch from the CLI and wait until the reconnecting hosts have pushed it to every panel. */
async function reengage(env: Record<string, string>, pages: Page[]): Promise<void> {
  execFileSync(BIN, ["kill"], { env, stdio: "pipe", timeout: 15000 });
  for (const page of pages) await waitForText(page, UI.killed);
}

// ---- what the options page runs, at the message level ----------------------------------------------------------

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

  // Everything after the mkdtemp runs under the one finally, so a failed step still removes the profiles, the
  // wrappers, the manifests, and the throwaway runtime dir.
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "bb-presence-"));
  const profileA = path.join(work, "profile-a");
  const profileB = path.join(work, "profile-b");
  const instances: Instance[] = [];
  // Every exit path (a crash, Ctrl-C, the normal finish) ends the Chromes this run started and removes its dir.
  process.on("exit", () => {
    for (const { browser } of instances) browser.process()?.kill("SIGKILL");
    fs.rmSync(work, { recursive: true, force: true });
  });
  process.on("SIGINT", () => process.exit(130));
  try {
    for (const dir of [profileA, profileB]) fs.mkdirSync(dir);
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
    registerHost(profileA, env, BROWSER_A);
    registerHost(profileB, env, BROWSER_B);

    const a = await launch(profileA);
    instances.push(a);
    // The host's startup push of the engaged state is the proof the port is up before the panel is driven.
    await waitForText(a.page, UI.killed);

    // 1: trust on first use, from the panel.
    await waitForText(a.page, UI.notEnrolled);
    await clickButton(a.page, UI.enroll);
    await waitForText(a.page, UI.enrolledNow);
    const aCredentials = await exportedCredentials(a);
    const aCredential = aCredentials[0];
    if (!aCredential)
      throw new Error("browser A's authenticator holds no credential after enrolling");
    const aId = Buffer.from(aCredential.credentialId, "base64").toString("base64url");
    // The worker's note lands a storage event after the enrolled line, so the id is waited for, not read once.
    await waitForText(a.page, aId);
    check(
      aCredentials.length === 1,
      "browser A: Enroll this browser enrolls the authenticator's one credential and the panel shows it",
      { aCredentials: aCredentials.length, aId },
    );
    const firstEnroll = auditRecords(work).filter((r) => r.event_kind === "enroll");
    check(
      firstEnroll.length === 1 &&
        firstEnroll[0]?.outcome === "ok" &&
        firstEnroll[0].surface === "extension" &&
        (firstEnroll[0].detail ?? "").includes(`browser=${BROWSER_A}`) &&
        (firstEnroll[0].detail ?? "").includes("authorized_by=first_use"),
      "audit.log carries A's enroll record under the extension surface, authorized by first use",
      firstEnroll,
    );

    // 2: browser B, with no credential of its own, releases the kill switch through the software confirmation.
    const b = await launch(profileB);
    instances.push(b);
    await waitForText(b.page, UI.killed);
    await clickButton(b.page, UI.release);
    await waitForText(b.page, UI.windowTitle);
    await clickButton(b.page, UI.confirmRelease);
    // The released line is transient (the host's next frame moves the mirror and the panel re-renders), so
    // the state line is what is waited on.
    const bAlive = await waitForAnyText(b.page, UI.alive);
    const windowRelease = auditRecords(work).filter((r) => r.event_kind === "kill_release");
    check(
      windowRelease.length === 1 &&
        windowRelease[0]?.outcome === "ok" &&
        windowRelease[0].surface === "extension" &&
        windowRelease[0].detail === "auth=confirm_window",
      `browser B (no credential): the panel's software confirmation releases the switch (panel: ${bAlive})`,
      windowRelease,
    );
    await reengage(env, [a.page, b.page]);

    // 3: B enrolls. The machine has A's enrollment, so the host wants an approval from an enrolled credential;
    // B's authenticator holds A's credential, as a platform authenticator shared across browsers would.
    await copyCredential(b, aCredential, aCredential.signCount);
    await waitForText(b.page, UI.notEnrolled);
    await clickButton(b.page, UI.enroll);
    await waitForText(b.page, UI.approvalTitle);
    const approvalShown = (await b.page.evaluate(() => document.body.innerText)).includes(
      `The host asks you to approve: enroll a credential for browser '${BROWSER_B}'`,
    );
    await clickButton(b.page, UI.approve);
    await waitForText(b.page, UI.enrolledNow);
    const bCredentials = await exportedCredentials(b);
    const bOwn = bCredentials.find((c) => c.credentialId !== aCredential.credentialId);
    const bEnroll = auditRecords(work).filter(
      (r) => r.event_kind === "enroll" && (r.detail ?? "").includes(`browser=${BROWSER_B}`),
    );
    check(
      approvalShown &&
        bOwn !== undefined &&
        bEnroll.length === 1 &&
        bEnroll[0]?.outcome === "ok" &&
        (bEnroll[0].detail ?? "").includes(`authorized_by=${credentialFingerprint(aId)}`),
      "browser B: the approval step names the host's action, A's credential approves it, and B's own credential enrolls under B's label",
      { approvalShown, bCredentials: bCredentials.length, bEnroll },
    );

    // One authenticator, one counter: B's copy signed, so the host's stored count moved past A's own copy, and
    // A's next assertion would read as a clone (sign_count_not_increased, as the host's clone detection should
    // say). A shared platform authenticator advances the one counter both browsers see, so carry it back.
    const bCopy = bCredentials.find((c) => c.credentialId === aCredential.credentialId);
    if (!bCopy) throw new Error("browser B's authenticator lost A's credential");
    await a.cdp.send("WebAuthn.removeCredential", {
      authenticatorId: a.authenticatorId,
      credentialId: aCredential.credentialId,
    });
    await copyCredential(a, aCredential, bCopy.signCount);

    // 4: A releases the switch behind a tap on its enrolled authenticator.
    await clickButton(a.page, UI.release);
    const aAlive = await waitForAnyText(a.page, UI.alive);
    const tapRelease = auditRecords(work).filter((r) => r.event_kind === "kill_release");
    check(
      tapRelease.length === 2 &&
        tapRelease[1]?.outcome === "ok" &&
        tapRelease[1].surface === "extension" &&
        tapRelease[1].detail === `auth=${credentialFingerprint(aId)}`,
      `browser A: Release kill switch is answered by its enrolled credential's assertion (panel: ${aAlive})`,
      tapRelease,
    );
    await reengage(env, [a.page, b.page]);

    // The remaining checks drive A at the message level: the host's refusal codes, each as the extension
    // receives it. The approval assertion for the replay is minted here first.
    const approvalTarget = await openLaterEnrollment(a.page);
    check(
      !approvalTarget.reply.ok &&
        approvalTarget.reply.error === PRESENCE_REQUIRED &&
        approvalTarget.request !== null &&
        approvalTarget.request.allowed_credential_ids.length === 2,
      "enrolled machine: enroll_begin is answered presence_required beside a request naming both credentials",
      approvalTarget,
    );
    if (!approvalTarget.request) throw new Error("cannot continue without a presence request");
    const approval = await assertCredential(a.page, approvalTarget.request.challenge, {
      id: aId,
      transport: "internal",
    });
    const approved = await send(a.page, {
      type: "webauthn_presence_assert",
      nonce: approvalTarget.request.nonce,
      ...approval,
    });
    check(approved.ok, "an assertion from the enrolled credential approves the request", approved);
    // The approval is held for the next enroll_begin, which consumes it (the options exclude A's credential,
    // so the panel would create a second one); here it is consumed and left unfinished so the next request
    // needs presence again.
    const consumed = await send(a.page, { type: "webauthn_enroll_begin" });
    check(
      consumed.ok &&
        (consumed.options as EnrollOptions).exclude_credential_ids.length === 1 &&
        (consumed.options as EnrollOptions).exclude_credential_ids[0] === aId,
      "the next enroll_begin consumes the approval and answers options excluding A's credential",
      consumed,
    );

    // 5: the approval assertion, offered again for a fresh request, is a replay.
    const replayTarget = await openLaterEnrollment(a.page);
    if (!replayTarget.request) throw new Error("no presence request for the replay");
    const replayed = await send(a.page, {
      type: "webauthn_presence_assert",
      nonce: replayTarget.request.nonce,
      ...approval,
    });
    check(
      !replayed.ok && replayed.error === "sign_count_not_increased",
      "a replayed assertion is refused: the counter already moved past it",
      replayed,
    );

    // 6: a credential the host never enrolled. A second, roaming authenticator mints it: Chrome refuses to
    // register on an authenticator that already holds an excluded credential (InvalidStateError).
    await addAuthenticator(a.cdp, "usb");
    const strayChallenge = Buffer.from("stray enrollment, never shown to the host").toString(
      "base64url",
    );
    const stray = await createCredential(a.page, {
      challenge: strayChallenge,
      nonce: "unused",
      user_id: Buffer.from("stray").toString("base64url"),
      user_name: "stray",
      exclude_credential_ids: [aId],
    });
    const unenrolledTarget = await openLaterEnrollment(a.page);
    if (!unenrolledTarget.request) throw new Error("no presence request for the stray credential");
    const strayAssertion = await assertCredential(a.page, unenrolledTarget.request.challenge, {
      id: stray.rawId,
      transport: "usb",
    });
    const unenrolled = await send(a.page, {
      type: "webauthn_presence_assert",
      nonce: unenrolledTarget.request.nonce,
      ...strayAssertion,
    });
    check(
      !unenrolled.ok && unenrolled.error === "credential_not_enrolled",
      "an assertion from a credential the host never enrolled is refused",
      unenrolled,
    );

    // 7: the right credential and nonce over the wrong challenge.
    const mismatchTarget = await openLaterEnrollment(a.page);
    if (!mismatchTarget.request) throw new Error("no presence request for the challenge mismatch");
    const otherChallenge = Buffer.from("some other statement").toString("base64url");
    const overOther = await assertCredential(a.page, otherChallenge, {
      id: aId,
      transport: "internal",
    });
    const mismatch = await send(a.page, {
      type: "webauthn_presence_assert",
      nonce: mismatchTarget.request.nonce,
      ...overOther,
    });
    check(
      !mismatch.ok && mismatch.error === "challenge_mismatch",
      "an assertion over another challenge is refused",
      mismatch,
    );

    // 8: the window may not vouch for a browser that has an enrolled credential.
    const windowTarget = await openLaterEnrollment(a.page);
    if (!windowTarget.request) throw new Error("no presence request for the window answer");
    const confirmed = await send(a.page, {
      type: "webauthn_presence_confirm",
      nonce: windowTarget.request.nonce,
    });
    check(
      !confirmed.ok && confirmed.error === "software_confirmation_not_allowed",
      "the window's confirmation is refused on an enrolled browser (no downgrade)",
      confirmed,
    );

    // 9: the host's trail, under the extension surface.
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
  } catch (e) {
    // What each panel showed when the step gave up: a refusal sentence is the usual answer.
    for (const [i, { page }] of instances.entries()) {
      const text = await page.evaluate(() => document.body.innerText).catch(() => "(page gone)");
      console.error(`--- options page ${i === 0 ? "A" : "B"} at failure ---\n${text}`);
    }
    throw e;
  } finally {
    for (const { browser } of instances) await browser.close().catch(() => {});
    fs.rmSync(work, { recursive: true, force: true });
  }
  finishSuite("presence_exchange_test", Pass, Fail);
}

main().catch((e) => {
  console.error("presence_exchange_test crashed:", e);
  finishSuite("presence_exchange_test", Pass, Fail + 1);
});
