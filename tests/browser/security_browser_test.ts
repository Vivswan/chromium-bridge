/**
 * Security browser proofs (ADR-0027 / #32) - the runtime verification that the
 * Vitest + fakeBrowser suite cannot do, run against an ISOLATED Chrome for
 * Testing. It proves, in a real browser:
 *
 *   1. The pinned manifest key is honored: our extension loads at the pinned
 *      extension ID (the native host's allowed_origins depends on this).
 *   2. #32, our side: our real storage.local ACCEPTS the same TRUSTED_CONTEXTS
 *      restriction our production startup applies, and a trusted context reads
 *      a seeded trust key. This shows the production API path works on our
 *      storage; it does NOT observe that startup already applied it (Chrome has
 *      no getAccessLevel, and our extension cannot grant itself host access to
 *      inject a content script under automation) - the production INVOCATION is
 *      asserted by src/apps/extension/tests/entrypoints/background.test.ts, and the
 *      function + gate behavior by trusted-storage.test.ts and the #32 gate
 *      tests in enrollment.test.ts.
 *   3. #32, the mechanism: after setAccessLevel(TRUSTED_CONTEXTS), a
 *      content-script-world read of a seeded key is BLOCKED by Chrome, proven
 *      with a BEFORE/AFTER control - the SAME injected read succeeds before the
 *      restriction and fails after, so the block is the access level and not a
 *      missing permission. Proven with a minimal <all_urls> helper fixture,
 *      since our own extension holds no host permission to inject a content
 *      script under automation. Combined with proof 2 and the compile-time fact
 *      that our content bundle contains no storage access at all, a content
 *      script cannot read the trust state.
 *   4. Off-DOM confirmation, sender gate: confirm_ready / confirm_resolve sent
 *      from a NON-confirm extension page are refused (only /confirm.html may
 *      answer), so no page-reachable context can approve a confirmation.
 *   5. Off-DOM confirmation, not web-accessible: a web page cannot fetch
 *      chrome-extension://<id>/confirm.html (it is not a web-accessible
 *      resource), so the guarded page cannot read the confirmation surface.
 *   6. i18n: the options page renders localized across en / zh_CN / zh_TW, and
 *      the document lang attribute follows the chosen locale.
 *
 * SAFETY: this launches a NON-HEADLESS Chrome with --load-extension. Driving
 * your daily Chrome/Brave this way can capture and close your real session, so
 * it refuses unless CHROME_BIN points at an isolated Chrome for Testing /
 * Chromium (see tests/README.md). Native messaging is NOT exercised (forbidden
 * under automated --load-extension), matching ext_test.ts.
 *
 * Run:  CHROME_BIN=/path/to/chrome-for-testing bun tests/browser/security_browser_test.ts
 * Requires: bun + puppeteer-core + isolated Chrome (CHROME_BIN). Override the
 * loaded extension dir with BB_EXT_DIR.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import puppeteer, { type Browser, type Target } from "puppeteer-core";
import { assertIsolatedBrowserOrSkip } from "./browser-safety";

const REPO = path.resolve(import.meta.dir, "../..");
const EXTENSION_DIR =
  process.env.BB_EXT_DIR || path.join(REPO, "src", "apps", "extension", "dist", "chrome-mv3");
const HELPER_DIR = path.join(REPO, "tests", "fixtures", "access-level-probe");
// The guard (assertIsolatedBrowserOrSkip) verifies CHROME_BIN by --version
// before this is used; it is only ever an isolated Chrome for Testing here.
const CHROME = process.env.CHROME_BIN ?? "";
const PINNED_ID = "mkjjlmjbcljpcfkfadfmhblmmddkdihf";
const LOCALES_DIR = path.join(EXTENSION_DIR, "_locales");

// SAFETY: this launches a non-headless Chrome with --load-extension; a real
// browser could capture and close the user's session. The shared guard runs
// CHROME_BIN --version and refuses anything that does not identify as an
// isolated Chrome for Testing (see tests/browser/browser-safety.ts).

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

type Worker = NonNullable<Awaited<ReturnType<Target["worker"]>>>;
interface Sw {
  worker: Worker;
  id: string;
}

/** Select a service worker by a distinctive manifest permission. Chrome for
 * Testing ships built-in component extensions whose service workers also match
 * a naive `type === "service_worker"` filter, so pick by permission. */
async function findSw(browser: Browser, has: (perms: string[]) => boolean): Promise<Sw> {
  for (let i = 0; i < 40; i++) {
    for (const t of browser.targets().filter((x) => x.type() === "service_worker")) {
      const w = await t.worker().catch(() => null);
      if (!w) continue;
      const perms = (await w
        .evaluate(() => chrome.runtime.getManifest().permissions ?? [])
        .catch(() => [])) as string[];
      if (has(perms)) {
        const id = t.url().match(/chrome-extension:\/\/([a-p]+)\//)?.[1] ?? "";
        return { worker: w, id };
      }
    }
    await sleep(400);
  }
  throw new Error("service worker not found");
}

/** Select a service worker by its extension's manifest name (unique per
 * fixture), so the helper cannot be confused with any other extension. */
async function findSwByName(browser: Browser, name: string): Promise<Sw> {
  return findSwBy(browser, async (w) => {
    const n = (await w.evaluate(() => chrome.runtime.getManifest().name).catch(() => "")) as string;
    return n === name;
  });
}

async function findSwBy(browser: Browser, match: (w: Worker) => Promise<boolean>): Promise<Sw> {
  for (let i = 0; i < 40; i++) {
    for (const t of browser.targets().filter((x) => x.type() === "service_worker")) {
      const w = await t.worker().catch(() => null);
      if (!w) continue;
      if (await match(w).catch(() => false)) {
        const id = t.url().match(/chrome-extension:\/\/([a-p]+)\//)?.[1] ?? "";
        return { worker: w, id };
      }
    }
    await sleep(400);
  }
  throw new Error("service worker not found");
}

let lastUserDataDir = "";
function launch(extDirs: string[]): Promise<Browser> {
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "bb-sec-"));
  lastUserDataDir = userDataDir;
  return puppeteer.launch({
    executablePath: CHROME,
    headless: false,
    userDataDir,
    ignoreDefaultArgs: [
      "--disable-extensions",
      "--enable-automation",
      "--disable-component-extensions-with-background-pages",
    ],
    args: [
      `--disable-extensions-except=${extDirs.join(",")}`,
      `--load-extension=${extDirs.join(",")}`,
      "--no-first-run",
      "--no-default-browser-check",
      "--no-sandbox",
      "--disable-dev-shm-usage",
    ],
    defaultViewport: null,
  });
}

/** Expected localized options title, read from the built _locales so the test
 * cannot drift from the shipped strings. */
function expectedTitle(locale: string): string {
  const msgs = JSON.parse(
    fs.readFileSync(path.join(LOCALES_DIR, locale, "messages.json"), "utf8"),
  ) as Record<string, { message: string }>;
  const entry = msgs.options_title;
  if (!entry) throw new Error(`options_title missing from ${locale} messages`);
  return entry.message;
}

async function main(): Promise<void> {
  assertIsolatedBrowserOrSkip();

  // A local web origin for the content-script-injection and web-fetch proofs -
  // deterministic and offline (no dependency on a public site).
  const server = Bun.serve({
    port: 0,
    fetch: () =>
      new Response("<!doctype html><title>bb-fixture</title><body>ok", {
        headers: { "content-type": "text/html" },
      }),
  });
  const WEB_URL = `http://127.0.0.1:${server.port}/`;

  let browser: Browser | null = null;
  try {
    for (const [label, p] of [
      ["extension dir", EXTENSION_DIR],
      ["helper fixture", HELPER_DIR],
      ["Chrome", CHROME],
    ] as const) {
      if (!fs.existsSync(p)) {
        console.error(`missing ${label}: ${p}`);
        process.exit(2);
      }
    }

    // ---- Launch 1: our extension + the helper fixture ----------------------
    browser = await launch([EXTENSION_DIR, HELPER_DIR]);
    const ours = await findSw(browser, (p) => p.includes("nativeMessaging"));

    // Proof 1: pinned key honored.
    check(ours.id === PINNED_ID, "extension loads at the pinned ID (manifest key honored)", {
      got: ours.id,
      want: PINNED_ID,
    });

    // Proof 2 (#32, our side): our real storage.local ACCEPTS the same
    // TRUSTED_CONTEXTS restriction our production startup applies
    // (hardenStorageAccess in lib/background/trusted-storage.ts), and a trusted
    // context reads a seeded trust key. NOTE what this does and does NOT show:
    // it shows the API path our production uses works on OUR storage, but it
    // cannot observe that the startup ALREADY applied it - Chrome has no
    // getAccessLevel, and our extension holds no host permission to inject a
    // content script under automation (the click-to-grant prompt is not
    // auto-acceptable). The production INVOCATION (background.ts calls
    // hardenStorageAccess at startup) is asserted by an entrypoint-wiring unit
    // test: src/apps/extension/tests/entrypoints/background.test.ts. The function's
    // behavior and the gate's fail-closed-until-hardened posture are covered by
    // trusted-storage.test.ts and the #32 gate tests in enrollment.test.ts. The
    // BROWSER-enforced blocking our extension relies on is proven in Proof 3.
    const our32 = (await ours.worker.evaluate(async () => {
      const out: Record<string, unknown> = {};
      try {
        await chrome.storage.local.set({ enclaveCompromised: { reason: "SENTINEL", at: 1 } });
        await chrome.storage.local.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
        out.setAccessOk = true;
      } catch (e) {
        out.setAccessErr = String(e);
      }
      out.trustedRead = (await chrome.storage.local.get("enclaveCompromised")).enclaveCompromised;
      return out;
    })) as { setAccessOk?: boolean; setAccessErr?: string; trustedRead?: { reason?: string } };
    check(
      our32.setAccessOk === true,
      "our storage.local accepts the TRUSTED_CONTEXTS restriction (the production path)",
      our32,
    );
    check(
      our32.trustedRead?.reason === "SENTINEL",
      "a trusted context (our SW) reads the seeded trust key",
      our32.trustedRead,
    );

    // Proof 3 (#32, the mechanism): the helper fixture proves Chrome blocks a
    // content-script read after TRUSTED_CONTEXTS.
    const helper = await findSwByName(browser, "Access-level probe (test fixture)");
    const webPage = await browser.newPage();
    await webPage.goto(WEB_URL, { waitUntil: "domcontentloaded", timeout: 20000 }).catch(() => {});
    await sleep(500);
    const webTabId = (await helper.worker.evaluate(async (url) => {
      const t = (await chrome.tabs.query({})).find((x) => x.url === url);
      return t?.id;
    }, WEB_URL)) as number | undefined;
    check(typeof webTabId === "number", "opened a web tab to inject a content-script probe into");
    const mech = (await helper.worker.evaluate(
      (tid) =>
        (globalThis as unknown as { __runProbe: (t: number) => Promise<unknown> }).__runProbe(
          tid as number,
        ),
      webTabId,
    )) as {
      swRead?: string;
      before?: { ok: boolean; value?: string | null };
      after?: { ok: boolean; value?: string | null; err?: string };
    };
    // Control: the SAME content-script read succeeds BEFORE the restriction, so
    // the "after" failure is the access level and not a missing host permission
    // or an unrelated injection error.
    check(
      mech.before?.ok === true && mech.before?.value === "SENTINEL_TRUST_VALUE",
      "mechanism control: a content-script read SUCCEEDS before setAccessLevel",
      mech.before,
    );
    check(
      mech.swRead === "SENTINEL_TRUST_VALUE",
      "mechanism: a trusted context reads the seeded key after restricting",
      mech.swRead,
    );
    check(
      mech.after?.ok === false && !mech.after?.value,
      "mechanism: the SAME content-script read is BLOCKED after setAccessLevel(TRUSTED_CONTEXTS)",
      mech.after,
    );

    // Proof 5 (off-DOM confirm, not web-accessible): the guarded web page cannot
    // fetch confirm.html. Control: the SAME page CAN fetch a same-origin web
    // resource, so a blocked confirm.html fetch is the not-web-accessible
    // policy and not a broken network. Assert the page is really a web origin.
    const webAccess = (await webPage.evaluate(async (extId) => {
      const origin = location.origin;
      const control = await fetch(location.href)
        .then((r) => r.ok)
        .catch(() => false);
      const confirm = await fetch(`chrome-extension://${extId}/confirm.html`)
        .then((r) => ({ reached: true, ok: r.ok, status: r.status }))
        .catch((e) => ({ reached: false, err: String(e).slice(0, 80) }));
      return { origin, control, confirm };
    }, ours.id)) as {
      origin: string;
      control: boolean;
      confirm: { reached: boolean; ok?: boolean; err?: string };
    };
    check(
      webAccess.origin.startsWith("http://127.0.0.1") && webAccess.control === true,
      "control: the guarded page is a real web origin that CAN fetch its own resources",
      webAccess,
    );
    check(
      webAccess.confirm.reached === false || webAccess.confirm.ok === false,
      "a web page cannot fetch the confirmation window (not web-accessible)",
      webAccess.confirm,
    );

    // Proof: a plain web page cannot even REACH the runtime router (no
    // externally_connectable), so the mediated path to the trust state
    // (add_allow/get_enrollment/...) is unreachable from page context. A
    // content-script context DOES have runtime.sendMessage, but the router
    // refuses a non-extension-page sender - covered by the unit test
    // src/apps/extension/tests/background/messages.test.ts.
    const pageRuntime = (await webPage.evaluate(() => {
      const c = (globalThis as unknown as { chrome?: { runtime?: { sendMessage?: unknown } } })
        .chrome;
      return typeof c?.runtime?.sendMessage;
    })) as string;
    check(
      pageRuntime === "undefined",
      "a web page cannot message the extension at all (no chrome.runtime.sendMessage)",
      { pageRuntime },
    );

    // Open our options page (a non-confirm extension page) at the pinned ID.
    const optUrl = `chrome-extension://${ours.id}/options.html`;
    const optPage = await browser.newPage();
    await optPage.goto(optUrl, { waitUntil: "load", timeout: 15000 });
    await sleep(1200);

    // Proof 4 (off-DOM confirm, sender gate): confirm_* from a non-confirm
    // extension page is refused - including the deny-and-kill panic exit,
    // which must not hand any other page a side door that answers a pending
    // confirmation.
    const gate = (await optPage.evaluate(async () => {
      const ready = await chrome.runtime.sendMessage({ type: "confirm_ready", id: "x" });
      const resolve = await chrome.runtime.sendMessage({
        type: "confirm_resolve",
        id: "x",
        approved: true,
      });
      const denyKill = await chrome.runtime.sendMessage({ type: "confirm_deny_kill" });
      return { ready, resolve, denyKill };
    })) as {
      ready?: { ok?: boolean; error?: string };
      resolve?: { ok?: boolean; error?: string };
      denyKill?: { ok?: boolean; error?: string };
    };
    check(
      gate.ready?.ok === false && gate.resolve?.ok === false && gate.denyKill?.ok === false,
      "confirm_ready / confirm_resolve / confirm_deny_kill are refused from a non-confirm extension page",
      gate,
    );

    // Proof 6 (i18n): the options page renders localized across all three
    // locales. Set uiLanguage, reload, assert the title and lang attribute.
    for (const locale of ["en", "zh_CN", "zh_TW"] as const) {
      await ours.worker.evaluate(async (l) => {
        await chrome.storage.local.set({ uiLanguage: l });
      }, locale);
      await optPage.reload({ waitUntil: "load" });
      await sleep(1000);
      const rendered = (await optPage.evaluate(() => ({
        h1: document.querySelector("h1")?.textContent?.trim(),
        lang: document.documentElement.lang,
        mounted: (document.getElementById("root")?.childElementCount ?? 0) > 0,
      }))) as { h1?: string; lang?: string; mounted?: boolean };
      const want = expectedTitle(locale);
      const wantLang = locale.replace("_", "-");
      check(
        rendered.mounted === true && rendered.h1 === want && rendered.lang === wantLang,
        `options page renders localized in ${locale}`,
        { got: rendered, want, wantLang },
      );
    }
  } finally {
    if (browser) await browser.close().catch(() => {});
    server.stop(true);
    if (lastUserDataDir) {
      try {
        fs.rmSync(lastUserDataDir, { recursive: true, force: true });
      } catch {
        // best-effort cleanup
      }
    }
  }

  console.log(`\n${"=".repeat(50)}\n${Pass} passed, ${Fail} failed`);
  process.exit(Fail > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error("fatal:", e);
  process.exit(1);
});
