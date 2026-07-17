/**
 * Extension smoke test via puppeteer - launches a REAL Chrome with our
 * extension loaded in a throwaway profile and verifies the extension
 * installs and its service worker boots with the expected APIs.
 *
 * SCOPE (deliberately limited): this only verifies that the extension
 * LOADS. It does NOT verify the native-messaging bridge end-to-end, because
 * Chrome restricts the `nativeMessaging` permission under automated
 * (`--load-extension`) launches - `chrome.runtime.connectNative` is present
 * but the host connection is forbidden without an interactive user load.
 * End-to-end verification is therefore a manual step (see README → Testing).
 *
 * Run:  bun tests/ext_test.ts
 * Requires: bun + puppeteer-core + system Chrome (CHROME_BIN).
 * Override the loaded extension dir with BB_EXT_DIR.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import puppeteer, { type Target } from "puppeteer-core";
import { assertIsolatedBrowserOrSkip } from "./browser-safety";

const REPO = path.resolve(import.meta.dir, "..");
// The load-unpacked target is the built bundle. Run
// `bun run --cwd extension build` first (run_all.ts / just handle this).
// Override with BB_EXT_DIR to point at a different unpacked extension.
const EXTENSION_DIR = process.env.BB_EXT_DIR || path.join(REPO, "extension", "dist", "chrome-mv3");
// The guard (assertIsolatedBrowserOrSkip) verifies CHROME_BIN by --version
// before use; it is only ever an isolated Chrome for Testing here.
const CHROME = process.env.CHROME_BIN ?? "";

// SAFETY (do not remove): this launches a NON-HEADLESS Chrome with
// --load-extension. On macOS, launching your normal Google Chrome while it is
// running forwards the flags to the EXISTING instance (ignoring --user-data-dir),
// so the test captures - and on cleanup CLOSES - your real browser session.
// (This actually happened.) Refuse unless CHROME_BIN points at an ISOLATED
// browser (Chrome for Testing / Chromium) that is NOT your daily Chrome.
// SAFETY: see tests/browser-safety.ts - the shared guard runs CHROME_BIN
// --version and refuses anything that is not an isolated Chrome for Testing.

let Pass = 0;
let Fail = 0;
function check(cond: boolean, label: string): void {
  if (cond) {
    Pass++;
    console.log(`  PASS  ${label}`);
  } else {
    Fail++;
    console.log(`  FAIL  ${label}`);
  }
}
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

async function main(): Promise<void> {
  assertIsolatedBrowserOrSkip();
  for (const [label, p] of [
    ["extension dir", EXTENSION_DIR],
    ["system Chrome", CHROME],
  ] as const) {
    if (!fs.existsSync(p)) {
      console.error(`missing ${label}: ${p}`);
      process.exit(2);
    }
  }

  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "bb-ext-"));
  console.log("user-data-dir:", userDataDir);
  console.log("launching Chrome with extension...");

  // CRITICAL: puppeteer's default args include --disable-extensions and
  // --disable-component-extensions-with-background-pages, both of which
  // silently prevent --load-extension from working. They must be excluded
  // here - finding this was the main debugging effort.
  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: false, // MV3 SW needs a non-headless browser to run reliably
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
      // Required for Chrome to launch on CI runners (unprivileged/containerized);
      // harmless for this throwaway-profile test locally.
      "--no-sandbox",
      "--disable-dev-shm-usage",
    ],
    defaultViewport: null,
  });

  try {
    // Find OUR extension's service worker. Chrome for Testing ships built-in
    // component extensions whose service workers ALSO match a naive
    // type === "service_worker" filter (and would give a wrong extension ID
    // and wrong permission readout), so select by our distinctive
    // `nativeMessaging` permission.
    let sw: Target | undefined;
    for (let i = 0; i < 30 && !sw; i++) {
      for (const t of browser.targets().filter((x) => x.type() === "service_worker")) {
        const w = await t.worker().catch(() => null);
        if (!w) continue;
        const perms = (await w
          .evaluate(() => chrome.runtime.getManifest().permissions ?? [])
          .catch(() => [])) as string[];
        if (perms.includes("nativeMessaging")) {
          sw = t;
          break;
        }
      }
      if (!sw) await sleep(500);
    }
    check(!!sw, "extension service worker target exists");
    if (!sw) {
      console.log(
        "  targets:",
        browser.targets().map((t) => `${t.type()}:${t.url().slice(0, 50)}`),
      );
      throw new Error("no service worker - extension did not load");
    }

    const idMatch = sw.url().match(/chrome-extension:\/\/([a-z]+)\//);
    const extId = idMatch?.[1] ?? "";
    console.log("extension ID:", extId);
    // The manifest key pins the ID even under --load-extension, so assert the
    // exact pinned value (the native host's allowed_origins depends on it).
    check(extId === "mkjjlmjbcljpcfkfadfmhblmmddkdihf", "extension loads at the pinned ID");

    const worker = await sw.worker();
    if (!worker) throw new Error("service worker target has no worker");
    const alive = await worker.evaluate(
      () => typeof chrome !== "undefined" && typeof chrome.runtime !== "undefined",
    );
    check(alive, "service worker is alive (has chrome.runtime)");

    // Verify the manifest's permissions actually granted their APIs. This is
    // the value of the smoke test: a manifest typo or a permission that
    // Chrome silently drops would show up here.
    const apis = await worker.evaluate(() => ({
      hasTabs: typeof chrome.tabs !== "undefined",
      hasScripting: typeof chrome.scripting !== "undefined",
      hasStorage: typeof chrome.storage !== "undefined",
      hasDebugger: typeof chrome.debugger !== "undefined",
      hasCookies: typeof chrome.cookies !== "undefined",
      hasConnectNative: typeof chrome.runtime.connectNative,
    }));
    check(apis.hasTabs, "chrome.tabs API available");
    check(apis.hasStorage, "chrome.storage API available");
    check(apis.hasScripting, "chrome.scripting API available");
    // connectNative is present but the host connection itself is forbidden
    // under automated --load-extension; that leg is the manual/integration
    // step (see README).
    console.log(
      `  debugger=${apis.hasDebugger} cookies=${apis.hasCookies} ` +
        `connectNative=${apis.hasConnectNative}`,
    );

    console.log("\n✓ Extension loads and service worker boots with expected APIs.");
    console.log("  Native-messaging bridge requires interactive verification (see README).");
  } finally {
    await browser.close();
    try {
      fs.rmSync(userDataDir, { recursive: true, force: true });
    } catch {}
  }

  console.log(`\n${"=".repeat(50)}\n${Pass} passed, ${Fail} failed`);
  process.exit(Fail > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error("fatal:", e);
  process.exit(1);
});
