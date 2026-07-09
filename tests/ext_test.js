/**
 * Extension smoke test via puppeteer — launches a REAL Chrome with our
 * extension loaded in a throwaway profile and verifies the extension
 * installs and its service worker boots with the expected APIs.
 *
 * SCOPE (deliberately limited): this only verifies that the extension
 * LOADS. It does NOT verify the native-messaging bridge end-to-end, because
 * Chrome restricts the `nativeMessaging` permission under automated
 * (`--load-extension`) launches — `chrome.runtime.connectNative` is present
 * but the host connection is forbidden without an interactive user load.
 * End-to-end verification is therefore a manual step (see README → Testing).
 *
 * Run:  node tests/ext_test.js
 * Requires: node + puppeteer-core + system Chrome (CHROME_BIN).
 *
 * SETUP: cd tests && npm install puppeteer-core   (uses your system Chrome,
 *        does not download Chromium).
 */

const puppeteer = require("puppeteer-core");
const fs = require("fs");
const path = require("path");
const os = require("os");

const REPO = path.resolve(__dirname, "..");
const EXTENSION_DIR = path.join(REPO, "extension");
const CHROME =
  process.env.CHROME_BIN ||
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

let _pass = 0;
let _fail = 0;
function check(cond, label) {
  if (cond) {
    _pass++;
    console.log("  PASS  " + label);
  } else {
    _fail++;
    console.log("  FAIL  " + label);
  }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  for (const [label, p] of [
    ["extension dir", EXTENSION_DIR],
    ["system Chrome", CHROME],
  ]) {
    if (!fs.existsSync(p)) {
      console.error(`missing ${label}: ${p}`);
      process.exit(2);
    }
  }

  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "bb-ext-"));
  console.log("user-data-dir:", userDataDir);
  console.log("launching Chrome with extension…");

  // CRITICAL: puppeteer's default args include --disable-extensions and
  // --disable-component-extensions-with-background-pages, both of which
  // silently prevent --load-extension from working. They must be excluded
  // here — finding this was the main debugging effort.
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
    ],
    defaultViewport: null,
  });

  try {
    // Find OUR extension's service worker (skip built-in extensions like
    // Hangouts, which also register a background target).
    let sw = null;
    for (let i = 0; i < 30; i++) {
      sw = browser
        .targets()
        .find(
          (t) =>
            t.type() === "service_worker" &&
            t.url().startsWith("chrome-extension://")
        );
      if (sw) break;
      await sleep(500);
    }
    check(!!sw, "extension service worker target exists");
    if (!sw) {
      console.log(
        "  targets:",
        browser.targets().map((t) => t.type() + ":" + t.url().slice(0, 50))
      );
      throw new Error("no service worker — extension did not load");
    }

    const extId = sw.url().match(/chrome-extension:\/\/([a-z]+)\//)[1];
    console.log("extension ID:", extId);
    check(/^[a-p]{32}$/.test(extId), "extension ID is 32 lowercase a-p chars");

    const worker = await sw.worker();
    const alive = await worker.evaluate(
      () => typeof chrome !== "undefined" && typeof chrome.runtime !== "undefined"
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
    check(apis.hasScripting, "chrome.scripting API available");
    check(apis.hasStorage, "chrome.storage API available");
    check(apis.hasDebugger, "chrome.debugger API available");
    check(apis.hasCookies, "chrome.cookies API available");
    // connectNative's availability depends on how the extension was loaded
    // (interactive vs automated). Report it but don't fail the suite on it —
    // under puppeteer it's often undefined even though the manifest is correct.
    console.log(
      `  note: connectNative is ${apis.hasConnectNative} under this load mode ` +
        "(interactive load is the real test)."
    );

    console.log("\n✓ Extension loads and service worker boots with expected APIs.");
    console.log("  Native-messaging bridge requires interactive verification (see README).");
  } finally {
    await browser.close();
    try {
      fs.rmSync(userDataDir, { recursive: true, force: true });
    } catch {}
  }

  console.log(`\n${"=".repeat(50)}\n${_pass} passed, ${_fail} failed`);
  process.exit(_fail > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error("fatal:", e);
  process.exit(1);
});
