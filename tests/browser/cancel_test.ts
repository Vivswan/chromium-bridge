/**
 * The cancel signal through Chrome's real native messaging: a stand-in host (fake_host.ts), registered in
 * the throwaway profile, sends the extension a `cancel` for an id and then a bridge request, and the log of
 * what the extension posts back proves the contract.
 *
 *   cancel { id: 41 }                   -> consumed by the dispatch collaborator, answered with NOTHING
 *   tab_list { id: 42 }                 -> answered, the control that the pipe works: refused by the
 *                                          enrollment gate (the profile is unpaired)
 *
 * Frames are ordered on one port, so the answer to 42 arriving with no answer to 41 before it is the proof;
 * before the collaborator existed the cancel fell through parseBridgeReq and 41 was answered as a malformed
 * bridge request. Only the frame routing is proved here: the enrollment gate refuses every bridge request
 * until the profile is paired, on every platform, so the abort of a RUNNING op is pinned by the vitest suite
 * (tests/background/dispatch-cancel.test.ts).
 *
 * Run:  CHROME_BIN=<Chrome for Testing> bun tests/browser/cancel_test.ts
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { NATIVE_HOST_ID } from "@chromium-bridge/shared/identity.gen";
import puppeteer, { type Browser } from "puppeteer-core";
import { assertIsolatedBrowserOrSkip, extensionDir, finishSuite } from "./browser-safety";

const EXTENSION_DIR = extensionDir();
// The guard (assertIsolatedBrowserOrSkip) verifies CHROME_BIN by --version
// before use; it is only ever an isolated Chrome for Testing here.
const CHROME = process.env.CHROME_BIN ?? "";
// The manifest key pins the extension id; the host manifest authorizes only it.
const PINNED_ID = "mkjjlmjbcljpcfkfadfmhblmmddkdihf";
const FAKE_HOST = path.join(import.meta.dir, "fake_host.ts");

let Pass = 0;
let Fail = 0;
function check(cond: boolean, label: string, detail?: unknown): void {
  if (cond) {
    Pass++;
    console.log(`  PASS  ${label}`);
  } else {
    Fail++;
    console.log(`  FAIL  ${label}`, detail === undefined ? "" : JSON.stringify(detail));
  }
}
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** The frames the fake host has logged so far, oldest first. */
function logged(logFile: string): Record<string, unknown>[] {
  if (!fs.existsSync(logFile)) return [];
  return fs
    .readFileSync(logFile, "utf8")
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

/** Register the fake host in the throwaway profile. Chrome resolves user-level manifests under
 * <user-data-dir>/NativeMessagingHosts on macOS and Linux, so nothing outside the profile is touched. The
 * wrapper exists because a manifest names one executable and Chrome passes it no arguments of ours. */
function registerFakeHost(userDataDir: string, logFile: string): void {
  const wrapper = path.join(userDataDir, "fake-host");
  fs.writeFileSync(wrapper, `#!/bin/sh\nexec "${process.execPath}" "${FAKE_HOST}" "${logFile}"\n`, {
    mode: 0o755,
  });
  const dir = path.join(userDataDir, "NativeMessagingHosts");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, `${NATIVE_HOST_ID}.json`),
    JSON.stringify({
      name: NATIVE_HOST_ID,
      description: "cancel_test stand-in host",
      path: wrapper,
      type: "stdio",
      allowed_origins: [`chrome-extension://${PINNED_ID}/`],
    }),
  );
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
  if (process.platform === "win32") {
    // Host registration is a shared HKCU value there, never profile-scoped; this suite stays off it.
    console.log("SKIP: profile-scoped host manifests exist on macOS and Linux only");
    process.exit(0);
  }

  // Everything after the mkdtemp runs under the one finally, so a failed registration or launch still removes
  // the profile, the wrapper, and the manifest.
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "bb-cancel-"));
  const logFile = path.join(userDataDir, "fake-host.log");
  let browser: Browser | null = null;
  try {
    registerFakeHost(userDataDir, logFile);
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
    // The service worker connects on startup, the fake host plays its script, and the extension's answers
    // land in the log. The answer to 42 is the end of the exchange: wait for it, bounded.
    const deadline = Date.now() + 30000;
    while (Date.now() < deadline && !logged(logFile).some((f) => f.id === 42)) {
      await sleep(250);
    }
    const frames = logged(logFile);
    const answer42 = frames.find((f) => f.id === 42);
    // Answered at all is the control: the verdict is the gate's (refused, since the profile is unpaired).
    check(
      answer42 !== undefined && typeof answer42.ok === "boolean",
      "control: the request the fake host sent after the cancel is answered",
      frames,
    );
    check(
      !frames.some((f) => f.id === 41),
      "the cancel frame is consumed by the extension and never answered",
      frames.filter((f) => f.id === 41),
    );
  } finally {
    await browser?.close().catch(() => {});
    fs.rmSync(userDataDir, { recursive: true, force: true });
  }
  finishSuite("cancel_test", Pass, Fail);
}

main().catch((e) => {
  console.error("cancel_test crashed:", e);
  finishSuite("cancel_test", Pass, Fail + 1);
});
