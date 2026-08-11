/**
 * Real end-to-end integration test - the seam e2e.py deliberately mocks.
 *
 * Exercises the FULL chain with nothing stubbed: MCP client (this) -> real MCP
 * server (release binary) -> localhost TCP bridge -> real native host (release
 * binary, spawned by Chrome) -> real extension (background.js) ->
 * chrome.tabs.query -> back. If tab_list returns the isolated profile's own
 * fixture tab, the whole native-messaging path e2e.py can't reach is proven.
 *
 * Isolation matters: a raw Chrome launch merges into an already-running Chrome
 * (and would query your real session). puppeteer launches a truly isolated
 * instance. If the manifest has a pinned public key, the test derives the
 * pinned extension id; otherwise it derives the id from the throwaway path.
 *
 * OPT-IN, Windows + Chrome for Testing (or Chromium). Pops a non-headless
 * window. macOS is SKIPPED since ADR-0032 phase 5: enrollment is
 * unconditionally required there and needs an interactive Touch ID pairing a
 * throwaway profile cannot perform (the macOS host-manifest plumbing below
 * is kept for the day a pairing harness exists). On Windows the HKCU
 * registry value is backed up and restored. Not part of the default suite or
 * CI.
 *
 * Run:  BB_REAL_E2E=1 node tests/browser/integration_e2e.ts
 */

import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath, pathToFileURL } from "node:url";
// The narrow subpath (not the barrel): the barrel's extensionless
// re-exports do not resolve under Node ESM, and this file documents Node as
// a supported runner. protocol.gen.ts is a leaf module with no imports, so
// Node's type stripping loads it as-is.
import {
  MCP_META_CLIENT_CAPABILITIES,
  MCP_META_PROTOCOL_VERSION,
  MCP_PROTOCOL_VERSION,
} from "@chromium-bridge/shared/protocol.gen";
import puppeteer from "puppeteer-core";
import { assertIsolatedBrowserOrSkip } from "./browser-safety";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "../..");
const IS_WINDOWS = process.platform === "win32";
const BIN = path.join(REPO, "target", "release", `chromium-bridge${IS_WINDOWS ? ".exe" : ""}`);
const DIST = path.join(REPO, "build", "extension");
// The guard (assertIsolatedBrowserOrSkip) verifies CHROME_BIN by --version
// before use; it is only ever an isolated Chrome for Testing here.
const CHROME = process.env.CHROME_BIN ?? "";
const HOST_NAME = "com.vivswan.chromium_bridge.host";
const REG_KEY = `HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\${HOST_NAME}`;
const LOCK = IS_WINDOWS
  ? path.join(
      process.env.LOCALAPPDATA || path.join(os.homedir(), "AppData/Local"),
      "chromium-bridge/run.lock",
    )
  : path.join(os.homedir(), "Library/Application Support/chromium-bridge/run.lock");
const FIXTURE = pathToFileURL(path.join(REPO, "tests", "fixtures", "page.html")).href;

// ── preflight (opt-in) ─────────────────────────────────────────────────────
if (process.env.BB_REAL_E2E !== "1") {
  console.log("SKIP: set BB_REAL_E2E=1 to run the real Chrome integration test.");
  process.exit(0);
}
if (process.platform !== "darwin" && !IS_WINDOWS) {
  console.log("SKIP: real integration test runs on Windows only (macOS is skipped below).");
  process.exit(0);
}
if (process.platform === "darwin") {
  // ADR-0032 Phase 5 retired the requireEnrollment opt-out this suite used
  // to write into the throwaway profile: enrollment is unconditionally
  // required on macOS, and satisfying it takes a real pairing ceremony
  // (interactive Touch ID) a throwaway profile cannot perform - the bridge
  // would refuse tab_list at the enrollment gate. Windows keeps working
  // because the browser's own platform probe reports no Secure Enclave
  // there, so enrollment is unavailable rather than unsatisfied.
  console.log(
    "SKIP: on macOS the enrollment gate is unconditional since ADR-0032 phase 5 and needs " +
      "an interactive Touch ID pairing this throwaway profile cannot perform; run the real " +
      "e2e on Windows (see tests/README.md).",
  );
  process.exit(0);
}
// SAFETY (do not remove): this launches a NON-HEADLESS Chrome with
// --load-extension; a real browser could capture and then CLOSE your session.
// The shared guard runs CHROME_BIN --version and refuses anything that does not
// identify as an isolated Chrome for Testing (see tests/browser/browser-safety.ts).
assertIsolatedBrowserOrSkip();
for (const [label, p] of [
  ["release binary", BIN],
  ["extension dist", DIST],
  ["Chrome", CHROME],
] as const) {
  if (!fs.existsSync(p)) {
    console.log(`SKIP: missing ${label}: ${p}`);
    process.exit(0);
  }
}

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

/** Chrome derives an extension id from its public key when pinned, or from the
 * unpacked extension's absolute path otherwise. */
function extIdFromPath(p: string): string {
  const manifest = JSON.parse(fs.readFileSync(path.join(p, "manifest.json"), "utf8"));
  if (typeof manifest.key === "string") {
    const h = createHash("sha256").update(Buffer.from(manifest.key, "base64")).digest("hex");
    return [...h.slice(0, 32)].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
  }
  const h = createHash("sha256").update(p).digest("hex");
  return [...h.slice(0, 32)].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
}

function readWindowsRegistration(): string | null {
  try {
    const out = execFileSync("reg.exe", ["query", REG_KEY, "/ve"], { encoding: "utf8" });
    return out.match(/REG_SZ\s+(.+)\r?$/m)?.[1]?.trim() || null;
  } catch {
    return null;
  }
}

function writeWindowsRegistration(manifestPath: string): void {
  execFileSync("reg.exe", ["add", REG_KEY, "/ve", "/t", "REG_SZ", "/d", manifestPath, "/f"], {
    stdio: "ignore",
  });
}

function removeWindowsRegistration(): void {
  try {
    execFileSync("reg.exe", ["delete", REG_KEY, "/f"], { stdio: "ignore" });
  } catch {}
}

async function main(): Promise<void> {
  // Use a throwaway copy/profile so the test never operates on the real session.
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "bb-e2e-"));
  fs.cpSync(DIST, path.join(work, "ext"), { recursive: true });
  const extDir = fs.realpathSync(path.join(work, "ext"));
  const extId = extIdFromPath(extDir);
  console.log("[e2e] extension id:", extId);

  let hostPath = BIN;
  if (!IS_WINDOWS) {
    const wrapper = path.join(work, "run-host.sh");
    fs.writeFileSync(wrapper, `#!/bin/sh\nexec "${BIN}" --native-host\n`);
    fs.chmodSync(wrapper, 0o755);
    hostPath = wrapper;
  }

  // Back up any existing host registration so a real install is untouched.
  // (Windows only: the HKCU registry value is shared by every Chrome instance
  // of this Windows account. On macOS the manifest lives inside the throwaway
  // profile, so there is nothing to back up.)
  let backup: string | null = null;
  if (IS_WINDOWS) {
    backup = readWindowsRegistration();
  }
  try {
    fs.rmSync(LOCK);
  } catch {}

  const mcp = spawn(BIN, [], { stdio: ["pipe", "pipe", "pipe"] });
  let connected = false;
  mcp.stderr.on("data", (chunk: Buffer) => {
    // The session log line carries the browser label, e.g.
    // "native host 'default' connected and authenticated (generation 1)".
    if (chunk.toString("utf8").includes("connected and authenticated")) {
      connected = true;
    }
  });

  const outputLines = createInterface({ input: mcp.stdout });
  const queuedLines: string[] = [];
  const lineWaiters: Array<(line: string) => void> = [];
  outputLines.on("line", (line) => {
    const waiter = lineWaiters.shift();
    if (waiter) waiter(line);
    else queuedLines.push(line);
  });
  async function recv(): Promise<any> {
    const line =
      queuedLines.shift() || (await new Promise<string>((resolve) => lineWaiters.push(resolve)));
    return JSON.parse(line);
  }
  function send(obj: unknown): void {
    mcp.stdin.write(`${JSON.stringify(obj)}\n`);
  }

  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "bb-e2e-profile-"));
  let browser: Awaited<ReturnType<typeof puppeteer.launch>> | null = null;
  try {
    for (let i = 0; i < 100; i++) {
      if (fs.existsSync(LOCK)) break;
      await sleep(50);
    }
    check(fs.existsSync(LOCK), "MCP server wrote the lock file");

    // Host manifest authorizes ONLY our throwaway extension id. Written before
    // launch so connectNative succeeds on the first try. On macOS the manifest
    // goes inside the throwaway profile: Chrome for Testing and Chromium
    // resolve user-level manifests relative to --user-data-dir, so this works
    // and never touches a real registration (see tests/README.md).
    const testManifest = IS_WINDOWS
      ? path.join(work, `${HOST_NAME}.json`)
      : path.join(profile, "NativeMessagingHosts", `${HOST_NAME}.json`);
    if (!IS_WINDOWS) fs.mkdirSync(path.dirname(testManifest), { recursive: true });
    fs.writeFileSync(
      testManifest,
      JSON.stringify({
        name: HOST_NAME,
        description: "chromium-bridge integration test",
        path: hostPath,
        type: "stdio",
        allowed_origins: [`chrome-extension://${extId}/`],
      }),
    );
    if (IS_WINDOWS) writeWindowsRegistration(testManifest);

    // puppeteer launches a TRULY isolated instance (unlike a raw subprocess).
    browser = await puppeteer.launch({
      executablePath: CHROME,
      headless: false,
      dumpio: process.env.BB_REAL_E2E_DEBUG === "1",
      userDataDir: profile,
      ignoreDefaultArgs: [
        "--disable-extensions",
        "--enable-automation",
        "--disable-component-extensions-with-background-pages",
      ],
      args: [
        `--disable-extensions-except=${extDir}`,
        `--load-extension=${extDir}`,
        "--no-first-run",
        "--no-default-browser-check",
      ],
      defaultViewport: null,
    });
    const page = await browser.newPage();
    await page.goto(FIXTURE).catch(() => {});
    await sleep(1000);

    const expectedWorkerUrl = `chrome-extension://${extId}/background.js`;
    const extensionLoaded = browser.targets().some((target) => target.url() === expectedWorkerUrl);
    if (!extensionLoaded) {
      throw new Error(
        `test extension did not load (expected ${expectedWorkerUrl}). ` +
          "Official Google Chrome 137+ ignores --load-extension; point CHROME_BIN " +
          "to Chrome for Testing or Chromium.",
      );
    }

    if (process.env.BB_REAL_E2E_DEBUG === "1") {
      console.log(
        "[e2e] Chrome targets:",
        browser.targets().map((target) => `${target.type()} ${target.url()}`),
      );
    }

    // The enrollment gate (ADR-0021) refuses bridge ops on macOS until a
    // host key is paired and pinned; the requireEnrollment opt-out this
    // suite once wrote was retired with ADR-0032 Phase 5, which is why the
    // preflight above skips macOS outright. Here (Windows) the browser's
    // own platform probe reports no Secure Enclave, enrollment is
    // unavailable rather than unsatisfied, and the gate does not block.
    const workerTarget = browser.targets().find((target) => target.url() === expectedWorkerUrl);
    const worker = await workerTarget!.worker();
    if (!worker) throw new Error("could not attach to the extension service worker");

    // Modern stateless MCP (2026-07-28): there is no initialize handshake.
    // Every request - the opener included - carries the generated version
    // and client-capabilities keys in params._meta (rmcp requires both; a
    // bare probe has no served form and would drop the connection).
    const meta = {
      [MCP_META_PROTOCOL_VERSION]: MCP_PROTOCOL_VERSION,
      [MCP_META_CLIENT_CAPABILITIES]: {},
    };
    send({ jsonrpc: "2.0", id: 1, method: "server/discover", params: { _meta: meta } });
    const discover = await recv();
    check(
      discover.result?.resultType === "complete" &&
        Array.isArray(discover.result?.supportedVersions) &&
        discover.result.supportedVersions.includes(MCP_PROTOCOL_VERSION),
      "server/discover advertises the generated protocol version",
    );

    for (let i = 0; i < 300; i++) {
      if (connected) break;
      await sleep(100);
    }
    check(connected, "real extension connected via native host to the MCP server");

    send({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: "tab_list",
        arguments: {},
        _meta: meta,
      },
    });
    const r = await recv();
    if (r.result?.isError === true) {
      check(false, `tab_list failed: ${r.result.content?.[0]?.text || "unknown error"}`);
      throw new Error("tab_list failed through the real native-messaging chain");
    }
    const tabs = JSON.parse(r.result.content[0].text);
    // The real proof: structured chrome.tabs data crossed the entire chain.
    const first = Array.isArray(tabs) && tabs.length >= 1 ? tabs[0] : undefined;
    check(
      !!first && typeof first.id === "number" && typeof first.url === "string",
      "tab_list returned structured real chrome.tabs data (full round-trip works)",
    );
    check(r.result.isError === false, "tool call not an error");
    check(
      r.result.resultType === "complete" && r.result._meta === undefined,
      "modern tool result carries resultType (serverInfo _meta rides only discover)",
    );

    // Bonus hermeticity check: only holds when this launch is truly isolated.
    // If your normal Chrome is running, it captures --load-extension and the
    // extension answers from THAT session instead of our throwaway profile.
    const hermetic = tabs.some((t: { url?: string }) => (t.url || "").includes("page.html"));
    if (hermetic) {
      check(true, "isolated: our fixture tab present (fully hermetic)");
    } else {
      console.log(
        "  NOTE: fixture tab not seen - a running Chrome captured the extension\n" +
          "        load, so tab_list reflected that session. The round-trip above is\n" +
          "        still real. For full isolation, quit Chrome or point CHROME_BIN at a\n" +
          "        separate Chromium/Canary before running.",
      );
    }
  } finally {
    if (browser) await browser.close().catch(() => {});
    mcp.kill();
    if (IS_WINDOWS) {
      removeWindowsRegistration();
      if (backup) writeWindowsRegistration(backup);
    }
    // macOS: the manifest lives inside `profile`, deleted just below.
    fs.rmSync(work, { recursive: true, force: true });
    fs.rmSync(profile, { recursive: true, force: true });
  }

  console.log(`\n${"=".repeat(40)}\n${Pass} passed, ${Fail} failed`);
  process.exit(Fail > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error("fatal:", e);
  process.exit(1);
});
