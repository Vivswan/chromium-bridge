/**
 * Real end-to-end integration test - the seam e2e.py deliberately mocks.
 *
 * Exercises the chain with nothing stubbed: MCP client (this) -> real MCP
 * server (release binary) -> bridge socket -> real native host (release
 * binary, spawned by Chrome) -> real extension (background.js) -> its
 * enrollment gate -> back. The gate's refusal of tab_list proves the whole
 * native-messaging path e2e.py can't reach.
 *
 * Isolation matters: a raw Chrome launch merges into an already-running Chrome
 * (and would query your real session). puppeteer launches a truly isolated
 * instance. If the manifest has a pinned public key, the test derives the
 * pinned extension id; otherwise it derives the id from the throwaway path.
 *
 * OPT-IN, macOS or Windows + Chrome for Testing (or Chromium). Pops a
 * non-headless window. Enrollment is required on every platform and a
 * throwaway profile has no pinned host key, so the proof this test gives is
 * that the chain reaches the extension's enrollment gate: tab_list comes back
 * refused with the enrollment reason, and a served reply fails the test.
 *
 * The MCP server and the host run in a throwaway runtime dir (XDG_RUNTIME_DIR
 * and HOME, LOCALAPPDATA on Windows), proved by the binary's own `doctor
 * --paths`: a lock resolving anywhere else refuses the run, since the host
 * unlinks the existing socket before binding and would take the user's live
 * broker down. On Windows the host registration is an HKCU value every Chrome
 * of the account shares, so the suite runs only where none exists (a real
 * install's Chrome must never be pointed at the test host) and removes the one
 * it wrote. Not part of the default suite or CI.
 *
 * Run:  GENKAN_REAL_E2E=1 bun tests/browser/integration_e2e.ts
 */

import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  MCP_META_CLIENT_CAPABILITIES,
  MCP_META_PROTOCOL_VERSION,
  MCP_PROTOCOL_VERSION,
} from "@genkan/shared/generated/protocol";
import puppeteer from "puppeteer-core";
import {
  assertHostIsolated,
  assertIsolatedBrowserOrSkip,
  extensionDir,
  throwawayHostEnv,
  writeHostWrapper,
} from "./browser-safety";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "../..");
const IS_WINDOWS = process.platform === "win32";
const BIN = path.join(REPO, "target", "release", `genkan${IS_WINDOWS ? ".exe" : ""}`);
// The unpacked bundle, from the one home every browser suite shares (GENKAN_EXT_DIR, else the chrome-mv3 build).
const DIST = extensionDir();
// The guard (assertIsolatedBrowserOrSkip) verifies CHROME_BIN by --version
// before use; it is only ever an isolated Chrome for Testing here.
const CHROME = process.env.CHROME_BIN ?? "";
const HOST_NAME = "com.vivswan.genkan.host";
const REG_KEY = `HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\${HOST_NAME}`;
const REG_KEY_MACHINE = `HKLM\\Software\\Google\\Chrome\\NativeMessagingHosts\\${HOST_NAME}`;

const FIXTURE = pathToFileURL(path.join(REPO, "tests", "fixtures", "page.html")).href;

// ── preflight (opt-in) ─────────────────────────────────────────────────────
if (process.env.GENKAN_REAL_E2E !== "1") {
  console.log("SKIP: set GENKAN_REAL_E2E=1 to run the real Chrome integration test.");
  process.exit(0);
}
if (process.platform !== "darwin" && !IS_WINDOWS) {
  console.log(
    "SKIP: real integration test runs on macOS and Windows (profile-scoped host manifests).",
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

/** The registration a real install may hold. `absent` is reg.exe's own "unable to find" answer; anything
 * else that is not a parsed value is `unreadable`, and the suite refuses to run rather than risk deleting
 * a registration it could not back up. */
type Registration =
  | { state: "absent" }
  | { state: "present"; path: string }
  | { state: "unreadable"; reason: string };

function readWindowsRegistration(key: string, view: "32" | "64"): Registration {
  let out: string;
  try {
    out = execFileSync("reg.exe", ["query", key, "/ve", `/reg:${view}`], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (e) {
    const err = e as { status?: number; stderr?: unknown };
    const stderr = typeof err.stderr === "string" ? err.stderr : String(err.stderr ?? "");
    if (err.status === 1 && /unable to find/i.test(stderr)) return { state: "absent" };
    return { state: "unreadable", reason: stderr.trim() || `reg.exe exited ${err.status ?? "?"}` };
  }
  const value = out.match(/REG_SZ\s+(.+)\r?$/m)?.[1]?.trim();
  return value
    ? { state: "present", path: value }
    : { state: "unreadable", reason: "no REG_SZ value in the query output" };
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
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "genkan-e2e-"));
  // Every exit path (a refusal, a crash, Ctrl-C, the normal finish) ends the children this run started and
  // removes its throwaway dirs. The profile and the processes are registered as they come to exist.
  const throwaway: string[] = [work];
  const children: Array<{ kill(signal?: NodeJS.Signals): unknown } | null> = [];
  // The registration this run wrote, if it got that far: the only one the cleanup may remove, and only while
  // it still holds this run's value. The key goes because this run created it; a value that changed meanwhile
  // arrived from elsewhere and stays.
  let wroteRegistration: string | null = null;
  const removeOwnRegistration = (): void => {
    if (!IS_WINDOWS || wroteRegistration === null) return;
    const now = readWindowsRegistration(REG_KEY, "64");
    if (now.state === "present" && now.path === wroteRegistration) removeWindowsRegistration();
    else console.warn("[e2e] the host registration changed under the run; leaving it in place");
    wroteRegistration = null;
  };
  process.on("exit", () => {
    for (const child of children) child?.kill("SIGKILL");
    for (const dir of throwaway) fs.rmSync(dir, { recursive: true, force: true });
    removeOwnRegistration();
  });
  process.on("SIGINT", () => process.exit(130));
  const env = throwawayHostEnv(work);
  // The binary's own word on where it would put the lock under this environment: anywhere outside the
  // throwaway dir is the user's live runtime dir, and the run refuses (fail closed, not a platform guess).
  // A probe that cannot be read refuses the same way.
  let LOCK: string;
  try {
    LOCK = assertHostIsolated(BIN, env, work);
  } catch (e) {
    console.error(`REFUSING TO RUN: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  }
  fs.cpSync(DIST, path.join(work, "ext"), { recursive: true });
  const extDir = fs.realpathSync(path.join(work, "ext"));
  const extId = extIdFromPath(extDir);
  console.log("[e2e] extension id:", extId);

  const hostPath = writeHostWrapper(work, BIN, ["--native-host"], env);

  // Windows only: the HKCU registration is shared by every Chrome of this account, so a real install's
  // Chrome would be pointed at the test host for the duration of the run. The suite runs only where no
  // registration exists, and refuses when it cannot tell. (On macOS the manifest lives inside the throwaway
  // profile, so a real registration is never touched.)
  // Chrome reads HKCU before HKLM and both the 32- and 64-bit registry views, so all four are checked.
  if (IS_WINDOWS) {
    for (const key of [REG_KEY, REG_KEY_MACHINE]) {
      for (const view of ["32", "64"] as const) {
        const existing = readWindowsRegistration(key, view);
        if (existing.state === "absent") continue;
        const why =
          existing.state === "present"
            ? `a host registration exists at ${key} (/reg:${view}, ${existing.path}); a real install's Chrome would be pointed at the test host`
            : `the host registration at ${key} (/reg:${view}) could not be read (${existing.reason})`;
        console.error(`REFUSING TO RUN: ${why}`);
        process.exit(1);
      }
    }
  }
  // Everything that can throw before the try below is done before the server exists, so a server never
  // outlives the exit hook that removes its runtime dir.
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "genkan-e2e-profile-"));
  throwaway.push(profile);

  const mcp = spawn(BIN, [], { stdio: ["pipe", "pipe", "pipe"], env });
  children.push(mcp);
  // The server's diagnostics, kept for the failure report: a reply that never comes is explained there.
  // The session lines also carry the browser leg's state ("native host 'default' connected and
  // authenticated (generation N)" / "disconnected (generation N)"), which is how the suite knows a host is
  // attached right now rather than was attached once.
  const serverLog: string[] = [];
  const live = new Set<string>();
  let partial = "";
  mcp.stderr.on("data", (chunk: Buffer) => {
    // Chunks are not lines: the remainder after the last newline waits for the next chunk.
    const pieces = (partial + chunk.toString("utf8")).split("\n");
    partial = pieces.pop() ?? "";
    for (const line of pieces) {
      if (line.length === 0) continue;
      serverLog.push(line);
      const generation = line.match(
        /native host '[^']*' (connected and authenticated|disconnected) \(generation (\d+)\)/,
      );
      if (!generation) continue;
      if (generation[1] === "disconnected") live.delete(generation[2] ?? "");
      else live.add(generation[2] ?? "");
    }
  });
  let exited = false;
  mcp.on("exit", (code, signal) => {
    exited = true;
    serverLog.push(`[server exited: code ${code} signal ${signal}]`);
  });

  const outputLines = createInterface({ input: mcp.stdout });
  const queuedLines: string[] = [];
  const lineWaiters: Array<(line: string) => void> = [];
  outputLines.on("line", (line) => {
    const waiter = lineWaiters.shift();
    if (waiter) waiter(line);
    else queuedLines.push(line);
  });
  /** The next reply line, or a thrown error carrying the server's log when none arrives in time: a dead
   * transport fails the suite instead of hanging it. */
  async function recv(): Promise<any> {
    const queued = queuedLines.shift();
    if (queued !== undefined) return JSON.parse(queued);
    const line = await new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => {
        const at = lineWaiters.indexOf(settle);
        if (at >= 0) lineWaiters.splice(at, 1);
        reject(
          new Error(
            `no reply from the MCP server within 30s; server log:\n${serverLog.slice(-40).join("\n")}`,
          ),
        );
      }, 30_000);
      const settle = (reply: string) => {
        clearTimeout(timer);
        resolve(reply);
      };
      lineWaiters.push(settle);
    });
    return JSON.parse(line);
  }
  function send(obj: unknown): void {
    mcp.stdin.write(`${JSON.stringify(obj)}\n`);
  }

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
        description: "genkan integration test",
        path: hostPath,
        type: "stdio",
        allowed_origins: [`chrome-extension://${extId}/`],
      }),
    );
    if (IS_WINDOWS) {
      writeWindowsRegistration(testManifest);
      wroteRegistration = testManifest;
    }

    // puppeteer launches a TRULY isolated instance (unlike a raw subprocess).
    browser = await puppeteer.launch({
      executablePath: CHROME,
      headless: false,
      dumpio: process.env.GENKAN_REAL_E2E_DEBUG === "1",
      env,
      // Ctrl-C: puppeteer's own handler would exit without this file's cleanup; the SIGINT handler below
      // routes through the exit hook instead.
      handleSIGINT: false,
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
    children.push(browser.process());
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

    if (process.env.GENKAN_REAL_E2E_DEBUG === "1") {
      console.log(
        "[e2e] Chrome targets:",
        browser.targets().map((target) => `${target.type()} ${target.url()}`),
      );
    }

    // The enrollment gate refuses bridge ops until a host key is paired and
    // pinned, with no opt-out and no platform exemption, and a throwaway profile
    // holds no pin: the refusal below is the round trip's proof.
    const workerTarget = browser.targets().find((target) => target.url() === expectedWorkerUrl);
    const worker = await workerTarget!.worker();
    if (!worker) throw new Error("could not attach to the extension service worker");
    // An open extension page keeps the MV3 worker alive: Chrome ends an idle worker after about 30 s, the
    // host dies with the port, and nothing reconnects until an event wakes the worker again.
    const options = await browser.newPage();
    await options.goto(`chrome-extension://${extId}/options.html`, {
      waitUntil: "load",
      timeout: 15000,
    });

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

    // A host attached and STILL attached after a settle window: the extension connects, runs its ceremony,
    // and may reconnect around it, and a request sent into that churn proves nothing.
    let connected = false;
    for (let i = 0; i < 300 && !connected; i++) {
      if (live.size === 0) {
        await sleep(100);
        continue;
      }
      await sleep(1500);
      connected = live.size > 0;
    }
    check(
      connected,
      "real extension connected via native host to the MCP server",
      serverLog.slice(-20),
    );

    // The browser leg re-attaches around the extension's connect-time ceremony, so a tab_list sent the
    // instant the first attach is logged can land in a gap (NOT_CONNECTED at the server, which waits 12 s
    // for a browser before answering) or on a connection that drops mid-request (CONNECTION_LOST). Neither
    // reply reached the extension's gate, so neither proves anything either way; they are retried three
    // times under a fresh id each, and every other reply is judged as it is.
    const errorText = (reply: any): string | null => {
      const content: unknown = reply?.result?.content;
      const first = Array.isArray(content)
        ? (content[0] as { type?: unknown; text?: unknown })
        : undefined;
      return typeof first?.text === "string" && first.type === "text" ? first.text : null;
    };
    let id = 2;
    let r: any;
    for (let attempt = 0; attempt < 3; attempt++, id++) {
      send({
        jsonrpc: "2.0",
        id,
        method: "tools/call",
        params: {
          name: "tab_list",
          arguments: {},
          _meta: meta,
        },
      });
      r = await recv();
      const transient = /NOT_CONNECTED|CONNECTION_LOST/.test(errorText(r) ?? "");
      if (r.id !== id || !transient) break;
      await sleep(250);
    }
    // The profile holds no pinned host key, so the only correct answer is the enrollment gate's refusal,
    // as the JSON-RPC reply to THIS request: a served tab_list would mean the gate is gone, and an
    // uncorrelated or shapeless reply proves nothing.
    check(
      r.jsonrpc === "2.0" &&
        r.id === id &&
        r.error === undefined &&
        typeof r.result === "object" &&
        r.result !== null &&
        r.result.isError === true &&
        errorText(r)?.includes("enrollment required") === true,
      "tab_list reached the extension's enrollment gate and was refused (no pin in a throwaway profile)",
      { reply: r, serverLog: serverLog.slice(-20) },
    );
    check(
      r.result?.resultType === "complete" && r.result?._meta === undefined,
      "modern tool result carries resultType (serverInfo _meta rides only discover)",
    );
  } finally {
    if (browser) await browser.close().catch(() => {});
    // The server is gone before the exit hook removes its runtime dir, or its shutdown writes recreate it;
    // a server that will not die keeps its dir (a warning, never a delete under a live process).
    mcp.kill();
    for (let i = 0; i < 50 && !exited; i++) await sleep(100);
    if (!exited) {
      mcp.kill("SIGKILL");
      for (let i = 0; i < 50 && !exited; i++) await sleep(100);
    }
    if (!exited) {
      console.warn(`[e2e] the MCP server did not exit; leaving ${work} and ${profile} in place`);
      throwaway.length = 0;
    }
    removeOwnRegistration();
  }

  console.log(`\n${"=".repeat(40)}\n${Pass} passed, ${Fail} failed`);
  process.exit(Fail > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error("fatal:", e);
  process.exit(1);
});
