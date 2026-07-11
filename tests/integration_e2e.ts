/**
 * Real end-to-end integration test — the seam e2e.py deliberately mocks.
 *
 * Exercises the FULL chain with nothing stubbed: MCP client (this) -> real MCP
 * server (release binary) -> localhost TCP bridge -> real native host (release
 * binary, spawned by Chrome) -> real extension (background.js) ->
 * chrome.tabs.query -> back. If tab_list returns the isolated profile's own
 * fixture tab, the whole native-messaging path e2e.py can't reach is proven.
 *
 * Isolation matters: a raw Chrome launch merges into an already-running Chrome
 * (and would query your real session). puppeteer launches a truly isolated
 * instance, and a UNIQUE extension copy (unique path => unique id) means the
 * host manifest only ever authorizes THIS throwaway profile.
 *
 * OPT-IN, macOS + Google Chrome only. Pops a non-headless Chrome window and
 * temporarily writes a native-messaging host manifest (backing up/restoring any
 * existing one). Not part of the default suite or CI.
 *
 * Run:  BB_REAL_E2E=1 bun tests/integration_e2e.ts
 */
import puppeteer from "puppeteer-core";
import { spawn } from "bun";
import { createHash } from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

const REPO = path.resolve(import.meta.dir, "..");
const BIN = path.join(REPO, "target", "release", "browser-bridge");
const DIST = path.join(REPO, "extension", "dist");
const CHROME =
  process.env.CHROME_BIN || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const NM_DIR = path.join(
  os.homedir(),
  "Library/Application Support/Google/Chrome/NativeMessagingHosts"
);
const HOST_NAME = "com.browser_bridge.host";
const MANIFEST = path.join(NM_DIR, HOST_NAME + ".json");
const LOCK = path.join(os.homedir(), "Library/Application Support/browser-bridge/run.lock");
const FIXTURE = "file://" + path.join(REPO, "tests", "fixtures", "page.html");

// ── preflight (opt-in) ─────────────────────────────────────────────────────
if (process.env.BB_REAL_E2E !== "1") {
  console.log("SKIP: set BB_REAL_E2E=1 to run the real Chrome integration test.");
  process.exit(0);
}
if (process.platform !== "darwin") {
  console.log("SKIP: real integration test is macOS + Google Chrome only.");
  process.exit(0);
}
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

let _pass = 0;
let _fail = 0;
function check(cond: boolean, label: string): void {
  if (cond) {
    _pass++;
    console.log("  PASS  " + label);
  } else {
    _fail++;
    console.log("  FAIL  " + label);
  }
}
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Chrome derives an unpacked extension's id from SHA-256 of its absolute path:
 * first 128 bits, each hex digit mapped 0-f -> a-p. */
function extIdFromPath(p: string): string {
  const h = createHash("sha256").update(p).digest("hex");
  return [...h.slice(0, 32)].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
}

async function main(): Promise<void> {
  // Unique copy => unique id => the manifest authorizes only this throwaway.
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "bb-e2e-"));
  fs.cpSync(DIST, path.join(work, "ext"), { recursive: true });
  const extDir = fs.realpathSync(path.join(work, "ext"));
  const extId = extIdFromPath(extDir);
  console.log("[e2e] extension id:", extId);

  const wrapper = path.join(work, "run-host.sh");
  fs.writeFileSync(wrapper, `#!/bin/sh\nexec "${BIN}" --native-host\n`);
  fs.chmodSync(wrapper, 0o755);

  // Back up any existing host manifest so a real install is untouched.
  let backup: string | null = null;
  if (fs.existsSync(MANIFEST)) {
    backup = MANIFEST + ".bb-e2e-backup";
    fs.renameSync(MANIFEST, backup);
  }
  try {
    fs.rmSync(LOCK);
  } catch {}

  const mcp = spawn({ cmd: [BIN], stdin: "pipe", stdout: "pipe", stderr: "pipe" });
  let connected = false;
  (async () => {
    const r = mcp.stderr.getReader();
    const d = new TextDecoder();
    try {
      for (;;) {
        const { value, done } = await r.read();
        if (done) break;
        if (d.decode(value).includes("native host connected and authenticated")) {
          connected = true;
        }
      }
    } catch {}
  })();

  const reader = mcp.stdout.getReader();
  const dec = new TextDecoder();
  let buf = "";
  async function recv(): Promise<any> {
    while (!buf.includes("\n")) {
      const { value, done } = await reader.read();
      if (done) throw new Error("mcp server stdout closed");
      buf += dec.decode(value);
    }
    const i = buf.indexOf("\n");
    const line = buf.slice(0, i);
    buf = buf.slice(i + 1);
    return JSON.parse(line);
  }
  function send(obj: unknown): void {
    mcp.stdin.write(JSON.stringify(obj) + "\n");
    mcp.stdin.flush();
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
    // launch so connectNative succeeds on the first try.
    fs.mkdirSync(NM_DIR, { recursive: true });
    fs.writeFileSync(
      MANIFEST,
      JSON.stringify({
        name: HOST_NAME,
        description: "browser-bridge integration test",
        path: wrapper,
        type: "stdio",
        allowed_origins: [`chrome-extension://${extId}/`],
      })
    );

    // puppeteer launches a TRULY isolated instance (unlike a raw subprocess).
    browser = await puppeteer.launch({
      executablePath: CHROME,
      headless: false,
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

    send({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2025-06-18", capabilities: {} },
    });
    await recv();
    send({ jsonrpc: "2.0", method: "notifications/initialized" });

    for (let i = 0; i < 300; i++) {
      if (connected) break;
      await sleep(100);
    }
    check(connected, "real extension connected via native host to the MCP server");

    send({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "tab_list", arguments: {} },
    });
    const r = await recv();
    const tabs = JSON.parse(r.result.content[0].text);
    // The real proof: structured chrome.tabs data crossed the entire chain.
    const first = Array.isArray(tabs) && tabs.length >= 1 ? tabs[0] : undefined;
    check(
      !!first && typeof first.id === "number" && typeof first.url === "string",
      "tab_list returned structured real chrome.tabs data (full round-trip works)"
    );
    check(r.result.isError === false, "tool call not an error");

    // Bonus hermeticity check: only holds when this launch is truly isolated.
    // If your normal Chrome is running, it captures --load-extension and the
    // extension answers from THAT session instead of our throwaway profile.
    const hermetic = tabs.some((t: { url?: string }) => (t.url || "").includes("page.html"));
    if (hermetic) {
      check(true, "isolated: our fixture tab present (fully hermetic)");
    } else {
      console.log(
        "  NOTE: fixture tab not seen — a running Chrome captured the extension\n" +
          "        load, so tab_list reflected that session. The round-trip above is\n" +
          "        still real. For full isolation, quit Chrome or point CHROME_BIN at a\n" +
          "        separate Chromium/Canary before running."
      );
    }
  } finally {
    if (browser) await browser.close().catch(() => {});
    mcp.kill();
    try {
      fs.rmSync(MANIFEST);
    } catch {}
    if (backup) fs.renameSync(backup, MANIFEST);
    fs.rmSync(work, { recursive: true, force: true });
    fs.rmSync(profile, { recursive: true, force: true });
  }

  console.log(`\n${"=".repeat(40)}\n${_pass} passed, ${_fail} failed`);
  process.exit(_fail > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error("fatal:", e);
  process.exit(1);
});
