/**
 * Third-party MCP client interop suite: drives the release binary over stdio
 * with the OFFICIAL TypeScript MCP client SDK v2 (@modelcontextprotocol/client,
 * spec revision 2026-07-28). This is the one real modern client we can test
 * against, so it proves the served protocol works beyond our own test
 * harnesses: era negotiation via `server/discover` and the complete-result
 * shape on `tools/list` / `tools/call`. Every post-connect request also rides
 * the per-request `_meta` protocol-version envelope the SDK auto-attaches on
 * a modern connection, so a server that refused the envelope would fail the
 * whole suite.
 *
 * The client PINS the modern era (`versionNegotiation: { mode: { pin:
 * '2026-07-28' } }`): no legacy fallback, so a server that cannot answer
 * `server/discover` fails the connect loudly instead of silently downgrading
 * to the 2025 `initialize` handshake. On the SDK's stdio transport the pinned
 * probe runs on a short-lived sibling process of the same binary, reaped
 * before the session child starts; the server's stale-lock replacement makes
 * that back-to-back spawn pattern safe.
 *
 * No browser is ever launched: with nothing attached to the bridge, tools/call
 * answers with the typed NOT_CONNECTED error INSIDE the result (isError true),
 * and this suite asserts exactly that shape.
 *
 * Run:  moon run test-interop   (or: bun test tests/interop/sdk-client.test.ts)
 * Requires the release binary at target/release/chromium-bridge (built if
 * missing via cargo, mirroring tests/protocol/e2e.py).
 */

import { afterAll, beforeAll, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Client } from "@modelcontextprotocol/client";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/client/stdio";

const REPO = path.resolve(import.meta.dir, "..", "..");
const BIN = path.join(
  REPO,
  "target",
  "release",
  process.platform === "win32" ? "chromium-bridge.exe" : "chromium-bridge",
);

// Mirror e2e.py's ensure_binary(): use the release binary if present, build
// it otherwise (cargo may live in /opt/homebrew/bin, off bun's default PATH).
function ensureBinary(): void {
  if (fs.existsSync(BIN)) return;
  console.error("[setup] release binary missing, building...");
  const cargo = fs.existsSync("/opt/homebrew/bin/cargo") ? "/opt/homebrew/bin/cargo" : "cargo";
  const build = Bun.spawnSync(
    [cargo, "build", "--release", "--manifest-path", path.join(REPO, "Cargo.toml")],
    {
      env: { ...process.env, PATH: `/opt/homebrew/bin:${process.env.PATH ?? ""}` },
      stdout: "inherit",
      stderr: "inherit",
    },
  );
  if (build.exitCode !== 0) {
    throw new Error(`cargo build --release failed (exit ${build.exitCode})`);
  }
}

// A private runtime dir keeps this suite's broker lock/socket away from any
// real bridge instance: the lock path honors XDG_RUNTIME_DIR on macOS and
// Linux, and lives under LOCALAPPDATA on Windows
// (src/packages/core/src/ipc/lockfile.rs) - all three are overridden below.
// XDG_CONFIG_HOME and (on macOS) HOME are pointed there too, mirroring
// e2e.py's isolation, so even fallback config paths stay in the sandbox.
let runtimeDir: string;
let client: Client;
let connected = false;
let connectError: unknown;

function assertConnected(): void {
  if (!connected) {
    throw new Error(`modern connect failed earlier in this suite: ${connectError}`);
  }
}

beforeAll(() => {
  runtimeDir = fs.mkdtempSync(path.join(os.tmpdir(), "bb-interop-"));
});

afterAll(async () => {
  if (connected) {
    await client.close();
  }
  fs.rmSync(runtimeDir, { recursive: true, force: true });
});

test("release binary is present (building it if missing)", () => {
  ensureBinary();
  expect(fs.existsSync(BIN)).toBe(true);
}, 600_000);

test("SDK v2 connects with the modern era pinned to 2026-07-28", async () => {
  client = new Client(
    { name: "interop-suite", version: "0.1.0" },
    { versionNegotiation: { mode: { pin: "2026-07-28" } } },
  );
  const env: Record<string, string> = {
    ...getDefaultEnvironment(),
    XDG_RUNTIME_DIR: runtimeDir,
    XDG_CONFIG_HOME: path.join(runtimeDir, "config"),
  };
  if (process.platform === "darwin") {
    env.HOME = runtimeDir;
  }
  if (process.platform === "win32") {
    env.LOCALAPPDATA = runtimeDir;
  }
  const transport = new StdioClientTransport({ command: BIN, env });
  try {
    await client.connect(transport, { timeout: 20_000 });
  } catch (e) {
    connectError = e;
    throw e;
  }
  connected = true;
  expect(client.getProtocolEra()).toBe("modern");
  expect(client.getNegotiatedProtocolVersion()).toBe("2026-07-28");
}, 30_000);

test("server/discover advertises the contract", async () => {
  assertConnected();
  // The connect-time probe's verdict...
  const adopted = client.getDiscoverResult();
  expect(adopted).toBeDefined();
  // ...and a live discover on the established session must agree.
  const discover = await client.discover();
  for (const result of [adopted, discover] as const) {
    if (!result) throw new Error("missing DiscoverResult");
    // The exact supported set is rmcp's full built-in list (ADR-0034 keeps
    // the SDK default); the Rust unit tests pin its newest entry to the
    // repo-wide 2026-07-28 pin, and this exact-list pin catches an rmcp
    // upgrade moving the wire.
    expect(result.supportedVersions).toEqual([
      "2024-11-05",
      "2025-03-26",
      "2025-06-18",
      "2025-11-25",
      "2026-07-28",
    ]);
    expect(result.capabilities.tools).toBeTruthy();
    // Cache freshness rides the loose result schema, not the static type.
    // Independent black-box pins of the served values; canonical source:
    // the Rust core's discover result (src/packages/core).
    const loose = result as Record<string, unknown>;
    expect(loose.ttlMs).toBe(3_600_000);
    expect(loose.cacheScope).toBe("private");
  }
  const serverInfo = client.getServerVersion();
  expect(serverInfo?.name).toBe("chromium-bridge");
}, 20_000);

test("tools/list carries the catalogue, stable across refetches", async () => {
  assertConnected();
  const first = await client.listTools();
  const names = first.tools.map((t) => t.name);
  expect(names).toContain("tab_list");
  expect(names).toContain("page_eval");
  // Black-box pin of the catalogue breadth (canonical source:
  // src/packages/core/src/tools/catalogue.rs); a regression dropping tools
  // must not slip past the two membership checks above.
  expect(names.length).toBeGreaterThanOrEqual(26);
  expect(new Set(names).size).toBe(names.length);
  for (const tool of first.tools) {
    expect(tool.name.length).toBeGreaterThan(0);
    expect(tool.inputSchema.type).toBe("object");
  }
  // Modern tools/list also stamps cache freshness (loose-schema fields).
  const loose = first as Record<string, unknown>;
  expect(loose.ttlMs).toBeGreaterThan(0);
  expect(loose.cacheScope).toBe("private");
  // A second, genuinely refetched list (bypass the SDK's response cache,
  // which would otherwise serve the first result back) must agree exactly:
  // the catalogue order must at least be stable within a session.
  const second = await client.listTools(undefined, { cacheMode: "bypass" });
  expect(second.tools.map((t) => t.name)).toEqual(names);
}, 20_000);

test("tools/call with no browser returns the typed NOT_CONNECTED error in-result", async () => {
  assertConnected();
  // Nothing is attached to the bridge socket, so the server must answer the
  // call itself with a tool-level error (isError true), never an RPC error:
  // the stable taxonomy code prefixes the text
  // (src/packages/core/src/tools/mod.rs error_outcome). This is the slowest
  // path in the suite: with an empty registry the server waits up to 12s for
  // a browser to attach before refusing, hence the generous timeout.
  const result = await client.callTool({ name: "tab_list", arguments: {} });
  expect(result.isError).toBe(true);
  const content = result.content;
  expect(Array.isArray(content)).toBe(true);
  const block = content[0];
  if (block?.type !== "text") throw new Error(`expected a text block, got ${block?.type}`);
  expect(block.text).toStartWith("Error [NOT_CONNECTED]:");
}, 60_000);
