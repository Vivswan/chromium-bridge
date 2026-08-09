#!/usr/bin/env bun

// Agent-harness interop smoke suite (chromium-bridge).
//
// Drives REAL agent-harness CLIs (Claude Code, Codex; the registry below is
// the extension point) headlessly against OUR release binary: each harness
// gets an ISOLATED config dir (never the user's real ~/.claude or ~/.codex),
// our binary is registered there as a stdio MCP server behind a tee shim
// that logs every JSON-RPC frame the harness sends, and the harness's own
// health-check command must report the server usable.
//
// Two purposes:
//   (a) a continuous check that agent harnesses can connect to and drive
//       the bridge's stdio MCP server;
//   (b) the ADR-0034 canary: the suite prints the OPENING method each
//       harness sent (the legacy `initialize` handshake vs the modern
//       2026-07-28 `server/discover` opening). When every harness opens
//       with server/discover, the temporary legacy shim can be deleted.
//
// No browser is involved anywhere: the server side is the bare binary with
// no native host attached, and the shim points the server's runtime, config,
// and home dirs at a throwaway scratch dir, so this instance can never
// attach to (or become) the user's real bridge broker or read real pairing
// state.
//
// Harnesses whose CLI is not on PATH are skipped with a message. A probe
// that cannot avoid a model/API call (Codex has no offline health check)
// runs only behind an explicit opt-in (BB_HARNESS_CODEX_LIVE=1 plus the API
// key) and is otherwise reported as "configured" - registration verified,
// live connection not exercised.
//
// Deliberately self-contained (node builtins only, no scripts/lib.ts
// import) so it runs without a `bun install`.
//
// Dual-use: local runs (`moon run harness-smoke`) and CI (the nightly
// harness-smoke.yml workflow, which uploads build/harness-captures/ as an
// artifact).
//
// Usage: bun tests/harness/run.ts [--mint-seeds] [--require-any]
//   --mint-seeds   after the run, copy deduplicated captured frames into
//                  src/packages/core/fuzz/seeds/mcp_jsonrpc/ (a real-world
//                  corpus for the fuzzer), one file per distinct frame
//   --require-any  fail (exit 1) unless at least one harness completed a
//                  LIVE MCP connection; the nightly workflow passes this so
//                  a broken harness install (or a run that only verified
//                  config entries) cannot read as a green night

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  accessSync,
  chmodSync,
  existsSync,
  constants as fsConstants,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const usage = "usage: bun tests/harness/run.ts [--mint-seeds] [--require-any]";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const BIN = resolve(REPO, "target", "release", "chromium-bridge");
const CAPTURE_DIR = resolve(REPO, "build", "harness-captures");
const SEEDS_DIR = resolve(REPO, "src", "packages", "core", "fuzz", "seeds", "mcp_jsonrpc");
// The name the bridge is registered under in each harness's isolated config.
const SERVER_NAME = "chromium-bridge";

interface Options {
  mintSeeds: boolean;
  requireAny: boolean;
}

function parseOptions(argv: string[]): Options {
  const options: Options = { mintSeeds: false, requireAny: false };
  for (const arg of argv) {
    if (arg === "--mint-seeds") options.mintSeeds = true;
    else if (arg === "--require-any") options.requireAny = true;
    else {
      console.error(`error: invalid argument: ${arg}\n${usage}`);
      process.exit(2);
    }
  }
  return options;
}

interface RunResult {
  status: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  /** Spawn-level failure (ENOENT and friends), distinct from a nonzero exit. */
  spawnError: string | undefined;
}

function run(
  cmd: string[],
  opts: { env: NodeJS.ProcessEnv; cwd: string; timeoutMs: number; stdin?: string },
): RunResult {
  const r = spawnSync(cmd[0] as string, cmd.slice(1), {
    env: opts.env,
    cwd: opts.cwd,
    timeout: opts.timeoutMs,
    input: opts.stdin,
    encoding: "utf8",
  });
  const timedOut =
    r.error !== undefined && /ETIMEDOUT/i.test((r.error as NodeJS.ErrnoException).code ?? "");
  return {
    status: r.status,
    stdout: r.stdout ?? "",
    stderr: r.stderr ?? "",
    timedOut,
    spawnError: r.error && !timedOut ? r.error.message : undefined,
  };
}

/** Everything the registry callbacks need for one harness run. */
interface HarnessContext {
  /** Resolved path of the harness CLI (see resolveCli). */
  cliBin: string;
  /** The tee shim the harness launches as its stdio MCP server command. */
  shim: string;
  /** NDJSON log of every frame the harness sent (survives the run). */
  capture: string;
  /** Throwaway per-harness dir holding the isolated config homes. */
  scratch: string;
  /** Environment for every CLI invocation: process.env plus the isolation
   * overrides (e.g. CLAUDE_CONFIG_DIR) pointing into scratch. */
  env: NodeJS.ProcessEnv;
}

type ProbeOutcome =
  /** The harness's own health check reported the server connected. */
  | { kind: "connected"; detail: string }
  /** Registration verified in the isolated config, but a live connection
   * would need a model/API call whose key is absent. */
  | { kind: "configured"; detail: string }
  | { kind: "failed"; detail: string };

interface Harness {
  name: string;
  /** Executable probed on PATH; missing -> the harness is skipped. */
  cli: string;
  /** Isolation overrides layered over process.env for every invocation. */
  isolationEnv(scratch: string): NodeJS.ProcessEnv;
  /** The file inside the isolated config home where configure()'s
   * registration must land; the driver refuses to probe when it is absent,
   * because that means the harness ignored the isolation env var and may
   * have written the user's REAL config instead. */
  configFile(scratch: string): string;
  /** Register ctx.shim as a stdio MCP server in the isolated config. */
  configure(ctx: HarnessContext): ProbeOutcome | undefined;
  /** Assert the harness can reach the server, without a model call where
   * the CLI supports that. */
  probe(ctx: HarnessContext): ProbeOutcome;
}

const CONFIGURE_TIMEOUT_MS = 60_000;
// The health check spawns the shim + binary and runs a real MCP handshake;
// a CI runner's cold start needs headroom.
const PROBE_TIMEOUT_MS = 180_000;

function failure(step: string, r: RunResult): ProbeOutcome {
  const why = r.spawnError ?? (r.timedOut ? "timed out" : `exit ${r.status}`);
  const tail = (r.stderr || r.stdout).trim().split("\n").slice(-3).join(" | ");
  return { kind: "failed", detail: `${step}: ${why}${tail ? ` (${tail})` : ""}` };
}

/**
 * Resolve a harness CLI to a real executable: BB_HARNESS_<NAME>_BIN wins,
 * then the first PATH hit that is not a terminal-mux proxy (cmux drops a
 * `claude` wrapper shim on PATH that breaks stdio MCP health checks), then
 * any PATH hit. Undefined means the harness is not installed.
 */
function resolveCli(cli: string): string | undefined {
  const override = process.env[`BB_HARNESS_${cli.toUpperCase()}_BIN`];
  if (override) return override;
  const candidates: string[] = [];
  for (const dir of (process.env.PATH ?? "").split(":")) {
    if (dir === "") continue;
    const candidate = join(dir, cli);
    try {
      accessSync(candidate, fsConstants.X_OK);
      candidates.push(candidate);
    } catch {
      // not here; keep walking PATH
    }
  }
  return candidates.find((candidate) => !candidate.includes("cmux-cli-shims")) ?? candidates[0];
}

const HARNESSES: Harness[] = [
  {
    // Claude Code: CLAUDE_CONFIG_DIR moves ALL config (including the user
    // scope's .claude.json) into scratch, and `claude mcp list` runs a real
    // MCP handshake against every approved server - a genuine connection
    // probe with no model call.
    name: "claude",
    cli: "claude",
    isolationEnv(scratch: string): NodeJS.ProcessEnv {
      return { ...process.env, CLAUDE_CONFIG_DIR: join(scratch, "claude-config") };
    },
    configFile(scratch: string): string {
      return join(scratch, "claude-config", ".claude.json");
    },
    configure(ctx: HarnessContext): ProbeOutcome | undefined {
      const r = run([ctx.cliBin, "mcp", "add", "--scope", "user", SERVER_NAME, "--", ctx.shim], {
        env: ctx.env,
        cwd: ctx.scratch,
        timeoutMs: CONFIGURE_TIMEOUT_MS,
      });
      return r.status === 0 ? undefined : failure("claude mcp add", r);
    },
    probe(ctx: HarnessContext): ProbeOutcome {
      const r = run([ctx.cliBin, "mcp", "list"], {
        env: ctx.env,
        cwd: ctx.scratch,
        timeoutMs: PROBE_TIMEOUT_MS,
      });
      if (r.spawnError || r.timedOut) return failure("claude mcp list", r);
      const line = r.stdout.split("\n").find((candidate) => candidate.includes(`${SERVER_NAME}:`));
      if (line && /connected/i.test(line) && !/failed/i.test(line)) {
        return { kind: "connected", detail: line.trim() };
      }
      return {
        kind: "failed",
        detail: `claude mcp list did not report ${SERVER_NAME} connected: ${line ?? (r.stdout.trim() || r.stderr.trim())}`,
      };
    },
  },
  {
    // Codex: CODEX_HOME moves config.toml (and auth) into scratch. There is
    // no offline health check - `codex mcp list` only reads the config - so
    // the live probe means running a REAL codex agent session, which is
    // gated behind an explicit opt-in on top of the API key; without both,
    // the outcome is "configured".
    name: "codex",
    cli: "codex",
    isolationEnv(scratch: string): NodeJS.ProcessEnv {
      // codex refuses a CODEX_HOME that does not exist yet.
      const home = join(scratch, "codex-home");
      mkdirSync(home, { recursive: true });
      return { ...process.env, CODEX_HOME: home };
    },
    configFile(scratch: string): string {
      return join(scratch, "codex-home", "config.toml");
    },
    configure(ctx: HarnessContext): ProbeOutcome | undefined {
      const r = run([ctx.cliBin, "mcp", "add", SERVER_NAME, "--", ctx.shim], {
        env: ctx.env,
        cwd: ctx.scratch,
        timeoutMs: CONFIGURE_TIMEOUT_MS,
      });
      return r.status === 0 ? undefined : failure("codex mcp add", r);
    },
    probe(ctx: HarnessContext): ProbeOutcome {
      const list = run([ctx.cliBin, "mcp", "list", "--json"], {
        env: ctx.env,
        cwd: ctx.scratch,
        timeoutMs: CONFIGURE_TIMEOUT_MS,
      });
      if (list.status !== 0 || !list.stdout.includes(ctx.shim)) {
        return failure("codex mcp list --json (registration missing)", list);
      }
      const key = process.env.OPENAI_API_KEY;
      // An ambient API key alone must never launch an agent session: the
      // live probe runs real codex with shell tools. Explicit opt-in only.
      if (!key || process.env.BB_HARNESS_CODEX_LIVE !== "1") {
        return {
          kind: "configured",
          detail:
            "registered in the isolated config.toml; live connection skipped " +
            "(codex has no offline health check - the live probe runs a real " +
            "codex agent session, so it needs OPENAI_API_KEY plus the " +
            "explicit BB_HARNESS_CODEX_LIVE=1 opt-in)",
        };
      }
      const login = run([ctx.cliBin, "login", "--with-api-key"], {
        env: ctx.env,
        cwd: ctx.scratch,
        timeoutMs: CONFIGURE_TIMEOUT_MS,
        stdin: key,
      });
      if (login.status !== 0) return failure("codex login --with-api-key", login);
      const exec = run(
        [
          ctx.cliBin,
          "exec",
          "--skip-git-repo-check",
          "-c",
          'sandbox_mode="read-only"',
          "Reply with the single word OK.",
        ],
        { env: ctx.env, cwd: ctx.scratch, timeoutMs: PROBE_TIMEOUT_MS },
      );
      if (exec.status !== 0) return failure("codex exec", exec);
      // The session succeeding is not enough: prove the server was actually
      // launched by requiring frames in the capture.
      if (!existsSync(ctx.capture) || readFileSync(ctx.capture, "utf8").trim() === "") {
        return { kind: "failed", detail: "codex exec succeeded but sent no frames to the server" };
      }
      return {
        kind: "connected",
        detail: "codex exec session launched the server and sent frames",
      };
    },
  },
];

/** Mirror tests/protocol/e2e.py ensure_binary(): build the release binary
 * when missing, preferring the homebrew cargo like the e2e suite does. */
function ensureBinary(): void {
  if (existsSync(BIN)) return;
  console.log("[harness-smoke] release binary missing, building...");
  const brewCargo = "/opt/homebrew/bin/cargo";
  const cargo = existsSync(brewCargo) ? brewCargo : "cargo";
  const env = { ...process.env, PATH: `/opt/homebrew/bin:${process.env.PATH ?? ""}` };
  const r = spawnSync(cargo, ["build", "--release", "--manifest-path", join(REPO, "Cargo.toml")], {
    env,
    stdio: "inherit",
  });
  if (r.status !== 0 || !existsSync(BIN)) {
    console.error("error: could not build the release binary");
    process.exit(1);
  }
}

/**
 * The tee shim the harness launches instead of the binary: it appends every
 * stdin frame (MCP stdio is NDJSON, so the capture file is NDJSON too) to
 * the capture log while feeding them to the real binary. It also points the
 * server's runtime/config/home dirs at throwaway dirs - the server this
 * suite spawns must never share a lock file, socket, pairing state, or kill
 * switch with the user's real bridge (same isolation the e2e suite's
 * admin-frames test uses). The runtime dir is created SEPARATELY with a
 * short name: the server binds a Unix socket under XDG_RUNTIME_DIR, and a
 * path over the SUN_LEN limit (104 bytes on macOS) makes it fail closed
 * before answering initialize.
 */
function writeShim(ctx: { scratch: string; runtime: string; capture: string }): string {
  const q = (value: string): string => `'${value.replace(/'/g, "'\\''")}'`;
  const state = join(ctx.scratch, "server-state");
  mkdirSync(state, { recursive: true });
  const shim = join(ctx.scratch, "mcp-server-shim.sh");
  const lines = [
    "#!/bin/sh",
    "# Generated by tests/harness/run.ts (recreated every run).",
    `export XDG_RUNTIME_DIR=${q(ctx.runtime)}`,
    `export XDG_CONFIG_HOME=${q(join(state, "config"))}`,
    `export HOME=${q(state)}`,
    `tee -a ${q(ctx.capture)} | exec ${q(BIN)}`,
    "",
  ];
  writeFileSync(shim, lines.join("\n"));
  chmodSync(shim, 0o755);
  return shim;
}

interface CaptureAnalysis {
  frames: number;
  /** Method of the first frame carrying one: the ADR-0034 canary. */
  opening: string | undefined;
  methods: string[];
}

function parseFrames(capture: string): unknown[] {
  if (!existsSync(capture)) return [];
  const frames: unknown[] = [];
  for (const line of readFileSync(capture, "utf8").split("\n")) {
    if (line.trim() === "") continue;
    try {
      frames.push(JSON.parse(line));
    } catch {
      // A torn final line (harness killed mid-write) is not a frame.
    }
  }
  return frames;
}

function analyzeCapture(capture: string): CaptureAnalysis {
  const frames = parseFrames(capture);
  const methods: string[] = [];
  for (const frame of frames) {
    const method = (frame as { method?: unknown }).method;
    if (typeof method === "string" && !methods.includes(method)) methods.push(method);
  }
  return { frames: frames.length, opening: methods[0], methods };
}

/** The shim-removal canary (ADR-0034), printed prominently per harness. */
function printCanary(name: string, analysis: CaptureAnalysis): void {
  const prefix = `[harness-smoke] CANARY ${name}: opening method =`;
  if (analysis.opening === undefined) {
    console.log(
      `[harness-smoke] CANARY ${name}: no frames captured (the server was never launched)`,
    );
  } else if (analysis.opening === "initialize") {
    console.log(`${prefix} initialize (LEGACY handshake; the ADR-0034 shim is still required)`);
  } else if (analysis.opening === "server/discover") {
    console.log(
      `${prefix} server/discover (MODERN 2026-07-28 opening; once every harness reports this, delete the ADR-0034 legacy shim)`,
    );
  } else {
    console.log(`${prefix} ${analysis.opening} (unexpected - inspect the capture)`);
  }
}

const slug = (method: string): string =>
  method
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");

/**
 * Copy deduplicated captured frames into the mcp_jsonrpc fuzz seed corpus.
 * Raw captured lines are written (the real-world bytes are the point);
 * dedup compares re-serialized JSON, so whitespace variants collapse while
 * key-order variants stay distinct (deliberate: those are different
 * real-world byte sequences). Names are descriptive
 * (harness-claude-initialize, harness-claude-tools-list, ...); a name
 * collision with different content gets a short hash suffix. Returns the
 * number of seeds written.
 */
export function mintSeeds(captureDir: string, seedsDir: string): number {
  mkdirSync(seedsDir, { recursive: true });
  const known = new Set<string>();
  for (const name of readdirSync(seedsDir)) {
    try {
      known.add(JSON.stringify(JSON.parse(readFileSync(join(seedsDir, name), "utf8"))));
    } catch {
      // Non-JSON seeds (hostile-input reproducers) cannot collide with a
      // captured frame; skip them.
    }
  }
  let minted = 0;
  const captures = existsSync(captureDir)
    ? readdirSync(captureDir).filter((name) => name.endsWith(".ndjson"))
    : [];
  for (const file of captures) {
    const harness = basename(file, ".ndjson");
    for (const line of readFileSync(join(captureDir, file), "utf8").split("\n")) {
      if (line.trim() === "") continue;
      // A seed is a single protocol frame; anything huge (a screenshot
      // payload in a future capture) does not belong in the committed corpus.
      if (Buffer.byteLength(line, "utf8") > 64 * 1024) continue;
      let frame: unknown;
      try {
        frame = JSON.parse(line);
      } catch {
        continue;
      }
      const canonical = JSON.stringify(frame);
      if (known.has(canonical)) continue;
      known.add(canonical);
      const method = (frame as { method?: unknown }).method;
      const kind =
        typeof method === "string"
          ? slug(method)
          : (frame as { error?: unknown }).error !== undefined
            ? "error"
            : "response";
      let name = `harness-${harness}-${kind}`;
      if (existsSync(join(seedsDir, name))) {
        name += `-${createHash("sha256").update(canonical).digest("hex").slice(0, 8)}`;
      }
      writeFileSync(join(seedsDir, name), `${line.trim()}\n`);
      console.log(`[harness-smoke] minted seed ${name}`);
      minted += 1;
    }
  }
  return minted;
}

interface HarnessReport {
  name: string;
  outcome: "connected" | "configured" | "failed" | "skipped";
  detail: string;
  opening: string | undefined;
  frames: number;
  methods: string[];
}

function runHarness(harness: Harness): HarnessReport {
  const report = (outcome: HarnessReport["outcome"], detail: string): HarnessReport => ({
    name: harness.name,
    outcome,
    detail,
    opening: undefined,
    frames: 0,
    methods: [],
  });
  const overrideVar = `BB_HARNESS_${harness.cli.toUpperCase()}_BIN`;
  const cliBin = resolveCli(harness.cli);
  if (!cliBin) {
    const detail = `${harness.cli} not on PATH - install it to include this harness`;
    console.log(`[harness-smoke] ${harness.name}: SKIP (${detail})`);
    return report("skipped", detail);
  }

  const scratch = mkdtempSync(join(tmpdir(), `bb-harness-${harness.name}-`));
  // Short prefix on purpose: the socket path bound under this dir must stay
  // inside SUN_LEN (see writeShim).
  const runtime = mkdtempSync(join(tmpdir(), "bbh-"));
  const capture = join(CAPTURE_DIR, `${harness.name}.ndjson`);
  try {
    const ctx: HarnessContext = {
      cliBin,
      scratch,
      capture,
      shim: writeShim({ scratch, runtime, capture }),
      env: harness.isolationEnv(scratch),
    };
    const version = run([cliBin, "--version"], {
      env: ctx.env,
      cwd: ctx.scratch,
      timeoutMs: 30_000,
    });
    if (version.spawnError || version.timedOut || version.status !== 0) {
      // An explicitly requested binary that cannot run is a failure, not a
      // silent coverage loss; only an implicit PATH miss is a skip.
      const why = version.spawnError ?? (version.timedOut ? "timed out" : `exit ${version.status}`);
      const detail = `${cliBin} --version is not runnable (${why})`;
      if (process.env[overrideVar]) {
        console.error(`[harness-smoke] ${harness.name}: FAILED (${overrideVar}: ${detail})`);
        return report("failed", `${overrideVar}: ${detail}`);
      }
      console.log(`[harness-smoke] ${harness.name}: SKIP (${detail})`);
      return report("skipped", detail);
    }
    console.log(
      `[harness-smoke] ${harness.name}: ${cliBin} (${version.stdout.trim().split("\n")[0]})`,
    );

    let outcome = harness.configure(ctx);
    if (outcome === undefined) {
      const configFile = harness.configFile(scratch);
      // The shim path is unique per run, so its presence proves THIS run's
      // registration landed in the isolated file (a bare server-name match
      // could be satisfied by pre-seeded content).
      if (!existsSync(configFile) || !readFileSync(configFile, "utf8").includes(ctx.shim)) {
        // Same fail-closed rule as e2e.py's isolate(): if the isolation env
        // var did not take, the registration may have landed in the user's
        // REAL config - refuse to continue and say where to look.
        outcome = {
          kind: "failed",
          detail:
            `isolation did not take: ${configFile} does not carry the ` +
            `${SERVER_NAME} registration; the harness may have written its ` +
            "real user config instead - check and clean it before rerunning",
        };
      } else {
        outcome = harness.probe(ctx);
      }
    }
    const analysis = analyzeCapture(capture);
    if (outcome.kind === "connected" && analysis.frames === 0) {
      outcome = {
        kind: "failed",
        detail: `reported connected but the capture holds no frames (${outcome.detail})`,
      };
    }
    console.log(`[harness-smoke] ${harness.name}: ${outcome.kind} - ${outcome.detail}`);
    if (analysis.frames > 0) {
      console.log(
        `[harness-smoke] ${harness.name}: captured ${analysis.frames} frame(s), methods: ${analysis.methods.join(", ")}`,
      );
    }
    printCanary(harness.name, analysis);
    return {
      name: harness.name,
      outcome: outcome.kind,
      detail: outcome.detail,
      opening: analysis.opening,
      frames: analysis.frames,
      methods: analysis.methods,
    };
  } finally {
    // The capture (in CAPTURE_DIR) survives; only the isolated config homes
    // and the server's scratch state go.
    rmSync(scratch, { recursive: true, force: true });
    rmSync(runtime, { recursive: true, force: true });
  }
}

function main(): number {
  const options = parseOptions(process.argv.slice(2));
  if (process.platform === "win32") {
    console.log("[harness-smoke] SKIP: the tee shim is POSIX sh; Windows is not covered");
    return 0;
  }
  ensureBinary();
  rmSync(CAPTURE_DIR, { recursive: true, force: true });
  mkdirSync(CAPTURE_DIR, { recursive: true });

  const reports = HARNESSES.map(runHarness);
  writeFileSync(
    join(CAPTURE_DIR, "summary.json"),
    `${JSON.stringify({ generatedAt: new Date().toISOString(), reports }, null, 2)}\n`,
  );

  if (options.mintSeeds) {
    const minted = mintSeeds(CAPTURE_DIR, SEEDS_DIR);
    console.log(`[harness-smoke] minted ${minted} new seed(s) into ${SEEDS_DIR}`);
  }

  const failed = reports.filter((report) => report.outcome === "failed");
  const connected = reports.filter((report) => report.outcome === "connected");
  const probed = reports.filter(
    (report) => report.outcome === "connected" || report.outcome === "configured",
  );
  console.log(
    `[harness-smoke] ${connected.length} connected, ${probed.length - connected.length} configured, ` +
      `${failed.length} failed, ${reports.length - probed.length - failed.length} skipped; ` +
      `captures in ${CAPTURE_DIR}`,
  );
  if (failed.length > 0) {
    console.error(`[harness-smoke] FAILED: ${failed.map((report) => report.name).join(", ")}`);
    return 1;
  }
  if (options.requireAny && connected.length === 0) {
    console.error(
      "[harness-smoke] FAILED: --require-any set but no harness completed a live MCP connection",
    );
    return 1;
  }
  return 0;
}

if (import.meta.main) {
  process.exit(main());
}
