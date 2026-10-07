#!/usr/bin/env bun
// Dev orchestrator for `moon run dev`: every dev surface at once, one terminal.
//
//   - extension (WXT):        FOREGROUND - real terminal output + live stdin
//   - the landing page (Astro):      background, output prefixed [web]
//   - dev browser:            background, output prefixed [browser]
//
// Why not `bun run --filter '*' dev`? The filter runner closes each child's
// stdin; WXT's readline-based key listener hits EOF and shuts the dev server
// down seconds after launch. WXT needs a live stdin for its keyboard shortcuts
// (r to reload, Ctrl-C to quit). Only one child can own the terminal, so the
// site and the browser lane run backgrounded with prefixed, non-interactive
// output.

import { type ChildProcess, execFileSync, spawn } from "node:child_process";
import { join } from "node:path";
import { repoRoot } from "./lib.ts";

const webDir = join(repoRoot, "src/apps/web");
const extensionDir = join(repoRoot, "src/apps/extension");

const prefixLines = (label: string, chunk: unknown) =>
  String(chunk)
    .split("\n")
    .filter((line) => line.trim())
    .map((line) => `[${label}] ${line}`)
    .join("\n");
const pipePrefixed = (child: ChildProcess, label: string) => {
  child.stdout?.on("data", (chunk) => console.log(prefixLines(label, chunk)));
  child.stderr?.on("data", (chunk) => console.error(prefixLines(label, chunk)));
};

// Detached so shutdown can signal the WHOLE group: `bun run dev` wraps the real `astro dev`, and
// killing just the wrapper's pid orphans astro, which then squats on its port across sessions.
// The dev script's ASTRO_DEV_BACKGROUND=1 marks the process as ALREADY backgrounded, so Astro 7
// skips its auto-daemonization and runs the server inside this child: logs stay on our pipe, the
// server stays in this group, and astro still writes the lockfile.
//   astro dev stop / status  -> read that lockfile and work
//   astro dev logs           -> reads the daemon log file this mode never creates; the logs are HERE
const web = spawn("bun", ["run", "dev"], {
  cwd: webDir,
  stdio: ["ignore", "pipe", "pipe"],
  detached: true,
});
pipePrefixed(web, "web");

let webKilled = false;
const killWeb = () => {
  // One-shot: the signal handler and WXT's exit handler both call this, and
  // a second `astro dev stop` would stall shutdown for up to 10 more seconds.
  if (webKilled) return;
  webKilled = true;
  // Signal the group first (negative pid = wrapper AND the astro server,
  // which ASTRO_DEV_BACKGROUND pins into this group): the stop below can
  // block for up to 10s, and if this process is force-killed while it runs,
  // the group must already be down.
  if (web.pid !== undefined) {
    try {
      process.kill(-web.pid, "SIGTERM");
    } catch {
      // Group already gone; nothing to clean up.
    }
  }
  // Belt and braces: `astro dev stop` reads Astro's lockfile and stops
  // whatever it names (SIGTERM, then SIGKILL after 5s), covering a server
  // that somehow escaped the group, and clears the lockfile so the next
  // start is clean.
  try {
    // `bun run` reaches the workspace's own astro; bunx would answer from bun's global cache without it.
    execFileSync("bun", ["run", "astro", "dev", "stop"], {
      cwd: webDir,
      stdio: "ignore",
      timeout: 10_000,
    });
  } catch {
    // No server running, or stop timed out; the group signal already applied.
  }
};

// WXT owns the terminal: stdout and stderr inherited, stdin piped so `r` and Ctrl-C reach it. Detached because
// the chain is bun wrapper -> bash -c -> node wxt, and bash dies on SIGTERM without forwarding it; the group
// signal reaches node wxt, whose own handlers close its dev server.
const wxt = spawn("bun", ["run", "dev"], {
  cwd: extensionDir,
  stdio: ["pipe", "inherit", "inherit"],
  detached: true,
});
if (wxt.stdin) {
  process.stdin.pipe(wxt.stdin, { end: false });
  // A forwarded keystroke can race WXT's own exit; without a handler that
  // EPIPE would crash the orchestrator mid-shutdown.
  wxt.stdin.on("error", () => {});
}

// Detached so one group signal tears down the lane AND the Chromium it spawned; the lane's SIGTERM handler
// closes Chrome by the pid chrome-launcher recorded.
const browser = spawn("bun", [join(repoRoot, "scripts/dev-browser.ts")], {
  cwd: repoRoot,
  stdio: ["ignore", "pipe", "pipe"],
  detached: true,
});
pipePrefixed(browser, "browser");
let browserKilled = false;
const killBrowser = () => {
  if (browserKilled) return;
  browserKilled = true;
  if (browser.pid !== undefined) {
    try {
      process.kill(-browser.pid, "SIGTERM");
    } catch {
      // Group already gone; the lane closes its own browser on exit.
    }
  }
};

let shuttingDown = false;
let startFailed = false;

const killWxt = () => {
  // Group signal (negative pid): SIGTERM to just the bun wrapper never
  // reaches node wxt (bash -c between them swallows it).
  if (wxt.pid !== undefined) {
    try {
      process.kill(-wxt.pid, "SIGTERM");
      return;
    } catch {
      // Group already gone; fall through to the plain kill.
    }
  }
  wxt.kill("SIGTERM");
};

const shutdown = () => {
  shuttingDown = true;
  // All the fast group signals first; killWeb ends with the potentially
  // slow, synchronous `astro dev stop`.
  killBrowser();
  killWxt();
  killWeb();
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

const spawnFailed = (name: string) => (error: Error) => {
  startFailed = true;
  console.error(`[dev] failed to start ${name}: ${error.message}`);
  shutdown();
};
web.on("error", spawnFailed("the landing page"));
wxt.on("error", (error: Error) => {
  // A wxt spawn failure never emits "exit", so the exit handler below cannot
  // finish the job - clean up and leave directly.
  spawnFailed("the extension dev server")(error);
  process.exit(1);
});

wxt.on("exit", (code, signal) => {
  killBrowser();
  killWeb();
  if (startFailed) process.exit(1);
  // Signal-terminated during our own shutdown is a clean stop; a signal from
  // anywhere else means dev died under us and the caller should see failure.
  if (shuttingDown) process.exit(code ?? 0);
  process.exit(code ?? (signal ? 1 : 0));
});
browser.on("error", (error: Error) =>
  console.error(`[browser] failed to start the dev browser lane: ${error.message}`),
);
browser.on("exit", (code) => {
  // Its process group is gone; mark it killed so a later killBrowser() never
  // signals -browser.pid after the OS may have recycled that pid as another
  // group's leader.
  const alreadyHandled = browserKilled;
  browserKilled = true;
  if (alreadyHandled || shuttingDown) return;
  const how = code === null ? "on a signal" : `with code ${code}`;
  console.error(`[browser] dev browser lane exited ${how}; extension and site keep running`);
});
web.on("exit", (code) => {
  if (!webKilled && code !== 0 && code !== null) {
    console.error(`[web] exited with code ${code}`);
  }
});
