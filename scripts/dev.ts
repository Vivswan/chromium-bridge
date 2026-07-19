#!/usr/bin/env bun
// Dev orchestrator for `just dev`: runs the docs site (Astro) in the
// background and the extension (WXT) in the foreground with the real
// terminal attached.
//
// Why not `bun run --filter '*' dev`? The filter runner closes each child's
// stdin; WXT's readline-based key listener hits EOF and shuts the dev server
// down seconds after launch. WXT needs a live stdin (its `o` + enter shortcut
// reopens the dev browser).
//
// The desktop app's dev loop (tauri) stays separate: `just app-dev`.

import { execFileSync, spawn } from "node:child_process";
import { join } from "node:path";
import { repoRoot } from "./lib.ts";

const siteDir = join(repoRoot, "docs/site");
const extensionDir = join(repoRoot, "src/apps/extension");

// Site: background, output prefixed. Detached puts it in its own process
// group so shutdown can signal the WHOLE tree: `bun run dev` wraps the real
// `astro dev` process, and killing just the wrapper's pid orphans astro,
// which then squats on its port across sessions.
const site = spawn("bun", ["run", "dev"], {
  cwd: siteDir,
  stdio: ["ignore", "pipe", "pipe"],
  detached: true,
});

let siteKilled = false;
const killSite = () => {
  // One-shot: the signal handler and WXT's exit handler both call this, and
  // a second `astro dev stop` would stall shutdown for up to 10 more seconds.
  if (siteKilled) return;
  siteKilled = true;
  // Signal the group first (negative pid = wrapper AND a foreground astro):
  // the daemon stop below can block for up to 10s, and if this process is
  // force-killed while it runs, the group must already be down.
  if (site.pid !== undefined) {
    try {
      process.kill(-site.pid, "SIGTERM");
    } catch {
      // Group already gone; nothing to clean up.
    }
  }
  // Astro 7 daemonizes `astro dev` whenever it detects an AI coding agent
  // (CLAUDECODE, Copilot terminals, Cursor, ...), so the real server may not
  // be in the child's process group at all. `astro dev stop` reads Astro's
  // lockfile and stops either flavor (SIGTERM, then SIGKILL after 5s).
  try {
    execFileSync("bunx", ["astro", "dev", "stop"], {
      cwd: siteDir,
      stdio: "ignore",
      timeout: 10_000,
    });
  } catch {
    // No server running, or stop timed out; the group signal already applied.
  }
};

const prefixed = (chunk: unknown) =>
  String(chunk)
    .split("\n")
    .filter((line) => line.trim())
    .map((line) => `[site] ${line}`)
    .join("\n");
site.stdout?.on("data", (chunk) => console.log(prefixed(chunk)));
site.stderr?.on("data", (chunk) => console.error(prefixed(chunk)));

// Extension: foreground with the real terminal for output; stdin is piped so
// the browser watchdog below can inject WXT's `o` (reopen) keypress. Your own
// keystrokes are forwarded through, so the shortcut still works by hand.
// Detached for the same reason as the site: the chain is bun wrapper ->
// bash -c -> node wxt, and bash dies on SIGTERM WITHOUT forwarding it, which
// orphans node wxt and leaves the dev browser open (observed). Signaling the
// group reaches node wxt, whose own handlers close the browser.
const wxt = spawn("bun", ["run", "dev"], {
  cwd: extensionDir,
  stdio: ["pipe", "inherit", "inherit"],
  detached: true,
});
if (wxt.stdin) {
  process.stdin.pipe(wxt.stdin, { end: false });
  // A watchdog write can race WXT's own exit; without a handler that EPIPE
  // would crash the orchestrator mid-shutdown.
  wxt.stdin.on("error", () => {});
}

// Browser watchdog: WXT never reopens the dev browser on its own. Quitting
// Chrome (cmd-Q) or a crash leaves dev running headless until someone types
// `o`. Poll for the dev browser and, on an alive -> gone transition, press
// `o` automatically. WXT 0.20 only attaches its stdin listener after the
// first file-watcher event, so a press that lands before then stays buffered
// in the pipe and the reopen happens with your next file save - verified, not
// lost.
//
// This repo configures no persistent chromiumProfile, so web-ext-run gives
// the dev browser a fresh temporary --user-data-dir on every (re)open - there
// is no fixed profile path to poll for. Instead a process is counted as OUR
// dev browser only if BOTH hold: its command line carries the flag pair
// web-ext-run always launches with (--remote-debugging-pipe plus
// --enable-unsafe-extension-debugging - no normal browser session has them),
// AND its parent chain leads back to our wxt child, so someone else's WXT
// project dev-ing on this machine is never mistaken for ours. Read-only ps;
// nothing here ever signals a browser process. Returns null when ps itself
// fails, so one bad scan reads as "unknown", never as "gone".
const devBrowserAlive = (rootPid: number): boolean | null => {
  let table: string;
  try {
    table = execFileSync("ps", ["-axo", "pid=,ppid=,command="], { encoding: "utf8" });
  } catch {
    return null;
  }
  const parentOf = new Map<number, number>();
  const candidates: number[] = [];
  for (const row of table.split("\n")) {
    const m = row.match(/^\s*(\d+)\s+(\d+)\s+(.*)$/);
    if (!m) continue;
    const pid = Number(m[1]);
    const ppid = Number(m[2]);
    const command = m[3] ?? "";
    parentOf.set(pid, ppid);
    if (
      command.includes("--remote-debugging-pipe") &&
      command.includes("--enable-unsafe-extension-debugging")
    ) {
      candidates.push(pid);
    }
  }
  return candidates.some((pid) => {
    // Walk up the parent chain; hop cap guards against a cycle in a torn read.
    for (let p = pid, hops = 0; p > 1 && hops < 32; hops++) {
      if (p === rootPid) return true;
      const parent = parentOf.get(p);
      if (parent === undefined) return false;
      p = parent;
    }
    return false;
  });
};

let shuttingDown = false;
let startFailed = false;
let wasAlive = false;
const watchdog = setInterval(() => {
  if (shuttingDown || wxt.pid === undefined || wxt.exitCode !== null) return;
  const alive = devBrowserAlive(wxt.pid);
  if (alive === null) return;
  if (wasAlive && !alive) {
    console.log("[dev] Dev browser closed, reopening...");
    if (wxt.stdin?.writable) wxt.stdin.write("o\n");
  }
  wasAlive = alive;
}, 3000);

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
  clearInterval(watchdog);
  killWxt();
  killSite();
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

const spawnFailed = (name: string) => (error: Error) => {
  startFailed = true;
  console.error(`[dev] failed to start ${name}: ${error.message}`);
  shutdown();
};
site.on("error", spawnFailed("the docs site"));
wxt.on("error", (error: Error) => {
  // A wxt spawn failure never emits "exit", so the exit handler below cannot
  // finish the job - clean up and leave directly.
  spawnFailed("the extension dev server")(error);
  process.exit(1);
});

wxt.on("exit", (code, signal) => {
  clearInterval(watchdog);
  killSite();
  if (startFailed) process.exit(1);
  // Signal-terminated during our own shutdown is a clean stop; a signal from
  // anywhere else means dev died under us and the caller should see failure.
  if (shuttingDown) process.exit(code ?? 0);
  process.exit(code ?? (signal ? 1 : 0));
});
site.on("exit", (code) => {
  if (code !== 0 && code !== null) console.error(`[site] exited with code ${code}`);
});
