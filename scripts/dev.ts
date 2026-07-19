#!/usr/bin/env bun
// Dev orchestrator for `just dev`: every dev surface at once, one terminal.
//
//   - extension (WXT):        FOREGROUND - real terminal output + live stdin
//   - docs site (Astro):      background, output prefixed [site]
//   - desktop app (tauri):    background, output prefixed [app]
//
// Why not `bun run --filter '*' dev`? The filter runner closes each child's
// stdin; WXT's readline-based key listener hits EOF and shuts the dev server
// down seconds after launch. WXT needs a live stdin (its `o` + enter shortcut
// reopens the dev browser). Only one child can own the terminal, so the site
// and the app run backgrounded with prefixed, non-interactive output.
//
// `just app-dev` remains the app-only convenience loop.

import { type ChildProcess, execFileSync, spawn } from "node:child_process";
import { join } from "node:path";
import { repoRoot } from "./lib.ts";

const siteDir = join(repoRoot, "docs/site");
const extensionDir = join(repoRoot, "src/apps/extension");
const appDir = join(repoRoot, "src/apps/desktop");

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

// Site: background, detached. Detached puts it in its own process group so
// shutdown can signal the WHOLE tree: `bun run dev` wraps the real
// `astro dev` process, and killing just the wrapper's pid orphans astro,
// which then squats on its port across sessions.
const site = spawn("bun", ["run", "dev"], {
  cwd: siteDir,
  stdio: ["ignore", "pipe", "pipe"],
  detached: true,
});
pipePrefixed(site, "site");

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

// Desktop app: background, detached; `just app-dev`'s steps MINUS its
// extension production build - the WXT lane fills the same build/extension
// outDir continuously, so building it here again would be wasted work. (Small
// startup race: tauri can be up before WXT's first dev build lands; the app
// just sees the extension artifacts a moment later.) The prereqs run
// first (icon rasters, then the host binary Enclave ops need as a sibling of
// the dev app), then `tauri dev`, whose beforeDevCommand starts the
// desktop-UI vite on 1420 (strictPort; no clash with astro). tauri dev fans
// out into cargo, vite, and the native app binary - none of them setsid, so
// they stay in the detached child's process group and one negative-pid
// SIGTERM reaps the whole tree. appChild always points at the lane's CURRENT
// process (a prereq or tauri), so shutdown mid-prereq kills the right group.
let appChild: ChildProcess | null = null;
let appKilled = false;
const killApp = () => {
  if (appKilled) return;
  appKilled = true;
  const child = appChild;
  if (child?.pid === undefined) return;
  // Signal the group even when the direct child already exited: its
  // descendants (vite, cargo, the app window) share the pgid and can
  // outlive it.
  try {
    process.kill(-child.pid, "SIGTERM");
  } catch {
    // Whole group already gone; nothing to clean up.
  }
};
const runAppStep = (cmd: string, args: string[], cwd: string) =>
  new Promise<number>((resolve) => {
    const child = spawn(cmd, args, { cwd, stdio: ["ignore", "pipe", "pipe"], detached: true });
    appChild = child;
    pipePrefixed(child, "app");
    child.on("error", (error) => {
      console.error(`[app] failed to start ${cmd}: ${error.message}`);
      resolve(1);
    });
    child.on("exit", (code, signal) => resolve(code ?? (signal ? 1 : 0)));
  });
const startApp = async () => {
  const prereqs: [string, string[], string][] = [
    ["bun", ["scripts/gen-icons.ts", "desktop"], repoRoot],
    ["cargo", ["build"], repoRoot],
  ];
  for (const [cmd, args, cwd] of prereqs) {
    const code = await runAppStep(cmd, args, cwd);
    if (appKilled) return;
    if (code !== 0) {
      console.error(
        `[app] prereq failed: ${cmd} ${args.join(" ")} (exit ${code}); ` +
          "desktop app lane stopped - extension and site keep running",
      );
      return;
    }
  }
  const app = spawn("bunx", ["tauri", "dev"], {
    cwd: appDir,
    stdio: ["ignore", "pipe", "pipe"],
    detached: true,
  });
  appChild = app;
  pipePrefixed(app, "app");
  app.on("error", (error) => console.error(`[app] failed to start tauri dev: ${error.message}`));
  app.on("exit", (code) => {
    if (appKilled) return;
    // The leader can die while its group (vite, cargo, the app window)
    // lives - e.g. a tauri CLI crash - and that would squat port 1420.
    // Sweep the group on any exit we did not initiate.
    if (app.pid !== undefined) {
      try {
        process.kill(-app.pid, "SIGTERM");
      } catch {
        // Whole group already gone.
      }
    }
    const how = code === null ? "on a signal" : `with code ${code}`;
    console.error(`[app] tauri dev exited ${how}; extension and site keep running`);
  });
};
void startApp();

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
  // All the fast group signals first; killSite ends with the potentially
  // slow, synchronous `astro dev stop`.
  killWxt();
  killApp();
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
  killApp();
  killSite();
  if (startFailed) process.exit(1);
  // Signal-terminated during our own shutdown is a clean stop; a signal from
  // anywhere else means dev died under us and the caller should see failure.
  if (shuttingDown) process.exit(code ?? 0);
  process.exit(code ?? (signal ? 1 : 0));
});
site.on("exit", (code) => {
  if (!siteKilled && code !== 0 && code !== null) {
    console.error(`[site] exited with code ${code}`);
  }
});
