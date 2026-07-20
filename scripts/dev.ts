#!/usr/bin/env bun
// Dev orchestrator for `moon run dev`: every dev surface at once, one terminal.
//
//   - extension (WXT):        FOREGROUND - real terminal output + live stdin
//   - docs site (Astro):      background, output prefixed [web]
//   - desktop app (tauri):    background, output prefixed [app]
//
// Why not `bun run --filter '*' dev`? The filter runner closes each child's
// stdin; WXT's readline-based key listener hits EOF and shuts the dev server
// down seconds after launch. WXT needs a live stdin for its keyboard shortcuts
// (r to reload, Ctrl-C to quit). Only one child can own the terminal, so the
// site, the app, and the browser lane run backgrounded with prefixed,
// non-interactive output.
//
// `moon run dev-app` remains the app-only convenience loop.

import { type ChildProcess, execFileSync, spawn } from "node:child_process";
import { join } from "node:path";
import { repoRoot } from "./lib.ts";

const webDir = join(repoRoot, "src/apps/web");
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

// Docs site: background, detached. Detached puts it in its own process group
// so shutdown can signal the WHOLE tree: `bun run dev` wraps the real
// `astro dev` process, and killing just the wrapper's pid orphans astro,
// which then squats on its port across sessions.
//
// The dev script (src/apps/web/package.json) is stop-then-start:
// `astro dev stop; ASTRO_DEV_BACKGROUND=1 astro dev`. The stop clears any
// already-running tracked server (astro exits 0 when none is running);
// ASTRO_DEV_BACKGROUND=1 then pins Astro 7's lifecycle - the variable marks
// the process as ALREADY backgrounded, so astro skips its AI-agent
// auto-daemonization and runs the server inside this child. That keeps the
// logs on our pipe (prefixed [web]) and the server inside this child's
// process group, while astro still writes the lockfile that
// `astro dev stop` / `astro dev status` read. (`astro dev logs` reads the
// daemon log file, which this mode does not create - the logs are HERE.)
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
    execFileSync("bunx", ["astro", "dev", "stop"], {
      cwd: webDir,
      stdio: "ignore",
      timeout: 10_000,
    });
  } catch {
    // No server running, or stop timed out; the group signal already applied.
  }
};

// Desktop app: background, detached; `moon run dev-app`'s steps MINUS its
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

// Extension (WXT): foreground with the real terminal so its output shows and
// its keyboard shortcuts work; stdin is piped so your keystrokes (WXT's `r`
// reload, Ctrl-C) reach it. WXT builds, serves, and reloads the extension over
// its dev-server websocket but no longer opens a browser (webExt.disabled in
// wxt.config.ts) - the [browser] lane below owns that. Detached for the same
// reason as the site: the chain is bun wrapper -> bash -c -> node wxt, and
// bash dies on SIGTERM WITHOUT forwarding it, which orphans node wxt;
// signaling the group reaches node wxt, whose own handlers close its dev
// server.
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

// Dev browser: a dedicated detached lane (scripts/dev-browser.ts) OWNS the
// throwaway dev browser through web-ext-run and relaunches it from
// web-ext-run's own cleanup callback when the developer quits it or it
// crashes - replacing the old ps-poll / command-line-fingerprint /
// parent-chain-walk / stdin-`o`-injection watchdog. Detached so one group
// signal tears down the lane AND the Chromium it spawned; the lane's own
// SIGTERM handler exits the runner, which closes Chrome by the pid
// chrome-launcher recorded. Output prefixed [browser].
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
  killApp();
  killWeb();
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

const spawnFailed = (name: string) => (error: Error) => {
  startFailed = true;
  console.error(`[dev] failed to start ${name}: ${error.message}`);
  shutdown();
};
web.on("error", spawnFailed("the docs site"));
wxt.on("error", (error: Error) => {
  // A wxt spawn failure never emits "exit", so the exit handler below cannot
  // finish the job - clean up and leave directly.
  spawnFailed("the extension dev server")(error);
  process.exit(1);
});

wxt.on("exit", (code, signal) => {
  killBrowser();
  killApp();
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
