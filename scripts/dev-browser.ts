#!/usr/bin/env bun
// Dev browser lane for `moon run dev` (spawned by scripts/dev.ts): this
// process OWNS the throwaway dev browser through web-ext-run - the same
// launcher WXT would use - so a browser the developer quits or that crashes
// relaunches from web-ext-run's own registerCleanup callback. No ps polling,
// no command-line fingerprint, no parent-chain walk, no stdin key injection
// into WXT.
//
// WXT builds, serves, and reloads the extension but no longer opens the
// browser (webExt.disabled in src/apps/extension/wxt.config.ts). Its file-save
// reload runs over WXT's dev-server websocket from inside the loaded
// extension, independent of who launched Chrome, so nothing here drives
// reloads (noReload).
//
// Isolation (the browser-safety red line): this config sets NO chromiumProfile
// and NO keepProfileChanges, so web-ext-run hands Chrome a FRESH temporary
// --user-data-dir on every (re)launch - the dev browser can never open a real
// profile. assertFreshTempProfile fails closed if a future edit regresses
// that. Load path: branded Chrome 137+ dropped --load-extension, so
// web-ext-run loads the unpacked build over CDP behind
// --enable-unsafe-extension-debugging; we keep that path (target "chromium",
// no profile/user-data-dir args).

import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { PINNED_EXTENSION_ID } from "../src/packages/shared/src/identity.gen";
import { repoRoot } from "./lib.ts";

// WXT's serve (dev) mode writes to <outDir>/<target>-dev - the `-dev` suffix
// distinguishes it from the production `chrome-mv3` build, and only this dev
// output carries WXT's dev-server reload client. wxt.config.ts sets
// outDir=build/extension, target chrome-mv3, so the dev browser must load this.
const extensionOut = join(repoRoot, "build/extension/chrome-mv3-dev");

type DevBrowserConfig = {
  target: "chromium";
  sourceDir: string;
  startUrl: string[];
  chromiumPref: Record<string, unknown>;
  args: string[];
  chromiumBinary?: string;
  noReload: true;
  noInput: true;
};

// Rebuilt per launch so every relaunch is a clean, identical start.
const devBrowserConfig = (): DevBrowserConfig => ({
  target: "chromium",
  sourceDir: extensionOut,
  // Docs tab, started alongside dev by the [web] lane. Best-effort: on
  // extension-only dev, or when astro falls back off 4321, the tab just misses
  // it - it is a convenience, not something dev correctness depends on.
  startUrl: ["http://localhost:4321/chromium-bridge/"],
  // Pin our toolbar icon (untracked pref; verified it survives Chrome's
  // preference rewrite). extensions.ui.developer_mode is TRACKED (hash-guarded)
  // and cannot be preseeded - dev needs it only for the chrome://extensions UI
  // toggle, which the CDP load path does not require. The devtools entry
  // mirrors WXT's default (silences a devtools self-XSS sync warning).
  chromiumPref: {
    "extensions.pinned_extensions": [PINNED_EXTENSION_ID],
    devtools: {
      synced_preferences_sync_disabled: {
        skipContentScripts: false,
        "skip-content-scripts": false,
      },
    },
  },
  args: ["--unsafely-disable-devtools-self-xss-warnings"],
  // Honor CHROME_BIN so a developer can pin the dev browser to an isolated
  // Chrome for Testing (the repo's browser-safety convention); unset falls
  // back to web-ext-run's own chrome-launcher detection, unchanged from before.
  chromiumBinary: process.env.CHROME_BIN || undefined,
  noReload: true, // WXT reloads over its websocket; web-ext must not watch/reload
  noInput: true, // non-interactive: no web-ext stdin/keypress handling
});

// FAIL CLOSED: the dev browser must never reuse or persist a real profile. The
// config above sets none of these, but assert on the resolved object so a
// future edit that adds one refuses to launch instead of opening a real
// profile.
const assertFreshTempProfile = (cfg: DevBrowserConfig & Record<string, unknown>) => {
  const problems: string[] = [];
  if (cfg.chromiumProfile) problems.push("chromiumProfile reuses a profile");
  if (cfg.keepProfileChanges) problems.push("keepProfileChanges persists a profile");
  for (const arg of cfg.args) {
    if (/^--(user-data-dir|profile-directory)\b/.test(arg)) {
      problems.push(`arg "${arg}" smuggles a profile`);
    }
  }
  if (problems.length > 0) {
    throw new Error(`refusing to launch the dev browser: ${problems.join("; ")}`);
  }
};

let shuttingDown = false;
// The lane starts with dev.ts, before WXT's first serve-mode build.
const startedAt = Date.now();
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// Wait for WXT's fresh, SETTLED build. No browser is spawned here, so a slow or
// mid-write build costs nothing but time - ALL the waiting/retrying happens
// BEFORE any browser exists. "Fresh": the manifest's mtime is at or after this
// lane's start, so a chrome-mv3-dev/ left by a PREVIOUS session is ignored
// (WXT wipes and rebuilds it at startup). "Settled": it is parseable and has
// been unchanged for a moment, so we never hand web-ext-run a directory WXT is
// still writing. Returns false on timeout or shutdown.
const SETTLE_MS = 400;
const waitForSettledBuild = async (deadline: number): Promise<boolean> => {
  const manifest = join(extensionOut, "manifest.json");
  while (!shuttingDown) {
    try {
      const { mtimeMs } = statSync(manifest);
      const parsed = JSON.parse(readFileSync(manifest, "utf8")) as Record<string, unknown>;
      if (mtimeMs >= startedAt && parsed.manifest_version && Date.now() - mtimeMs >= SETTLE_MS) {
        return true;
      }
    } catch {
      // missing, stale, or mid-write (WXT rebuild in progress) - keep waiting
    }
    if (Date.now() > deadline) return false;
    await sleep(250);
  }
  return false;
};

// Hold the event loop open across the brief window between a browser closing
// and its relaunch, when no Chromium handle is active.
const keepAlive = setInterval(() => {}, 60_000);

type Runner = {
  registerCleanup(fn: () => void): void;
  exit(): Promise<void>;
  run(): Promise<void>;
};

// web-ext-run's cmd.run does NOT return its runner if it rejects (or hangs)
// AFTER spawning Chrome (e.g. the extension fails to load over CDP), which
// would leave a browser we could not close. So we capture the runner at
// CONSTRUCTION through web-ext's own injectable MultiExtensionRunner - a
// documented extension seam, not a monkeypatch - and publish it to the module
// `activeBrowser` immediately, BEFORE cmd.run can hang or reject. That single
// global handle is always reachable by shutdown. This class wraps the single
// chromium runner web-ext builds and mirrors the parts of its
// MultiExtensionRunner that cmd.run and we use (run, exit, registerCleanup).
// Everything it closes is closed by the pid web-ext recorded, so it never
// signals a process this lane did not spawn.
let activeBrowser: CapturingRunner | null = null;
class CapturingRunner {
  #runners: Runner[];
  #closePromise: Promise<void> | null = null;
  constructor(params: { runners: unknown[] }) {
    // web-ext builds each runner (here, the single chromium runner) and passes
    // them in; they carry the run/exit/registerCleanup surface we rely on.
    this.#runners = params.runners as Runner[];
    activeBrowser = this;
  }
  getName(): string {
    return "chromium-bridge dev runner";
  }
  async run(): Promise<void> {
    // Force chrome-launcher's handleSIGINT off. By default it installs its own
    // SIGINT handler that killAll()s (signalling stale registry instances by a
    // possibly-recycled pid) and process.exit(130)s, bypassing this lane's
    // orderly teardown. This lane owns its signals. We wrap each chromium
    // runner's own chromiumLaunch (which IS chrome-launcher's launch), adding
    // the opt; a no-op if web-ext renamed the field.
    for (const r of this.#runners) {
      const patchable = r as unknown as {
        chromiumLaunch?: (opts: Record<string, unknown>) => unknown;
      };
      const inner = patchable.chromiumLaunch;
      if (typeof inner === "function") {
        patchable.chromiumLaunch = (opts) => inner({ ...opts, handleSIGINT: false });
      }
    }
    await Promise.all(this.#runners.map((r) => r.run()));
  }
  registerCleanup(cb: () => void): void {
    const done = this.#runners.map(
      (r) => new Promise<void>((resolve) => r.registerCleanup(resolve)),
    );
    Promise.all(done).then(cb, cb);
  }
  // Close the browser for teardown, once. Memoized so the launch path and
  // shutdown that race each other await the SAME close (no double-kill, and
  // shutdown cannot process.exit while a close it did not start is mid-flight).
  // exit() closes Chrome by the pid chrome-launcher recorded but first awaits
  // web-ext's setup; bound that so a hung CDP handshake cannot stall teardown,
  // then fall back to a direct kill by the same recorded pid.
  close(): Promise<void> {
    this.#closePromise ??= (async () => {
      await Promise.race([this.#exit().catch(() => {}), sleep(8_000)]);
      // Direct kill by the pid chrome-launcher recorded, WITHOUT awaiting
      // web-ext's setup. A no-op if the instance is not up yet or web-ext
      // renamed the field, in which case the exit() above is the closer.
      for (const r of this.#runners) {
        (r as { chromiumInstance?: { kill(): unknown } | null }).chromiumInstance?.kill();
      }
    })();
    return this.#closePromise;
  }
  #exit(): Promise<void> {
    return Promise.all(this.#runners.map((r) => r.exit())).then(() => undefined);
  }
}

let launching = false;
// The most recent in-flight launch(), so shutdown() can wait for it to publish
// its handle (via the constructor) before closing.
let launchInFlight: Promise<void> | null = null;

const launch = async (): Promise<void> => {
  if (shuttingDown || launching) return;
  launching = true;
  try {
    const cfg = devBrowserConfig();
    assertFreshTempProfile(cfg);
    const { default: webExt } = await import("web-ext-run");
    if (!(await waitForSettledBuild(Date.now() + 120_000))) {
      if (!shuttingDown) {
        console.error("[browser] no settled extension build appeared; the browser lane is exiting");
        clearInterval(keepAlive);
        process.exit(1);
      }
      return;
    }
    if (shuttingDown) return;
    // A single spawn, never retried: web-ext validates the manifest and only
    // then launches Chrome, so once the settled build is ready this succeeds.
    // Retrying could double-spawn a browser. The CapturingRunner constructor
    // publishes the handle to activeBrowser before this resolves or rejects.
    const started = (await webExt.cmd.run(cfg, {
      shouldExitProgram: false,
      MultiExtensionRunner: CapturingRunner,
    })) as unknown as CapturingRunner;
    if (shuttingDown) {
      await started.close();
      return;
    }
    console.log("[browser] dev browser open (fresh temp profile).");
    // Relaunch when the developer quits the browser or it crashes: web-ext-run
    // fires its cleanup callbacks when the Chromium instance exits.
    started.registerCleanup(() => {
      if (activeBrowser !== started) return; // already torn down or superseded
      activeBrowser = null;
      if (shuttingDown) return;
      console.log("[browser] dev browser closed, relaunching...");
      launchInFlight = launch();
    });
  } catch (error) {
    // cmd.run can spawn Chrome and THEN reject; activeBrowser (published by the
    // CapturingRunner constructor, before the rejection) is our handle to close
    // that browser by its recorded pid, so a post-spawn failure cannot orphan.
    if (activeBrowser) await activeBrowser.close();
    if (!shuttingDown) {
      console.error(`[browser] failed to launch the dev browser: ${(error as Error).message}`);
      clearInterval(keepAlive);
      process.exit(1);
    }
  } finally {
    launching = false;
  }
};

const shutdown = async (): Promise<void> => {
  if (shuttingDown) return;
  shuttingDown = true;
  clearInterval(keepAlive);
  // Let an in-flight launch progress far enough to publish its handle (the
  // CapturingRunner constructor sets activeBrowser), bounded so a hung cmd.run
  // cannot stall teardown - the constructor runs early, so the handle is
  // published well before any hang.
  await Promise.race([launchInFlight ?? Promise.resolve(), sleep(5_000)]).catch(() => {});
  // Close the browser (live or mid-launch) by the pid web-ext-run recorded -
  // never a pattern match. close() is memoized, so if the launch path is
  // already closing it, this awaits that same close before we exit.
  const browser = activeBrowser;
  activeBrowser = null;
  if (browser) await browser.close();
  process.exit(0);
};
process.on("SIGTERM", () => void shutdown());
process.on("SIGINT", () => void shutdown());

launchInFlight = launch();
