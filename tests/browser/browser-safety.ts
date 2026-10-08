// Shared isolated-browser guard for the NON-HEADLESS --load-extension suites
// (ext_test, security_browser_test). A non-headless launch of the user's real
// browser can capture and then CLOSE their session on cleanup, so these suites
// must run only against an isolated Chrome for Testing.
//
// Identity, not path: a path check (even realpath) can be defeated by copying
// or renaming a real browser into a trusted-looking location. Instead we ask
// the binary itself: `CHROME_BIN --version`. Chrome for Testing reports
// "Google Chrome for Testing <ver>" and the headless shell reports a
// "HeadlessShell" build; a daily Chrome/Brave/Chromium reports its own name and
// is refused on the host (the container rule below is the one exception). This is identification (does this binary self-report as CfT?),
// not adversarial authentication: a deliberately hostile wrapper could print an
// accepted string and then launch a real browser. It exists to stop an
// ACCIDENTAL real-browser launch (an unset or wrong CHROME_BIN), which is the
// documented failure mode. --version prints and exits without opening a window
// or loading a profile.

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ISOLATED_VERSION = /Chrome for Testing|HeadlessShell/;

// Inside a container no browser can hold the user's session, so a distro Chromium (`Chromium <ver>
// built on Debian ...`, the container image's browser) is isolated by construction there, and only there.
// The engines' own marker files are the evidence (Docker, then Podman); the host has neither, so the
// host-side rule above is unchanged, and no env var or path can stand in for the marker.
const CONTAINER_MARKERS: readonly string[] = ["/.dockerenv", "/run/.containerenv"];
const CONTAINER_VERSION = /^Chromium\b/;

/** The unpacked extension bundle the browser suites load: the built
 * chrome-mv3 output by default, overridable with GENKAN_EXT_DIR. One home for
 * the env var name and the default path, so a custom GENKAN_EXT_DIR (or a moved
 * build output) applies to every suite at once instead of whichever files
 * happened to keep their copy current. */
export function extensionDir(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  return (
    process.env.GENKAN_EXT_DIR || join(resolve(here, "../.."), "build", "extension", "chrome-mv3")
  );
}

/** The isolation verdict for one binary, by its own --version. */
export function isolatedBrowser(
  bin: string,
  containerMarkers: readonly string[] = CONTAINER_MARKERS,
): string | null {
  let version = "";
  try {
    version = execFileSync(bin, ["--version"], { encoding: "utf8", timeout: 10000 }).trim();
  } catch {
    return null; // not runnable / not a browser
  }
  if (ISOLATED_VERSION.test(version)) return bin;
  const inContainer = containerMarkers.some((marker) => existsSync(marker));
  return inContainer && CONTAINER_VERSION.test(version) ? bin : null;
}

/** The environment a real-host suite runs the binary under: a throwaway runtime dir, config dir and HOME
 * under `work` (LOCALAPPDATA is what the binary reads on Windows), created here, plus the log settings the
 * suites parse (an inherited GENKAN_LOG=warn would hide the Info-level session lines). */
export function throwawayHostEnv(work: string): Record<string, string> {
  const dirs = {
    XDG_RUNTIME_DIR: join(work, "runtime"),
    XDG_CONFIG_HOME: join(work, "config"),
    HOME: join(work, "home"),
    LOCALAPPDATA: join(work, "localappdata"),
  };
  for (const dir of Object.values(dirs)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  return { ...process.env, ...dirs, GENKAN_LOG: "info", GENKAN_LOG_FORMAT: "text" } as Record<
    string,
    string
  >;
}

/** Write the native-messaging host wrapper for `bin` into `dir` and return its path. Chrome passes a host no
 * arguments and its own environment, so the wrapper sets the throwaway dirs from `env` itself: whichever
 * Chrome spawns it runs the binary there. A shell script on Unix, a .cmd on Windows (Chrome runs both). */
export function writeHostWrapper(
  dir: string,
  bin: string,
  args: readonly string[],
  env: Record<string, string>,
): string {
  const names = [
    "XDG_RUNTIME_DIR",
    "XDG_CONFIG_HOME",
    "HOME",
    "LOCALAPPDATA",
    "GENKAN_LOG",
    "GENKAN_LOG_FORMAT",
  ];
  if (process.platform === "win32") {
    const wrapper = join(dir, "run-host.cmd");
    const sets = names.map((name) => `set "${name}=${env[name]}"`).join("\r\n");
    writeFileSync(wrapper, `@echo off\r\n${sets}\r\n"${bin}" ${args.join(" ")}\r\n`);
    return wrapper;
  }
  const wrapper = join(dir, "run-host.sh");
  const exports = names.map((name) => `export ${name}="${env[name]}"`).join("\n");
  writeFileSync(wrapper, `#!/bin/sh\n${exports}\nexec "${bin}" ${args.join(" ")}\n`, {
    mode: 0o755,
  });
  return wrapper;
}

/** Whether `lockPath`, the lock the binary says it resolves under a suite's environment, sits inside the
 * suite's throwaway `work` dir. A real-host suite refuses to run otherwise: outside that dir the binary
 * would run in the user's live runtime dir, where the host unlinks the existing socket before binding. */
export function runtimeDirIsolated(lockPath: string, work: string): boolean {
  const rel = relative(resolve(work), resolve(lockPath));
  return rel !== "" && !rel.startsWith("..") && !isAbsolute(rel);
}

/** The lock `bin` resolves under `env`, read off `doctor --paths` (which touches nothing) and required to sit
 * inside the suite's throwaway `work` dir. Throws the reason a real-host suite refuses to run on: a probe
 * naming anything but exactly one run.lock, or a lock outside `work`, the user's live runtime dir. Every
 * suite that runs the real binary calls this before the binary's first write. */
export function assertHostIsolated(bin: string, env: Record<string, string>, work: string): string {
  const report = execFileSync(bin, ["doctor", "--paths"], {
    env,
    encoding: "utf8",
    timeout: 15000,
  });
  const lines = report.split("\n").filter((line) => line.startsWith("lock file:"));
  const lock = lines.length === 1 ? (lines[0] ?? "").slice("lock file:".length).trim() : "";
  if (lines.length !== 1 || basename(lock) !== "run.lock") {
    throw new Error(`doctor --paths did not name exactly one run.lock:\n${report}`);
  }
  if (!runtimeDirIsolated(lock, work)) {
    throw new Error(`the binary resolves its lock to ${lock}, outside ${work}`);
  }
  return lock;
}

/** Returns the isolated browser path, or null if CHROME_BIN is unset or does
 * not identify as an isolated browser. */
export function isolatedBrowserOrNull(): string | null {
  const bin = process.env.CHROME_BIN;
  return bin ? isolatedBrowser(bin) : null;
}

/** Exit(0) with a SKIP message unless CHROME_BIN identifies as isolated.
 *
 * GENKAN_REQUIRE_BROWSER=1 (set by CI) turns the skip into a hard failure: in CI
 * the suite must actually run, so a CHROME_BIN that stops identifying as an
 * isolated Chrome for Testing has to make the job red, never silently green.
 * The variable only ever makes the guard stricter - no value lets a
 * non-isolated browser through. */
export function assertIsolatedBrowserOrSkip(): string {
  const bin = isolatedBrowserOrNull();
  if (!bin) {
    const reason =
      "refusing to launch a browser that does not identify as an isolated\n" +
      "Chrome for Testing (checked via `--version`). A non-headless\n" +
      "--load-extension launch of a real browser can capture and close your\n" +
      "session. Install one and point CHROME_BIN at it, e.g.:\n" +
      "  bunx @puppeteer/browsers install chrome@stable --path tests/.chrome-for-testing\n" +
      "(see tests/README.md -> Safety).";
    if (process.env.GENKAN_REQUIRE_BROWSER === "1") {
      console.error(`FAIL (GENKAN_REQUIRE_BROWSER=1, the suite must run): ${reason}`);
      process.exit(1);
    }
    console.log(`SKIP: ${reason}`);
    process.exit(0);
  }
  return bin;
}

// A green browser step must mean the suite really asserted something: the guard above can exit(0) as a local skip, and
// GENKAN_REQUIRE_BROWSER only hardens it while both sides spell that variable the same way. So every suite finishes through
// finishSuite(): a zero-pass run fails, and under GENKAN_BROWSER_CANARY_DIR a per-suite RAN marker is dropped that a final
// CI step requires, so a skip anywhere upstream turns the job red no matter which env var drifted.

/** The exit code a finished suite deserves: nonzero on any failed check AND
 * on a vacuous run that passed zero checks. */
export function suiteExitCode(pass: number, fail: number): number {
  return fail > 0 || pass === 0 ? 1 : 0;
}

/** One-line marker body, also used as the printed summary. */
export function ranMarkerBody(suite: string, pass: number, fail: number): string {
  return `${suite}: ${pass} passed, ${fail} failed`;
}

/** Write the RAN marker for a suite when a canary dir is configured. Returns
 * the marker path, or null when no dir is set (local runs). */
export function writeRanMarker(
  suite: string,
  pass: number,
  fail: number,
  dir: string | undefined = process.env.GENKAN_BROWSER_CANARY_DIR,
): string | null {
  if (!dir) return null;
  mkdirSync(dir, { recursive: true });
  const marker = join(dir, suite);
  writeFileSync(marker, `${ranMarkerBody(suite, pass, fail)}\n`);
  return marker;
}

/** Print the summary, drop the RAN marker, and exit with the suite's verdict.
 * Every browser suite ends here instead of hand-rolling its exit. */
export function finishSuite(suite: string, pass: number, fail: number): never {
  console.log(`\n${"=".repeat(50)}\n${ranMarkerBody(suite, pass, fail)}`);
  if (pass === 0 && fail === 0) {
    console.error(`FAIL: ${suite} finished without running a single check (vacuous pass)`);
  }
  writeRanMarker(suite, pass, fail);
  process.exit(suiteExitCode(pass, fail));
}
