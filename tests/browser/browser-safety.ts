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
// is refused. This is identification (does this binary self-report as CfT?),
// not adversarial authentication: a deliberately hostile wrapper could print an
// accepted string and then launch a real browser. It exists to stop an
// ACCIDENTAL real-browser launch (an unset or wrong CHROME_BIN), which is the
// documented failure mode. --version prints and exits without opening a window
// or loading a profile.

import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const ISOLATED_VERSION = /Chrome for Testing|HeadlessShell/;

/** Returns the isolated browser path, or null if CHROME_BIN is unset or does
 * not identify (by its own --version) as an isolated Chrome for Testing. */
export function isolatedBrowserOrNull(): string | null {
  const bin = process.env.CHROME_BIN;
  if (!bin) return null;
  let version = "";
  try {
    version = execFileSync(bin, ["--version"], { encoding: "utf8", timeout: 10000 }).trim();
  } catch {
    return null; // not runnable / not a browser
  }
  return ISOLATED_VERSION.test(version) ? bin : null;
}

/** Exit(0) with a SKIP message unless CHROME_BIN identifies as isolated.
 *
 * BB_REQUIRE_BROWSER=1 (set by CI) turns the skip into a hard failure: in CI
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
    if (process.env.BB_REQUIRE_BROWSER === "1") {
      console.error(`FAIL (BB_REQUIRE_BROWSER=1, the suite must run): ${reason}`);
      process.exit(1);
    }
    console.log(`SKIP: ${reason}`);
    process.exit(0);
  }
  return bin;
}

// ---------------------------------------------------------------------------
// Suite-ran canary: a green browser step must mean the suite really asserted
// something. The guard above can exit(0) as a local skip, and BB_REQUIRE_BROWSER
// only hardens it while BOTH sides keep spelling that variable the same way -
// if the names ever part, CI's browser job would go silently green on skips.
// So every suite finishes through finishSuite(): it refuses a zero-pass run
// (a suite that asserted nothing is a failure, not a pass) and, when CI sets
// BB_BROWSER_CANARY_DIR, drops a per-suite RAN marker that a final job step
// requires - a skip anywhere upstream leaves no marker and turns the job red
// no matter which env var drifted.
// ---------------------------------------------------------------------------

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
  dir: string | undefined = process.env.BB_BROWSER_CANARY_DIR,
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
