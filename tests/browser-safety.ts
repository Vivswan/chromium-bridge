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

/** Exit(0) with a SKIP message unless CHROME_BIN identifies as isolated. */
export function assertIsolatedBrowserOrSkip(): string {
  const bin = isolatedBrowserOrNull();
  if (!bin) {
    console.log(
      "SKIP: refusing to launch a browser that does not identify as an isolated\n" +
        "Chrome for Testing (checked via `--version`). A non-headless\n" +
        "--load-extension launch of a real browser can capture and close your\n" +
        "session. Install one and point CHROME_BIN at it, e.g.:\n" +
        "  bunx @puppeteer/browsers install chrome@stable --path tests/.chrome-for-testing\n" +
        "(see tests/README.md -> Safety).",
    );
    process.exit(0);
  }
  return bin;
}
