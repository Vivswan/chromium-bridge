#!/usr/bin/env bun
// The browser suite runner: the one definition behind CI (.github/workflows/browser.yml), the container
// (scripts/container-browser-suites.sh via `moon run test-browser`), and a local run. It builds the
// extension bundle, runs the three suites against CHROME_BIN, then requires each suite's RAN marker.
//
// SAFETY: the suites launch CHROME_BIN non-headless with --load-extension, which can capture and close a
// real browser session, so the shared guard decides once here: an isolated browser or a SKIP, which
// BB_REQUIRE_BROWSER=1 (CI, the container) turns into a failure.
//
// The canary: each suite exits 0 only after finishSuite() wrote "<suite>: N passed, M failed" into
// BB_BROWSER_CANARY_DIR. A missing marker means the suite finished no real browser run (a guard skip
// upstream of its checks) and a zero-pass marker means it ran vacuously; both fail the run even when every
// suite exited 0, so no drift in the guard's env var spelling can green a run on silent skips.

import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { assertIsolatedBrowserOrSkip } from "./browser-safety";

const SUITES = ["dom_test", "ext_test", "security_browser_test"] as const;

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "../..");

function run(cmd: string[], env: Record<string, string>): boolean {
  const proc = Bun.spawnSync(cmd, {
    cwd: repo,
    stdout: "inherit",
    stderr: "inherit",
    env: { ...process.env, ...env },
  });
  return proc.exitCode === 0;
}

console.log("=== browser suites ===");
console.log("(1/3) build the extension bundle");
if (!run(["bun", "run", "--cwd", join(repo, "src/apps/extension"), "build"], {})) {
  console.error("EXTENSION BUILD FAILED");
  process.exit(1);
}

console.log("");
console.log("(2/3) isolated browser");
const chromeBin = assertIsolatedBrowserOrSkip();
console.log(`  ${chromeBin}`);

// A caller may name the canary dir to read the markers afterwards (compose.yaml does), so only this run's
// markers are cleared there: a marker from an earlier run must not vouch for this one.
const callerDir = process.env.BB_BROWSER_CANARY_DIR;
const canaryDir = callerDir ?? mkdtempSync(join(tmpdir(), "browser-canary-"));
for (const suite of SUITES) rmSync(join(canaryDir, suite), { force: true });

console.log("");
console.log("(3/3) suites");
let failed = false;
for (const suite of SUITES) {
  if (
    !run(["bun", join(here, `${suite}.ts`)], {
      CHROME_BIN: chromeBin,
      BB_BROWSER_CANARY_DIR: canaryDir,
    })
  ) {
    console.error(`${suite} FAILED`);
    failed = true;
  }
}

console.log("");
console.log("canary (every suite really ran)");
for (const suite of SUITES) {
  const marker = join(canaryDir, suite);
  if (!existsSync(marker)) {
    console.error(`  ${suite} left no RAN marker - it finished no real browser run (silent skip?)`);
    failed = true;
    continue;
  }
  const body = readFileSync(marker, "utf8").trim();
  if (body.includes(": 0 passed")) {
    console.error(`  ${suite} ran vacuously: ${body}`);
    failed = true;
    continue;
  }
  console.log(`  ${body}`);
}
if (!callerDir) rmSync(canaryDir, { recursive: true, force: true });

console.log("");
console.log(failed ? "=== SOME BROWSER SUITES FAILED ===" : "=== ALL BROWSER SUITES PASSED ===");
process.exit(failed ? 1 : 0);
