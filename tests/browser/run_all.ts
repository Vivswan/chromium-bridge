#!/usr/bin/env bun
// The browser suite runner: the one definition behind CI (.github/workflows/browser.yml), the container
// (compose.yaml's browser service via `moon run test-browser`), and a local run.
//
// SAFETY: the suites launch CHROME_BIN non-headless with --load-extension, which can capture and close a
// real browser session, so the shared guard decides once here (tests/README.md -> Safety).
//
// Two independent switches keep a silent skip from going green in CI: the guard's BB_REQUIRE_BROWSER, and a
// caller-named BB_BROWSER_CANARY_DIR, for which the runner's own skip is a failure and every suite's RAN
// marker (finishSuite in browser-safety.ts) is required. Either alone suffices, so a renamed variable on
// one side cannot green a run on the other.

import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { assertIsolatedBrowserOrSkip, isolatedBrowserOrNull } from "./browser-safety";

const SUITES = ["dom_test", "ext_test", "security_browser_test"] as const;

/** The caller-named canary dir, if any. An empty value is the shell's way of unsetting a variable
 * (`BB_BROWSER_CANARY_DIR= bun ...`), so it means "none", never a dir named "". A relative path is made
 * absolute here, since the suites write the markers from the repo root and the runner reads them from
 * wherever it was started. */
export function callerCanaryDir(env: NodeJS.ProcessEnv): string | undefined {
  const dir = env.BB_BROWSER_CANARY_DIR;
  return dir ? resolve(dir) : undefined;
}

function isolatedBrowserForCanary(dir: string): string {
  const bin = isolatedBrowserOrNull();
  if (bin) return bin;
  console.error(
    `FAIL: ${dir} was named for the RAN markers, so the suites must run, but CHROME_BIN` +
      ` (${process.env.CHROME_BIN ?? "unset"}) does not identify as an isolated browser`,
  );
  process.exit(1);
}

function main(): never {
  const here = dirname(fileURLToPath(import.meta.url));
  const repo = join(here, "../..");
  const callerDir = callerCanaryDir(process.env);

  const run = (cmd: string[], env: Record<string, string>): boolean => {
    const proc = Bun.spawnSync(cmd, {
      cwd: repo,
      stdout: "inherit",
      stderr: "inherit",
      env: { ...process.env, ...env },
    });
    return proc.exitCode === 0;
  };

  console.log("=== browser suites ===");
  console.log("(1/3) build the extension bundle");
  if (!run(["bun", "run", "--cwd", join(repo, "src/apps/extension"), "build"], {})) {
    console.error("EXTENSION BUILD FAILED");
    process.exit(1);
  }

  console.log("");
  console.log("(2/3) isolated browser");
  const chromeBin = callerDir ? isolatedBrowserForCanary(callerDir) : assertIsolatedBrowserOrSkip();
  console.log(`  ${chromeBin}`);

  // Only this run's markers are cleared in a caller-owned dir (compose.yaml reads them afterwards): a
  // marker from an earlier run must not vouch for this one.
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
      console.error(
        `  ${suite} left no RAN marker - it finished no real browser run (silent skip?)`,
      );
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
}

if (import.meta.main) main();
