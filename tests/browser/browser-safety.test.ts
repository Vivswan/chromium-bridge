// Unit tests for the suite-ran canary in browser-safety.ts. No browser is
// launched here - the guard is exercised as a real subprocess whose CHROME_BIN
// is unset, so it always takes the refusal path - making this file safe to run
// anywhere (CI runs it in the browser job next to the suites it guards).

import { describe, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ranMarkerBody, suiteExitCode, writeRanMarker } from "./browser-safety";

describe("suiteExitCode", () => {
  test("a suite with passing checks and no failures is green", () => {
    expect(suiteExitCode(12, 0)).toBe(0);
  });

  test("any failed check is red", () => {
    expect(suiteExitCode(12, 1)).toBe(1);
  });

  test("a vacuous run that asserted nothing is red, never a silent pass", () => {
    expect(suiteExitCode(0, 0)).toBe(1);
  });
});

describe("writeRanMarker", () => {
  test("writes the per-suite marker with the pass/fail summary", () => {
    const dir = mkdtempSync(join(tmpdir(), "bb-canary-"));
    const marker = writeRanMarker("ext_test", 9, 0, dir);
    expect(marker).toBe(join(dir, "ext_test"));
    expect(readFileSync(marker as string, "utf8")).toBe(`${ranMarkerBody("ext_test", 9, 0)}\n`);
  });

  test("without a canary dir (local runs) no marker is written", () => {
    expect(writeRanMarker("ext_test", 9, 0, undefined)).toBeNull();
  });
});

describe("guard skip vs canary (real subprocess)", () => {
  // The drift the CI canary guards against: the isolation guard exits before
  // any test runs (locally as a SKIP; in CI only BB_REQUIRE_BROWSER turns
  // that red, and only while both sides spell that variable the same way).
  // Run the REAL guard in a stub suite with no CHROME_BIN and prove the two
  // halves of the defense: the skip leaves NO marker for the CI canary step
  // to find, and strict mode turns the same skip into a hard failure.
  const stubFor = (dir: string): string => {
    const stub = join(dir, "stub_suite.ts");
    const safety = join(import.meta.dir, "browser-safety.ts");
    writeFileSync(
      stub,
      `import { assertIsolatedBrowserOrSkip, finishSuite } from ${JSON.stringify(safety)};\n` +
        `assertIsolatedBrowserOrSkip();\n` +
        `finishSuite("stub_suite", 1, 0);\n`,
    );
    return stub;
  };
  const baseEnv = (): NodeJS.ProcessEnv => {
    const env = { ...process.env };
    delete env.CHROME_BIN;
    delete env.BB_REQUIRE_BROWSER;
    delete env.BB_BROWSER_CANARY_DIR;
    return env;
  };

  test("a local skip exits 0 and leaves no RAN marker behind", () => {
    const dir = mkdtempSync(join(tmpdir(), "bb-canary-"));
    const out = execFileSync(process.execPath, [stubFor(dir)], {
      encoding: "utf8",
      env: { ...baseEnv(), BB_BROWSER_CANARY_DIR: dir },
    });
    expect(out).toContain("SKIP");
    expect(existsSync(join(dir, "stub_suite"))).toBe(false);
  });

  test("BB_REQUIRE_BROWSER=1 turns the same skip into a hard failure", () => {
    const dir = mkdtempSync(join(tmpdir(), "bb-canary-"));
    let status = 0;
    try {
      execFileSync(process.execPath, [stubFor(dir)], {
        encoding: "utf8",
        env: { ...baseEnv(), BB_REQUIRE_BROWSER: "1", BB_BROWSER_CANARY_DIR: dir },
      });
    } catch (err) {
      status = (err as { status?: number }).status ?? 0;
    }
    expect(status).toBe(1);
    expect(existsSync(join(dir, "stub_suite"))).toBe(false);
  });

  test("a suite that reaches its end writes the marker the CI step requires", () => {
    // Same stub without the guard: finishSuite alone must drop the marker.
    const dir = mkdtempSync(join(tmpdir(), "bb-canary-"));
    const stub = join(dir, "finish_only.ts");
    const safety = join(import.meta.dir, "browser-safety.ts");
    writeFileSync(
      stub,
      `import { finishSuite } from ${JSON.stringify(safety)};\nfinishSuite("finish_only", 2, 0);\n`,
    );
    execFileSync(process.execPath, [stub], {
      encoding: "utf8",
      env: { ...baseEnv(), BB_BROWSER_CANARY_DIR: dir },
    });
    expect(readFileSync(join(dir, "finish_only"), "utf8")).toBe(
      "finish_only: 2 passed, 0 failed\n",
    );
    // Only the marker and the stub itself live in the dir - nothing else.
    expect(readdirSync(dir).sort()).toEqual(["finish_only", "finish_only.ts"]);
  });
});
