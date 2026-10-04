// Unit tests for the isolation guard and the suite-ran canary in browser-safety.ts. No browser is
// launched here: the guard's browsers are stub scripts that print a version line, and the canary
// runs as a real subprocess with CHROME_BIN unset, so this file is safe to run anywhere (CI runs it
// in the browser job next to the suites it guards).

import { afterAll, describe, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isolatedBrowser, ranMarkerBody, suiteExitCode, writeRanMarker } from "./browser-safety";

// Every scratch dir this file creates, removed when the file is done whatever
// its tests did; nothing is left for the OS temp cleaner.
const scratchDirs: string[] = [];
const scratchDir = (prefix: string): string => {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  scratchDirs.push(dir);
  return dir;
};
afterAll(() => {
  for (const dir of scratchDirs) rmSync(dir, { recursive: true, force: true });
});

describe("isolatedBrowser", () => {
  // External facts the guard rests on: Chrome for Testing reports "Google Chrome for Testing <ver>",
  // Debian's chromium reports "Chromium <ver> built on Debian ...", and the engines leave a marker
  // file in every container (/.dockerenv for Docker, /run/.containerenv for Podman). Each case runs a
  // stub browser that prints one such line, with the marker present or absent.
  const dir = scratchDir("bb-isolated-");
  const marker = join(dir, "containerenv");
  writeFileSync(marker, "");
  const absentMarker = join(dir, "no-such-marker");
  const stubBrowser = (name: string, versionLine: string): string => {
    const bin = join(dir, name);
    writeFileSync(bin, `#!/bin/sh\necho ${JSON.stringify(versionLine)}\n`, { mode: 0o755 });
    return bin;
  };

  const chromium = "Chromium 140.0.7339.80 built on Debian 13.1, running on Debian 13.1";
  test.each([
    {
      name: "Chrome for Testing on the host",
      bin: "cft",
      version: "Google Chrome for Testing 140.0.7339.80",
      at: absentMarker,
      isolated: true,
    },
    {
      name: "the headless shell on the host",
      bin: "shell",
      version: "HeadlessShell 140.0.7339.80",
      at: absentMarker,
      isolated: true,
    },
    {
      name: "a distro Chromium inside a container",
      bin: "chromium",
      version: chromium,
      at: marker,
      isolated: true,
    },
    {
      name: "the same distro Chromium on the host",
      bin: "chromium",
      version: chromium,
      at: absentMarker,
      isolated: false,
    },
    {
      name: "a daily Chrome even inside a container",
      bin: "chrome",
      version: "Google Chrome 140.0.7339.80",
      at: marker,
      isolated: false,
    },
    {
      name: "a daily Brave on the host",
      bin: "brave",
      version: "Brave Browser 140.1.83.109",
      at: absentMarker,
      isolated: false,
    },
  ])("$name: isolated=$isolated", ({ bin: binName, version, at, isolated }) => {
    const bin = stubBrowser(binName, version);
    expect(isolatedBrowser(bin, [at])).toBe(isolated ? bin : null);
  });
});

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
    const dir = scratchDir("bb-canary-");
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
    const dir = scratchDir("bb-canary-");
    const out = execFileSync(process.execPath, [stubFor(dir)], {
      encoding: "utf8",
      env: { ...baseEnv(), BB_BROWSER_CANARY_DIR: dir },
    });
    expect(out).toContain("SKIP");
    expect(existsSync(join(dir, "stub_suite"))).toBe(false);
  });

  test("BB_REQUIRE_BROWSER=1 turns the same skip into a hard failure", () => {
    const dir = scratchDir("bb-canary-");
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
    const dir = scratchDir("bb-canary-");
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
