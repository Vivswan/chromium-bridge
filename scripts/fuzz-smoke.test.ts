import { describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildReport,
  describeExit,
  type FailureInfo,
  isSafeFailureDir,
  MAX_EMBED_BYTES,
  newFiles,
  parseOptions,
  snapshotDir,
} from "./fuzz-smoke";

function failure(overrides: Partial<FailureInfo> = {}): FailureInfo {
  return {
    target: "nm_frame",
    exit: "status 77",
    phase: "run",
    seed: 12345,
    runs: 200000,
    maxTotalTime: 120,
    crashFiles: ["crash-abc123"],
    crashBase64: "QUJD",
    ...overrides,
  };
}

describe("parseOptions", () => {
  test("defaults", () => {
    expect(parseOptions([])).toEqual({
      runs: 4096,
      maxTotalTime: 30,
      cmin: false,
      seed: undefined,
      failureDir: "fuzz/failures",
      requireToolchain: false,
    });
  });

  test("parses every flag", () => {
    expect(
      parseOptions([
        "--runs=7",
        "--max-total-time=9",
        "--cmin",
        "--seed=42",
        "--failure-dir=fuzz/failures-alt",
        "--require-toolchain",
      ]),
    ).toEqual({
      runs: 7,
      maxTotalTime: 9,
      cmin: true,
      seed: 42,
      failureDir: "fuzz/failures-alt",
      requireToolchain: true,
    });
  });

  test("an unknown or malformed flag exits 2 before any toolchain probe", () => {
    // parseOptions calls process.exit, so the rejection paths are exercised
    // through a real subprocess. --seed=0 is malformed (seeds are positive),
    // the oversized values would wrap inside libFuzzer's 32-bit parsing, and
    // the failure-dir shapes could point the startup delete outside
    // fuzz/failures.
    for (const arg of [
      "--bogus",
      "--runs=0",
      "--runs=2147483648",
      "--seed=0",
      "--seed=abc",
      "--seed=4294967296",
      "--failure-dir=",
      "--failure-dir=..",
      "--failure-dir=/tmp/x",
      "--failure-dir=a/../b",
      "--failure-dir=.",
      "--failure-dir=src",
    ]) {
      const run = spawnSync("bun", [join(import.meta.dir, "fuzz-smoke.ts"), arg], {
        encoding: "utf8",
      });
      expect(run.status).toBe(2);
      expect(run.stderr).toContain("invalid argument");
    }
  });

  test("accepts the 32-bit boundary values", () => {
    expect(parseOptions(["--seed=4294967295", "--runs=2147483647"])).toMatchObject({
      seed: 4294967295,
      runs: 2147483647,
    });
  });
});

describe("toolchain-missing behavior", () => {
  // With PATH emptied, rustup cannot be found, so the script takes its skip
  // path; the flag must turn that skip into a failure (a skipped nightly must
  // not read as green and auto-close the tracking issue). A throwaway
  // --failure-dir keeps the startup clear away from a developer's real
  // fuzz/failures reports.
  const runWithoutToolchain = (args: string[]) =>
    spawnSync(
      process.execPath,
      [
        join(import.meta.dir, "fuzz-smoke.ts"),
        `--failure-dir=fuzz/failures-test-${process.pid}`,
        ...args,
      ],
      {
        encoding: "utf8",
        env: { ...process.env, PATH: "/nonexistent" },
      },
    );

  test("skips with exit 0 by default", () => {
    const run = runWithoutToolchain([]);
    expect(run.status).toBe(0);
    expect(run.stdout).toContain("SKIP");
  });

  test("--require-toolchain turns the skip into exit 1", () => {
    const run = runWithoutToolchain(["--require-toolchain"]);
    expect(run.status).toBe(1);
    expect(run.stderr).toContain("required");
  });
});

describe("isSafeFailureDir", () => {
  test("accepts paths inside the fuzz/failures* namespace", () => {
    for (const path of ["fuzz/failures", "fuzz/failures-test-1", "fuzz/failures/nightly"]) {
      expect(isSafeFailureDir(path)).toBe(true);
    }
  });

  test("rejects anything else - the directory is recursively deleted", () => {
    for (const path of [
      "",
      ".",
      "..",
      "/abs",
      "a/../b",
      "a//b",
      "a/./b",
      "a/",
      "~x/../../etc",
      "src",
      "Cargo.toml",
      "fuzz",
      "fuzz/seeds",
      "fuzz/fuzz_targets",
      "fuzz/failuresX",
      "tmp-failures",
    ]) {
      expect(isSafeFailureDir(path)).toBe(false);
    }
  });
});

describe("snapshotDir / newFiles", () => {
  test("a missing directory snapshots empty and diffs cleanly", () => {
    const before = snapshotDir("/nonexistent/nowhere");
    expect(before.size).toBe(0);
    expect(newFiles(before, new Map([["crash-1", 1]]))).toEqual(["crash-1"]);
  });

  test("reports only the files added between snapshots, sorted", () => {
    const dir = mkdtempSync(join(tmpdir(), "artifacts-"));
    writeFileSync(join(dir, "crash-old"), "x");
    const before = snapshotDir(dir);
    writeFileSync(join(dir, "crash-b"), "x");
    writeFileSync(join(dir, "crash-a"), "x");
    expect(newFiles(before, snapshotDir(dir))).toEqual(["crash-a", "crash-b"]);
    rmSync(dir, { recursive: true, force: true });
  });

  test("a rewritten file counts as new", () => {
    // libFuzzer names crash files by input hash, so replaying a known crash
    // OVERWRITES the existing file; the mtime change must surface it.
    const dir = mkdtempSync(join(tmpdir(), "artifacts-"));
    writeFileSync(join(dir, "crash-same"), "x");
    const before = snapshotDir(dir);
    utimesSync(join(dir, "crash-same"), new Date(), new Date(Date.now() + 5000));
    expect(newFiles(before, snapshotDir(dir))).toEqual(["crash-same"]);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("describeExit", () => {
  test("prefers the signal when present", () => {
    expect(describeExit(null, "SIGABRT")).toBe("signal SIGABRT");
    expect(describeExit(77, null)).toBe("status 77");
    expect(describeExit(null, null)).toBe("status unknown");
  });
});

describe("buildReport (failure-report contract v1)", () => {
  test("line 1 is a markdown heading naming the target", () => {
    expect(buildReport(failure()).split("\n")[0]).toBe("# fuzz: nm_frame crashed");
  });

  test("carries the exact replay command in a fenced block near the top", () => {
    const report = buildReport(failure());
    const fenceLine = report.split("\n").indexOf("```bash");
    expect(fenceLine).toBeGreaterThan(0);
    expect(fenceLine).toBeLessThan(15); // head-truncation keeps 60 lines; stay well inside
    expect(report).toContain("cd src/packages/core");
    // --target pinned to the machine's own nightly host triple: a musl
    // prebuilt cargo-fuzz otherwise defaults to a triple ASan cannot link.
    expect(report).toContain(
      `cargo +nightly fuzz run --target "$(rustc +nightly -vV | sed -n 's/^host: //p')" nm_frame fuzz/artifacts/nm_frame/crash-abc123`,
    );
  });

  test("names the run configuration: seed, runs, wall clock", () => {
    const report = buildReport(failure());
    expect(report).toContain("seed 12345");
    expect(report).toContain("-runs=200000");
    expect(report).toContain("-max_total_time=120");
    expect(buildReport(failure({ seed: undefined }))).toContain("seed none");
  });

  test("embeds the base64 once, inside an executable recreate command", () => {
    const report = buildReport(failure());
    expect(report).toContain("printf '%s' 'QUJD' | base64 -d > crash.bin");
    expect(report).toContain("nm_frame crash.bin");
    // Exactly one copy: a second copy would double the block's size and can
    // push a full-size embed past the filing action's per-block budget.
    expect(report.split("QUJD").length - 1).toBe(1);
    // One line: the base64 must never be wrapped, or head-truncation could cut it.
    expect(report.split("\n").some((line) => line.includes("'QUJD'"))).toBe(true);
  });

  test("omits the base64 section when the input was too large to embed", () => {
    const report = buildReport(failure({ crashBase64: undefined }));
    expect(report).not.toContain("base64 -d");
    expect(report).toContain("nm_frame fuzz/artifacts/nm_frame/crash-abc123");
  });

  test("instructs pinning the input as a regression seed", () => {
    const report = buildReport(failure());
    expect(report).toContain("cp src/packages/core/fuzz/artifacts/nm_frame/crash-abc123");
    expect(report).toContain("fuzz/seeds/nm_frame");
  });

  test("structured targets get regression-test advice instead of a seed pin", () => {
    const report = buildReport(failure({ target: "handshake_verify" }));
    expect(report).toContain("regression unit test");
    expect(report).not.toContain("fuzz/seeds/handshake_verify");
  });

  test("no crash file: the replay block re-runs the pass's exact configuration", () => {
    const report = buildReport(failure({ crashFiles: [], crashBase64: undefined }));
    expect(report).toContain(
      "bun scripts/fuzz-smoke.ts --runs=200000 --max-total-time=120 --seed=12345",
    );
    expect(report).not.toContain("fuzz/artifacts/nm_frame/");
  });

  test("a cmin failure says the minimization pass crashed and replays with --cmin", () => {
    const report = buildReport(failure({ phase: "cmin", crashFiles: [], crashBase64: undefined }));
    expect(report).toContain("Corpus minimization");
    // cmin takes neither the seed nor -runs/-max_total_time, so the sentence
    // must claim no configuration...
    expect(report.split("\n")[2]).not.toContain("-runs=");
    expect(report.split("\n")[2]).not.toContain("seed");
    // ...but the re-run command reproduces the full pass, including the cmin stage.
    expect(report).toContain(
      "bun scripts/fuzz-smoke.ts --runs=200000 --max-total-time=120 --seed=12345 --cmin",
    );
  });

  test("lists further crash files from the same pass", () => {
    const report = buildReport(failure({ crashFiles: ["crash-1", "crash-2", "crash-3"] }));
    expect(report).toContain("crash-2, crash-3");
  });

  test("the embed cutoff keeps the report inside the issue's per-block budget", () => {
    // 3,000 raw bytes -> 4,000 base64 chars; the filing action caps a block
    // at 8,000 chars and heads the report at its first 60 body lines, so the
    // full-size report must fit both bounds or the replay content gets cut.
    const report = buildReport(
      failure({ crashBase64: Buffer.alloc(MAX_EMBED_BYTES).toString("base64") }),
    );
    expect(report.length).toBeLessThan(8_000);
    expect(report.split("\n").length).toBeLessThan(60);
  });
});
