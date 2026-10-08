import { afterEach, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdirSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  buildReport,
  type FailureInfo,
  generatedInputsError,
  isSafeFailureDir,
  MAX_EMBED_BYTES,
  newFiles,
  type Options,
  parseOptions,
  snapshotDir,
} from "../fuzz-smoke";
import { Scratch } from "../lib";

const scratch = new Scratch();
afterEach(() => scratch.remove());
const script = join(import.meta.dir, "..", "fuzz-smoke.ts");

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

// The flags reach libFuzzer and the nightly workflow through this parser. libFuzzer parses -runs and
// -max_total_time as signed 32-bit and -seed as unsigned 32-bit, so the boundary values must pass whole, and
// the scheduled nightly passes a blank --seed=, which is no seed given.
describe("parseOptions", () => {
  // A flag left out keeps the parser's own default, so each row pins the whole option set against
  // parseOptions([]) and fails only when a field it names moves.
  const defaults = parseOptions([]);
  const given: Options = {
    runs: 7,
    maxTotalTime: 9,
    cmin: true,
    seed: 42,
    failureDir: "fuzz/failures-alt",
    requireToolchain: true,
  };
  test.each<[name: string, argv: string[], options: Options]>([
    [
      "every flag parses",
      [
        "--runs=7",
        "--max-total-time=9",
        "--cmin",
        "--seed=42",
        "--failure-dir=fuzz/failures-alt",
        "--require-toolchain",
      ],
      given,
    ],
    [
      "the 32-bit boundary values are accepted",
      ["--seed=4294967295", "--runs=2147483647"],
      { ...defaults, seed: 4294967295, runs: 2147483647 },
    ],
    ["a blank --seed= is no seed given, not a malformed flag", ["--seed="], defaults],
  ])("%s", (_name, argv, options) => {
    expect(parseOptions(argv)).toEqual(options);
  });

  // parseOptions exits the process, so the refusals run as a subprocess.
  //   --seed=0                 -> libFuzzer reads a seed of 0 as "random"
  //   --runs / --seed too big  -> wrap inside libFuzzer's 32-bit parsing
  //   the --failure-dir shapes -> could aim the startup delete outside fuzz/failures
  test.each([
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
  ])("%s exits 2 with the usage before any toolchain probe", (arg) => {
    const run = spawnSync("bun", [script, arg], { encoding: "utf8" });
    expect({ status: run.status, stdout: run.stdout, stderr: run.stderr }).toEqual({
      status: 2,
      stdout: "",
      stderr: expect.stringMatching(/^error: .+\nusage: bun scripts\/fuzz-smoke\.ts /),
    });
  });
});

// With PATH emptied rustup cannot be found and the script takes its skip path; a skipped nightly must not
// read as green and auto-close the tracking issue. The throwaway --failure-dir keeps the startup clear
// away from a developer's real fuzz/failures reports.
describe("toolchain-missing behavior", () => {
  test.each<
    [name: string, args: string[], outcome: { status: number; stdout: string; stderr: string }]
  >([
    [
      "skips with exit 0 by default",
      [],
      {
        status: 0,
        stdout:
          "[fuzz-smoke] SKIP: no nightly toolchain (install with: rustup toolchain install nightly)\n",
        stderr: "",
      },
    ],
    [
      "--require-toolchain turns the skip into exit 1",
      ["--require-toolchain"],
      {
        status: 1,
        stdout: "",
        stderr: "error: nightly toolchain required (--require-toolchain) but missing\n",
      },
    ],
  ])("%s", (_name, args, outcome) => {
    const run = spawnSync(
      process.execPath,
      [script, `--failure-dir=fuzz/failures-test-${process.pid}`, ...args],
      { encoding: "utf8", env: { ...process.env, PATH: "/nonexistent" } },
    );
    expect({ status: run.status, stdout: run.stdout, stderr: run.stderr }).toEqual(outcome);
  });
});

// The failure directory is recursively deleted at startup, so only the fuzz/failures* namespace, spelled
// plainly, is a safe target.
describe("isSafeFailureDir", () => {
  test.each<[path: string, safe: boolean]>([
    ["fuzz/failures", true],
    ["fuzz/failures-test-1", true],
    ["fuzz/failures/nightly", true],
    ["", false],
    [".", false],
    ["..", false],
    ["/abs", false],
    ["a/../b", false],
    ["a//b", false],
    ["a/./b", false],
    ["a/", false],
    ["~x/../../etc", false],
    ["src", false],
    ["Cargo.toml", false],
    ["fuzz", false],
    ["fuzz/seeds", false],
    ["fuzz/fuzz_targets", false],
    ["fuzz/failuresX", false],
    ["tmp-failures", false],
  ])("%j -> %p", (path, safe) => {
    expect(isSafeFailureDir(path)).toBe(safe);
  });
});

describe("snapshotDir / newFiles", () => {
  test("a missing directory snapshots empty and diffs cleanly", () => {
    const before = snapshotDir("/nonexistent/nowhere");
    expect(before.size).toBe(0);
    expect(newFiles(before, new Map([["crash-1", 1]]))).toEqual(["crash-1"]);
  });

  test("reports only the files added between snapshots, sorted", () => {
    const dir = scratch.dir("artifacts");
    writeFileSync(join(dir, "crash-old"), "x");
    const before = snapshotDir(dir);
    writeFileSync(join(dir, "crash-b"), "x");
    writeFileSync(join(dir, "crash-a"), "x");
    expect(newFiles(before, snapshotDir(dir))).toEqual(["crash-a", "crash-b"]);
  });

  test("a rewritten file counts as new", () => {
    // libFuzzer names crash files by input hash, so replaying a known crash
    // OVERWRITES the existing file; the mtime change must surface it.
    const dir = scratch.dir("artifacts");
    writeFileSync(join(dir, "crash-same"), "x");
    const before = snapshotDir(dir);
    utimesSync(join(dir, "crash-same"), new Date(), new Date(Date.now() + 5000));
    expect(newFiles(before, snapshotDir(dir))).toEqual(["crash-same"]);
  });
});

// The report is the body of the issue the nightly files, read by a human who must replay the crash from it
// alone, so each scenario pins the whole text.
describe("buildReport (failure-report contract v1)", () => {
  const report = (...blocks: string[][]) => `${blocks.flat().join("\n")}\n`;
  // --target pinned to the machine's own nightly host triple: a musl prebuilt cargo-fuzz otherwise defaults
  // to a triple ASan cannot link.
  const fuzzRun = `cargo +nightly fuzz run --target "$(rustc +nightly -vV | sed -n 's/^host: //p')"`;
  const head = (sentence: string) => ["# fuzz: nm_frame crashed", "", sentence, ""];
  const ran = "libFuzzer exited with status 77 (seed 12345, -runs=200000, -max_total_time=120).";
  const replay = (target: string) => [
    "Replay the crashing input (the file is beside this report; the run's",
    "fuzz-failures artifact unpacks to artifacts/ and failures/ - extract",
    "it into src/packages/core/fuzz/ for the path below to line up):",
    "",
    "```bash",
    "cd src/packages/core",
    `${fuzzRun} ${target} fuzz/artifacts/${target}/crash-abc123`,
    "```",
    "",
  ];
  // One copy of the base64, on one line: a second copy could push a full-size embed past the filing
  // action's per-block budget, and a wrapped one could be cut by head-truncation.
  const embed = (target: string) => [
    "`crash-abc123` embedded as base64 (kept on one line so truncation",
    "cannot cut it); this block recreates and replays it directly:",
    "",
    "```bash",
    "cd src/packages/core",
    "printf '%s' 'QUJD' | base64 -d > crash.bin",
    `${fuzzRun} ${target} crash.bin`,
    "```",
    "",
  ];
  const rerun = (suffix: string) => [
    "cargo-fuzz left no new crash file (an OOM or timeout kill can do",
    "that); re-run this pass's exact configuration instead (the moon task",
    "regenerates the seed corpus and the dictionary first):",
    "",
    "```bash",
    `moon run fuzz-smoke -- --runs=200000 --max-total-time=120 --seed=12345${suffix}`,
    "```",
    "",
  ];
  const seedPin = [
    "Pin the input as a labelled seed in the generator so every future run (nightly",
    "and local smoke) replays it first, which is what makes the tracking issue's",
    "auto-close on a later green night trustworthy. fuzz/seeds/ is generated and",
    "gitignored (a file copied there is erased by the next run), so the pin is a case:",
    "",
    "```text",
    "src/packages/core/fuzz/src/seeds/nm_frame.rs: add a Seed::refused (or Seed::accepted)",
    "case built from the production type this input mutates, with the reader that must",
    "refuse it; `moon run test-fuzz` holds it to that label.",
    "```",
    "",
    "then commit the case with the fix.",
  ];

  test.each<[name: string, overrides: Partial<FailureInfo>, expected: string]>([
    [
      "a crash with its input embedded: replay, recreate, pin as a generator case",
      {},
      report(head(ran), replay("nm_frame"), embed("nm_frame"), seedPin),
    ],
    [
      "further crash files from the same pass are listed after the replay block",
      { crashFiles: ["crash-abc123", "crash-2", "crash-3"] },
      report(
        head(ran),
        replay("nm_frame"),
        ["Further crash files from the same pass: crash-2, crash-3.", ""],
        embed("nm_frame"),
        seedPin,
      ),
    ],
    [
      "an input too large to embed drops the recreate block and keeps the replay",
      { crashBase64: undefined },
      report(head(ran), replay("nm_frame"), seedPin),
    ],
    [
      "a structured target gets regression-test advice instead of a seed pin",
      { target: "handshake_verify" },
      report(
        ["# fuzz: handshake_verify crashed", "", ran, ""],
        replay("handshake_verify"),
        embed("handshake_verify"),
        [
          "Regression pinning: handshake_verify takes Arbitrary-derived input whose",
          "byte encoding is unstable across `arbitrary` versions, so do NOT pin",
          "the raw input as a seed; add a regression unit test reconstructing the",
          "decoded case instead.",
        ],
      ),
    ],
    [
      "no crash file: the replay block re-runs the pass's exact configuration",
      { crashFiles: [], crashBase64: undefined },
      report(head(ran), rerun("")),
    ],
    [
      "a cmin failure claims no configuration in its sentence and replays with --cmin",
      { phase: "cmin", crashFiles: [], crashBase64: undefined },
      report(
        head("Corpus minimization (cargo fuzz cmin) crashed with status 77."),
        rerun(" --cmin"),
      ),
    ],
  ])("%s", (_name, overrides, expected) => {
    expect(buildReport(failure(overrides))).toBe(expected);
  });

  test("the embed cutoff keeps the report inside the issue's per-block budget", () => {
    // 3,000 raw bytes -> 4,000 base64 chars; the filing action caps a block
    // at 8,000 chars and heads the report at its first 60 body lines, so the
    // full-size report must fit both bounds or the replay content gets cut.
    const text = buildReport(
      failure({ crashBase64: Buffer.alloc(MAX_EMBED_BYTES).toString("base64") }),
    );
    expect({ chars: text.length < 8_000, lines: text.split("\n").length < 60 }).toEqual({
      chars: true,
      lines: true,
    });
  });
});

// The seeds and the JSON dictionary are generated (`moon run fuzz-seeds`) and gitignored, so a fresh
// checkout has neither; a run that silently dropped them would fuzz without the corpus the nightly had and
// print the same green line. The driver must refuse and name the task.
test("a checkout without the generated corpus is refused, naming the generator task and each missing input", () => {
  const core = scratch.dir("fuzz-smoke-core");
  const targets = ["nm_frame", "classify_frame", "handshake_verify"];
  // The structured target takes no seeds and no dictionary, so nothing is demanded for it.
  expect(generatedInputsError(core, targets)).toBe(
    [
      "error: the fuzz inputs below are missing; the seeds and the JSON dictionary are generated, so run `moon run fuzz-seeds` first (or `moon run fuzz-smoke`, which does):",
      "  fuzz/seeds/nm_frame",
      "  fuzz/dictionaries/json_protocol.dict",
      "  fuzz/seeds/classify_frame",
    ].join("\n"),
  );
  for (const dir of ["fuzz/seeds/nm_frame", "fuzz/seeds/classify_frame", "fuzz/dictionaries"]) {
    mkdirSync(join(core, dir), { recursive: true });
  }
  writeFileSync(join(core, "fuzz/dictionaries/json_protocol.dict"), '"{"\n');
  expect(generatedInputsError(core, targets)).toBeUndefined();
});
