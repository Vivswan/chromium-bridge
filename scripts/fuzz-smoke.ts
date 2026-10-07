#!/usr/bin/env bun

// Smoke check for the cargo-fuzz targets: build each one and run it for a short bounded blast, proving the
// harnesses build and survive hostile bytes. The nightly job stretches this same script over a persistent corpus.
// node builtins only, no scripts/lib.ts import, so it runs without a `bun install`.
//
//   a target crashes                -> recorded, the pass continues, exit 1 at the end
//   its report                      -> <failure-dir>/<target>/report.md, the shape the fleet repository's
//                                      docs/fuzzer.md defines; the nightly job's issue-filing action reads it
//   nightly or cargo-fuzz missing   -> SKIP, exit 0, so the script can sit in a stable-only gate
//   ... under --require-toolchain   -> exit 1: an exit-0 skip in the nightly job would read as a green night
//                                      and auto-close the tracking issue
//   --seed=N                        -> best-effort determinism only; the corpus contents dominate what gets
//                                      explored, and the crash file is the real reproducer. Absent or blank,
//                                      one is drawn and logged so the pass can still be re-run as it was

import { spawnSync } from "node:child_process";
import { randomInt } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const usage =
  "usage: bun scripts/fuzz-smoke.ts [--runs=N] [--max-total-time=SECONDS] [--cmin] [--seed=N] [--failure-dir=PATH] [--require-toolchain]";

export interface Options {
  runs: number;
  maxTotalTime: number;
  cmin: boolean;
  seed: number | undefined;
  failureDir: string;
  requireToolchain: boolean;
}

/**
 * The --failure-dir directory is recursively DELETED at startup, so it must stay inside the core package's
 * fuzz/failures* namespace: an absolute path, a `.`/`..` or empty segment, or a plain name like `src` or
 * `fuzz/fuzz_targets` could point the delete at tracked checkout contents.
 */
export function isSafeFailureDir(path: string): boolean {
  const segments = path.split("/");
  return (
    segments.every((segment) => /^[A-Za-z0-9._-]+$/.test(segment) && !/^\.\.?$/.test(segment)) &&
    (path === "fuzz/failures" ||
      path.startsWith("fuzz/failures-") ||
      path.startsWith("fuzz/failures/"))
  );
}

function refuse(message: string): never {
  console.error(`error: ${message}\n${usage}`);
  process.exit(2);
}

function parseFlags(argv: string[]) {
  try {
    return parseArgs({
      args: argv,
      options: {
        runs: { type: "string" },
        "max-total-time": { type: "string" },
        cmin: { type: "boolean" },
        seed: { type: "string" },
        "failure-dir": { type: "string" },
        "require-toolchain": { type: "boolean" },
      },
      strict: true,
    });
  } catch (error) {
    return refuse(error instanceof Error ? error.message : String(error));
  }
}

export function parseOptions(argv: string[]): Options {
  const { values: flags } = parseFlags(argv);
  // libFuzzer parses -runs/-max_total_time as signed 32-bit and -seed as unsigned 32-bit; anything larger
  // silently wraps (a wrapped seed of 0 means "random", the opposite of what the caller asked for).
  const bounded = (name: "runs" | "max-total-time" | "seed", raw: string): number => {
    const limit = name === "seed" ? 0xffffffff : 0x7fffffff;
    const value = /^\d+$/.test(raw) ? Number(raw) : Number.NaN;
    if (!Number.isSafeInteger(value) || value <= 0 || value > limit) {
      refuse(`invalid argument: --${name}=${raw}`);
    }
    return value;
  };
  const failureDir = flags["failure-dir"];
  if (failureDir !== undefined && !isSafeFailureDir(failureDir)) {
    refuse(`invalid argument: --failure-dir=${failureDir}`);
  }
  return {
    runs: flags.runs === undefined ? 4096 : bounded("runs", flags.runs),
    maxTotalTime:
      flags["max-total-time"] === undefined
        ? 30
        : bounded("max-total-time", flags["max-total-time"]),
    cmin: flags.cmin === true,
    // nightly-fuzz.yml passes its dispatch input verbatim, blank on a scheduled run: no seed given.
    seed: flags.seed === undefined || flags.seed === "" ? undefined : bounded("seed", flags.seed),
    failureDir: failureDir ?? "fuzz/failures",
    requireToolchain: flags["require-toolchain"] === true,
  };
}

// Dictionaries steer mutation toward the target's input grammar. A byte dictionary is meaningless against
// Arbitrary-derived input; every other target gets the JSON dictionary, which only steers mutation, so the
// one binary-layout target (webauthn_authdata) loses nothing but a hint from it.
const noDictionary = new Set(["handshake_verify", "enclave_challenge"]);
const jsonDictionary = "fuzz/dictionaries/json_protocol.dict";

// Arbitrary-derived input has no stable byte encoding across `arbitrary` versions, so these targets' reports
// steer to a unit test, never a seed file.
const structuredTargets = noDictionary;

function dictionaryFor(target: string): string | undefined {
  return noDictionary.has(target) ? undefined : jsonDictionary;
}

/**
 * The seeds and the JSON dictionary are generated (`moon run fuzz-seeds`) and gitignored, so a fresh checkout has
 * neither; skipping them silently would fuzz without the corpus the nightly had and still print the same green line.
 */
export function generatedInputsError(core: string, targets: string[]): string | undefined {
  const missing = new Set<string>();
  for (const target of targets) {
    if (structuredTargets.has(target)) continue;
    for (const path of [`fuzz/seeds/${target}`, dictionaryFor(target)]) {
      if (path !== undefined && !existsSync(resolve(core, path))) missing.add(path);
    }
  }
  if (missing.size === 0) return undefined;
  return [
    "error: the fuzz inputs below are missing; the seeds and the JSON dictionary are generated, so run `moon run fuzz-seeds` first (or `moon run fuzz-smoke`, which does):",
    ...[...missing].map((path) => `  ${path}`),
  ].join("\n");
}

export function snapshotDir(dir: string): Map<string, number> {
  if (!existsSync(dir)) return new Map();
  return new Map(readdirSync(dir).map((name) => [name, statSync(resolve(dir, name)).mtimeMs]));
}

/**
 * libFuzzer names crash files by input hash, so a rerun of a known crash OVERWRITES its file: mtimes, not names,
 * tell new from old.
 */
export function newFiles(before: Map<string, number>, after: Map<string, number>): string[] {
  return [...after.entries()]
    .filter(([name, mtimeMs]) => before.get(name) !== mtimeMs)
    .map(([name]) => name)
    .sort();
}

export function describeExit(status: number | null, signal: string | null): string {
  return signal ? `signal ${signal}` : `status ${status ?? "unknown"}`;
}

export interface FailureInfo {
  target: string;
  exit: string;
  phase: "run" | "cmin";
  seed: number;
  runs: number;
  maxTotalTime: number;
  /** Bare names under fuzz/artifacts/<target>/, never paths. */
  crashFiles: string[];
  crashBase64: string | undefined;
}

/** Inputs up to this size are embedded in the report as one base64 line, so
 * the reproducer outlives the workflow-artifact retention window while the
 * line stays well inside the issue body's per-failure budget. */
export const MAX_EMBED_BYTES = 3000;

/**
 * The failure report, following the fleet's failure-report contract v1:
 * line 1 is a `# title` heading, and the body carries the exact replay
 * command in a fenced block, near the top so head-truncation keeps it.
 */
export function buildReport(info: FailureInfo): string {
  // cmin takes neither the seed nor -runs/-max_total_time, so its sentence claims no configuration.
  const configuration = `seed ${info.seed}, -runs=${info.runs}, -max_total_time=${info.maxTotalTime}`;
  const lines: string[] = [
    `# fuzz: ${info.target} crashed`,
    "",
    info.phase === "cmin"
      ? `Corpus minimization (cargo fuzz cmin) crashed with ${info.exit}.`
      : `libFuzzer exited with ${info.exit} (${configuration}).`,
    "",
  ];

  // The same --target pin main() computes, so the replay links under ASan on a musl-prebuilt cargo-fuzz.
  const hostArg = `--target "$(rustc +nightly -vV | sed -n 's/^host: //p')"`;

  const primary = info.crashFiles[0];
  if (primary) {
    lines.push(
      "Replay the crashing input (the file is beside this report; the run's",
      "fuzz-failures artifact unpacks to artifacts/ and failures/ - extract",
      "it into src/packages/core/fuzz/ for the path below to line up):",
      "",
      "```bash",
      "cd src/packages/core",
      `cargo +nightly fuzz run ${hostArg} ${info.target} fuzz/artifacts/${info.target}/${primary}`,
      "```",
      "",
    );
    if (info.crashFiles.length > 1) {
      lines.push(
        `Further crash files from the same pass: ${info.crashFiles.slice(1).join(", ")}.`,
        "",
      );
    }
    if (info.crashBase64) {
      lines.push(
        `\`${primary}\` embedded as base64 (kept on one line so truncation`,
        "cannot cut it); this block recreates and replays it directly:",
        "",
        "```bash",
        "cd src/packages/core",
        `printf '%s' '${info.crashBase64}' | base64 -d > crash.bin`,
        `cargo +nightly fuzz run ${hostArg} ${info.target} crash.bin`,
        "```",
        "",
      );
    }
  } else {
    lines.push(
      "cargo-fuzz left no new crash file (an OOM or timeout kill can do",
      "that); re-run this pass's exact configuration instead (the moon task",
      "regenerates the seed corpus and the dictionary first):",
      "",
      "```bash",
      `moon run fuzz-smoke -- --runs=${info.runs} --max-total-time=${info.maxTotalTime} --seed=${info.seed}${info.phase === "cmin" ? " --cmin" : ""}`,
      "```",
      "",
    );
  }

  if (structuredTargets.has(info.target)) {
    lines.push(
      `Regression pinning: ${info.target} takes Arbitrary-derived input whose`,
      "byte encoding is unstable across `arbitrary` versions, so do NOT pin",
      "the raw input as a seed; add a regression unit test reconstructing the",
      "decoded case instead.",
    );
  } else if (primary) {
    lines.push(
      "Pin the input as a labelled seed in the generator so every future run (nightly",
      "and local smoke) replays it first, which is what makes the tracking issue's",
      "auto-close on a later green night trustworthy. fuzz/seeds/ is generated and",
      "gitignored (a file copied there is erased by the next run), so the pin is a case:",
      "",
      "```text",
      `src/packages/core/fuzz/src/seeds/${info.target}.rs: add a Seed::refused (or Seed::accepted)`,
      "case built from the production type this input mutates, with the reader that must",
      "refuse it; `moon run test-fuzz` holds it to that label.",
      "```",
      "",
      "then commit the case with the fix.",
    );
  }

  return `${lines.join("\n")}\n`;
}

function main(): number {
  const options = parseOptions(process.argv.slice(2));
  const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  // cargo-fuzz resolves the fuzz workspace from the crate that contains fuzz/,
  // so run from the core package, not the repo root.
  const core = resolve(repo, "src/packages/core");
  const failureRoot = resolve(core, options.failureDir);
  // The recursive delete below is where a bad path would destroy tracked files, so the resolved path is
  // checked once more here.
  if (!failureRoot.startsWith(`${core}/`) || failureRoot === core) {
    console.error(`error: failure dir escapes ${core}: ${failureRoot}`);
    return 2;
  }

  // `timeoutMs` bounds subcommands with no wall-clock flag of their own (cmin): a hang there rides to the JOB
  // timeout, which cancels the run and skips the if:failure() reporting steps.
  function cargoFuzz(
    args: string[],
    timeoutMs?: number,
  ): { status: number | null; signal: string | null } {
    const run = spawnSync("cargo", ["+nightly", "fuzz", ...args], {
      cwd: core,
      stdio: "inherit",
      timeout: timeoutMs,
    });
    // A timeout kill surfaces as an ETIMEDOUT error plus the kill signal: a recordable failure, not a broken cargo.
    const timedOut =
      run.error &&
      /ETIMEDOUT|TimeoutError/i.test(
        `${run.error.name} ${(run.error as NodeJS.ErrnoException).code ?? ""}`,
      );
    if (run.error && !timedOut) {
      console.error(`error: failed to run cargo fuzz: ${run.error.message}`);
      process.exit(1);
    }
    return { status: run.status, signal: run.signal ?? (timedOut ? "SIGTERM" : null) };
  }

  // Cleared before the toolchain probes, so even a skipping run cannot leave yesterday's reports looking
  // current to the issue filer.
  rmSync(failureRoot, { recursive: true, force: true });

  const toolchains = spawnSync("rustup", ["toolchain", "list"], {
    cwd: core,
    encoding: "utf8",
  });
  if (toolchains.error || toolchains.status !== 0 || !toolchains.stdout?.includes("nightly")) {
    if (options.requireToolchain) {
      console.error("error: nightly toolchain required (--require-toolchain) but missing");
      return 1;
    }
    console.log(
      "[fuzz-smoke] SKIP: no nightly toolchain (install with: rustup toolchain install nightly)",
    );
    return 0;
  }
  const cargoFuzzProbe = spawnSync("cargo", ["+nightly", "fuzz", "--help"], {
    cwd: core,
    stdio: "ignore",
  });
  if (cargoFuzzProbe.error || cargoFuzzProbe.status !== 0) {
    if (options.requireToolchain) {
      console.error("error: cargo-fuzz required (--require-toolchain) but missing");
      return 1;
    }
    console.log(
      "[fuzz-smoke] SKIP: cargo-fuzz not installed (install with: cargo install cargo-fuzz)",
    );
    return 0;
  }

  // cargo-fuzz defaults --target to its own compile-time host triple, a musl triple when installed prebuilt
  // (taiki-e/install-action in CI), and ASan cannot link a static libc. The nightly toolchain's real host triple
  // is pinned instead.
  const rustcInfo = spawnSync("rustc", ["+nightly", "-vV"], { cwd: core, encoding: "utf8" });
  const host =
    rustcInfo.status === 0 ? /^host: (\S+)$/m.exec(rustcInfo.stdout ?? "")?.[1] : undefined;
  if (!host) {
    console.error("error: could not determine the host triple from `rustc +nightly -vV`");
    return 1;
  }

  // The target list comes from cargo-fuzz itself, so it cannot drift from fuzz/Cargo.toml.
  const list = spawnSync("cargo", ["+nightly", "fuzz", "list"], { cwd: core, encoding: "utf8" });
  if (list.error || list.status !== 0) {
    console.error("error: `cargo +nightly fuzz list` failed");
    return 1;
  }
  const targets = (list.stdout ?? "")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  if (targets.length === 0) {
    console.error("error: `cargo +nightly fuzz list` returned no targets");
    return 1;
  }

  // Crash files are copied beside the report so it survives when the artifacts dir is not uploaded whole.
  function recordFailure(info: FailureInfo): void {
    const dir = resolve(failureRoot, info.target);
    mkdirSync(dir, { recursive: true });
    writeFileSync(resolve(dir, "report.md"), buildReport(info));
    for (const file of info.crashFiles) {
      copyFileSync(resolve(core, "fuzz/artifacts", info.target, file), resolve(dir, file));
    }
    console.error(
      `[fuzz-smoke] ${info.target} FAILED (${info.exit}); report: ${options.failureDir}/${info.target}/report.md`,
    );
  }

  function crashEvidence(
    artifactsDir: string,
    before: Map<string, number>,
  ): { crashFiles: string[]; crashBase64: string | undefined } {
    const crashFiles = newFiles(before, snapshotDir(artifactsDir));
    const primary = crashFiles[0];
    let crashBase64: string | undefined;
    if (primary) {
      const bytes = readFileSync(resolve(artifactsDir, primary));
      if (bytes.byteLength <= MAX_EMBED_BYTES) crashBase64 = bytes.toString("base64");
    }
    return { crashFiles, crashBase64 };
  }

  const failed: string[] = [];
  const inputsError = generatedInputsError(core, targets);
  if (inputsError !== undefined) {
    console.error(inputsError);
    return 1;
  }
  // libFuzzer takes -seed as unsigned 32-bit, 0 meaning "random", so the drawn seed starts at 1.
  const seed = options.seed ?? randomInt(1, 0x1_0000_0000);
  console.log(`[fuzz-smoke] seed ${seed}`);
  for (const target of targets) {
    console.log(`[fuzz-smoke] ${target}: ${options.runs} runs (target ${host})`);
    // libFuzzer needs the corpus dir to exist; the generated seeds ride along as a second corpus dir it merges in.
    const corpus = `fuzz/corpus/${target}`;
    mkdirSync(resolve(core, corpus), { recursive: true });
    const runArgs = ["run", "--target", host, target, corpus];
    if (!structuredTargets.has(target)) runArgs.push(`fuzz/seeds/${target}`);
    runArgs.push(
      "--",
      `-runs=${options.runs}`,
      `-max_total_time=${options.maxTotalTime}`,
      `-seed=${seed}`,
    );
    const dictionary = dictionaryFor(target);
    if (dictionary) runArgs.push(`-dict=${dictionary}`);

    const artifactsDir = resolve(core, "fuzz/artifacts", target);
    const before = snapshotDir(artifactsDir);
    const run = cargoFuzz(runArgs);
    if (run.status === 0) continue;

    failed.push(target);
    recordFailure({
      target,
      exit: describeExit(run.status, run.signal),
      phase: "run",
      seed,
      runs: options.runs,
      maxTotalTime: options.maxTotalTime,
      ...crashEvidence(artifactsDir, before),
    });
  }

  if (options.cmin) {
    // Minimize only the corpora of targets that passed: minimizing a corpus
    // the target just crashed on wastes time and can crash again on the same
    // input, and a cmin crash on a "passing" target is itself a finding.
    for (const target of targets) {
      if (failed.includes(target)) continue;
      console.log(`[fuzz-smoke] ${target}: minimizing corpus`);
      const artifactsDir = resolve(core, "fuzz/artifacts", target);
      const before = snapshotDir(artifactsDir);
      // cmin has no wall-clock flag; it normally takes seconds, so three minutes is a hang and a killed cmin is
      // recorded below.
      const run = cargoFuzz(["cmin", "--target", host, target], 180_000);
      // cargo-fuzz has exited 0 while printing "Failed to minimize corpus"
      // after its libFuzzer child died, so a new crash artifact counts as a
      // failure even alongside a zero status.
      const evidence = crashEvidence(artifactsDir, before);
      if (run.status === 0 && evidence.crashFiles.length === 0) continue;
      failed.push(target);
      recordFailure({
        target,
        exit: describeExit(run.status, run.signal),
        phase: "cmin",
        seed,
        runs: options.runs,
        maxTotalTime: options.maxTotalTime,
        ...evidence,
      });
    }
  }

  if (failed.length > 0) {
    console.error(
      `[fuzz-smoke] ${failed.length}/${targets.length} target(s) failed: ${failed.join(", ")}`,
    );
    return 1;
  }
  console.log(`[fuzz-smoke] all targets survived ${options.runs} runs each`);
  return 0;
}

if (import.meta.main) {
  process.exit(main());
}
