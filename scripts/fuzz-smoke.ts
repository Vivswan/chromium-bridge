#!/usr/bin/env bun

// Fuzz smoke test for the wire parsers and semantic validators (chromium-bridge).
//
// Discovers every cargo-fuzz target, builds it, and runs it for a short,
// bounded blast of input (seeded from fuzz/seeds/<target> and steered by
// fuzz/dictionaries/ where those exist), purely to prove the harnesses build
// and survive hostile bytes. This is a smoke check, NOT a real fuzzing
// campaign: the nightly job stretches the same script into a longer bounded
// pass over a persistent corpus, but continuous fuzzing (OSS-Fuzz scale) is
// out of scope.
//
// A crashing target does not stop the pass: the script records the failure,
// writes a report for it under --failure-dir (one directory per target,
// following repo-platform's failure-report contract - see docs/fuzzer.md
// there - so the nightly job's issue-filing action can consume it), and
// continues with the remaining targets. The exit code is 1 when any target
// failed, 0 when all survived. (Earlier versions re-raised libFuzzer's
// signal / propagated cargo's status; with continue-through-targets there is
// no single status to propagate, and the callers only branch on nonzero.)
//
// Requirements: a nightly toolchain and cargo-fuzz (libFuzzer). If either is
// missing the script SKIPS (exit 0) rather than failing, so it can sit in a
// stable-only gate harmlessly; the nightly fuzz job makes it load-bearing.
//
// Deliberately self-contained (node builtins only, no scripts/lib.ts import)
// so it runs without a `bun install`.
//
// Dual-use: CI (the nightly fuzz job) and local runs (`moon run fuzz-smoke`).
//
// Usage: bun scripts/fuzz-smoke.ts [--runs=N] [--max-total-time=SECONDS] [--cmin]
//                                  [--seed=N] [--failure-dir=PATH] [--require-toolchain]
//   --runs=N                  iteration cap per target (default 4096)
//   --max-total-time=SECONDS  wall-clock cap per target (default 30)
//   --cmin                    minimize each passing target's corpus after the runs
//   --seed=N                  libFuzzer PRNG seed (best-effort determinism only:
//                             the corpus contents dominate what gets explored;
//                             the crashing input file is the real reproducer)
//   --failure-dir=PATH        failure-report directory, relative to
//                             src/packages/core and inside fuzz/failures*
//                             (default fuzz/failures); cleared at startup so
//                             stale reports never leak
//   --require-toolchain       fail (exit 1) instead of skipping when nightly
//                             or cargo-fuzz is missing; the nightly job passes
//                             this because an exit-0 skip there would read as
//                             a green night and auto-close the tracking issue

import { spawnSync } from "node:child_process";
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
 * A --failure-dir value must stay inside the fuzz/failures* namespace of the
 * core package: the directory is recursively DELETED at startup, so anything
 * looser (an absolute path, a `.`/`..` or empty segment, or a plain name
 * like `src` or `fuzz/seeds`) could point the delete at tracked checkout
 * contents. The flag exists to redirect the OUTPUT, not to name arbitrary
 * directories.
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

export function parseOptions(argv: string[]): Options {
  const options: Options = {
    runs: 4096,
    maxTotalTime: 30,
    cmin: false,
    seed: undefined,
    failureDir: "fuzz/failures",
    requireToolchain: false,
  };
  for (const arg of argv) {
    if (arg === "--cmin") {
      options.cmin = true;
      continue;
    }
    if (arg === "--require-toolchain") {
      options.requireToolchain = true;
      continue;
    }
    const dir = /^--failure-dir=(.+)$/.exec(arg)?.[1];
    if (dir && isSafeFailureDir(dir)) {
      options.failureDir = dir;
      continue;
    }
    const match = /^--(runs|max-total-time|seed)=(\d+)$/.exec(arg);
    const value = Number(match?.[2]);
    // libFuzzer parses -runs/-max_total_time as signed 32-bit and -seed as
    // unsigned 32-bit; anything larger silently wraps (a wrapped seed of 0
    // means "random", the opposite of what the caller asked for).
    const limit = match?.[1] === "seed" ? 0xffffffff : 0x7fffffff;
    if (match && Number.isSafeInteger(value) && value > 0 && value <= limit) {
      if (match[1] === "runs") options.runs = value;
      else if (match[1] === "max-total-time") options.maxTotalTime = value;
      else options.seed = value;
      continue;
    }
    console.error(`error: invalid argument: ${arg}\n${usage}`);
    process.exit(2);
  }
  return options;
}

// Dictionaries steer mutation toward the target's input grammar. The
// structured targets (Arbitrary-derived input) get none - a byte dictionary
// is meaningless against the arbitrary encoding; the DER parser gets DER
// tag/length bytes; everything else - including any future target absent
// from these two lists - consumes JSON protocol frames, so the JSON
// dictionary is the deliberate default (a wrong dictionary only weakens
// mutation, never correctness). Every path is existence-guarded so the
// script works before the dictionaries land.
const noDictionary = new Set(["handshake_verify", "enclave_challenge"]);
const dictionaryOverrides = new Map([["enclave_der", "fuzz/dictionaries/der.dict"]]);
const defaultDictionary = "fuzz/dictionaries/json_protocol.dict";

// The structured targets take Arbitrary-derived input whose byte encoding is
// unstable across `arbitrary` versions, so a pinned seed file can silently
// stop meaning what it meant; their reports steer to a regression unit test
// instead of a seed.
const structuredTargets = noDictionary;

/** The filenames in `dir` with their mtimes (empty map when it is absent). */
export function snapshotDir(dir: string): Map<string, number> {
  if (!existsSync(dir)) return new Map();
  return new Map(readdirSync(dir).map((name) => [name, statSync(resolve(dir, name)).mtimeMs]));
}

/**
 * The names in `after` that are new or rewritten since `before`, sorted.
 * mtimes matter: libFuzzer names crash files by input hash, so a rerun of a
 * known crash OVERWRITES an existing file instead of adding one.
 */
export function newFiles(before: Map<string, number>, after: Map<string, number>): string[] {
  return [...after.entries()]
    .filter(([name, mtimeMs]) => before.get(name) !== mtimeMs)
    .map(([name]) => name)
    .sort();
}

/** How the crashed run ended, for the report ("status 77" / "signal SIGABRT"). */
export function describeExit(status: number | null, signal: string | null): string {
  return signal ? `signal ${signal}` : `status ${status ?? "unknown"}`;
}

export interface FailureInfo {
  target: string;
  /** "status N" or "signal SIG..." from describeExit. */
  exit: string;
  /** What crashed: the fuzz run itself, or the corpus minimization pass. */
  phase: "run" | "cmin";
  seed: number | undefined;
  runs: number;
  maxTotalTime: number;
  /** New files cargo-fuzz left in fuzz/artifacts/<target>/, repo-relative names only. */
  crashFiles: string[];
  /** Single-line base64 of the first crash file, when it is small enough. */
  crashBase64: string | undefined;
}

/** Inputs up to this size are embedded in the report as one base64 line, so
 * the reproducer outlives the workflow-artifact retention window while the
 * line stays well inside the issue body's per-failure budget. */
export const MAX_EMBED_BYTES = 3000;

/**
 * The failure report, following repo-platform's failure-report contract v1:
 * line 1 is a `# title` heading, and the body carries the exact replay
 * command in a fenced block, near the top so head-truncation keeps it.
 */
export function buildReport(info: FailureInfo): string {
  // cmin takes neither the seed nor -runs/-max_total_time, so its sentence
  // claims no configuration.
  const configuration = `seed ${info.seed ?? "none"}, -runs=${info.runs}, -max_total_time=${info.maxTotalTime}`;
  const lines: string[] = [
    `# fuzz: ${info.target} crashed`,
    "",
    info.phase === "cmin"
      ? `Corpus minimization (cargo fuzz cmin) crashed with ${info.exit}.`
      : `libFuzzer exited with ${info.exit} (${configuration}).`,
    "",
  ];

  // Pin --target to the nightly host triple, same as the script does: a
  // musl-prebuilt cargo-fuzz (taiki-e/install-action) defaults to a triple
  // ASan cannot link, and the substitution is correct on any machine.
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
      "that); re-run this pass's exact configuration instead:",
      "",
      "```bash",
      `bun scripts/fuzz-smoke.ts --runs=${info.runs} --max-total-time=${info.maxTotalTime}${info.seed !== undefined ? ` --seed=${info.seed}` : ""}${info.phase === "cmin" ? " --cmin" : ""}`,
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
      "Pin the input as a regression seed so every future run (nightly and",
      "local smoke) replays it first, which is what makes the tracking",
      "issue's auto-close on a later green night trustworthy:",
      "",
      "```bash",
      `mkdir -p src/packages/core/fuzz/seeds/${info.target}`,
      `cp src/packages/core/fuzz/artifacts/${info.target}/${primary} src/packages/core/fuzz/seeds/${info.target}/`,
      "```",
      "",
      "then commit the new seed file with the fix.",
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
  // parseOptions already constrains --failure-dir; this is the last line of
  // defense in front of the recursive delete below.
  if (!failureRoot.startsWith(`${core}/`) || failureRoot === core) {
    console.error(`error: failure dir escapes ${core}: ${failureRoot}`);
    return 2;
  }

  function dictionaryFor(target: string): string | undefined {
    if (noDictionary.has(target)) return undefined;
    const dictionary = dictionaryOverrides.get(target) ?? defaultDictionary;
    return existsSync(resolve(core, dictionary)) ? dictionary : undefined;
  }

  // Run one cargo +nightly fuzz subcommand. A spawn error (cargo itself
  // missing/broken) is fatal; the run's own exit status/signal is returned
  // for the caller to record as a target failure. `timeoutMs` bounds
  // subcommands with no wall-clock flag of their own (cmin): a hang there
  // would otherwise ride to the JOB timeout, which cancels the run and
  // skips the if:failure() reporting steps entirely.
  function cargoFuzz(
    args: string[],
    timeoutMs?: number,
  ): { status: number | null; signal: string | null } {
    const run = spawnSync("cargo", ["+nightly", "fuzz", ...args], {
      cwd: core,
      stdio: "inherit",
      timeout: timeoutMs,
    });
    // A timeout kill surfaces as an error (ETIMEDOUT) plus the kill signal;
    // that is a recordable failure of the subcommand, not a broken cargo.
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

  // Stale reports from an earlier run must never end up in a filed issue;
  // clear before the toolchain probes so even a skipping run cannot leave
  // yesterday's reports looking current.
  rmSync(failureRoot, { recursive: true, force: true });

  const toolchains = spawnSync("rustup", ["toolchain", "list"], {
    cwd: core,
    encoding: "utf8",
  });
  // Skip when rustup is missing, fails, or lists no nightly toolchain (the old
  // shell pipeline's `rustup ... | grep -q nightly` under pipefail skipped on a
  // rustup failure too, even if partial output mentioned nightly). Under
  // --require-toolchain a skip is a FAILURE: the nightly job passes the flag
  // because an exit-0 skip there would read as a green night and auto-close
  // the tracking issue without having fuzzed anything.
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

  // cargo-fuzz defaults --target to its own compile-time host triple, which is
  // wrong when it was installed as a prebuilt musl binary (taiki-e/install-action
  // in CI passes x86_64-unknown-linux-musl): ASan cannot link a statically
  // linked libc. Pin the target to the nightly toolchain's real host triple.
  const rustcInfo = spawnSync("rustc", ["+nightly", "-vV"], { cwd: core, encoding: "utf8" });
  const host =
    rustcInfo.status === 0 ? /^host: (\S+)$/m.exec(rustcInfo.stdout ?? "")?.[1] : undefined;
  if (!host) {
    console.error("error: could not determine the host triple from `rustc +nightly -vV`");
    return 1;
  }

  // The target list comes from cargo-fuzz itself so it cannot silently drift
  // from fuzz/Cargo.toml; an empty list means the fuzz workspace is broken.
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

  // Record one failure: write the contract report and copy the crash files
  // beside it, so the report survives even if the artifacts dir is not
  // uploaded whole.
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

  // The crash evidence for a target: the new/rewritten artifact files, plus
  // a base64 embed of the first one when it is small enough to ride in the
  // report.
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
  for (const target of targets) {
    console.log(`[fuzz-smoke] ${target}: ${options.runs} runs (target ${host})`);
    // Pass the corpus dir explicitly (libFuzzer needs it to exist) so the
    // committed seeds can ride along as a second corpus dir libFuzzer merges in.
    const corpus = `fuzz/corpus/${target}`;
    mkdirSync(resolve(core, corpus), { recursive: true });
    const runArgs = ["run", "--target", host, target, corpus];
    const seeds = `fuzz/seeds/${target}`;
    if (existsSync(resolve(core, seeds))) runArgs.push(seeds);
    runArgs.push("--", `-runs=${options.runs}`, `-max_total_time=${options.maxTotalTime}`);
    if (options.seed !== undefined) runArgs.push(`-seed=${options.seed}`);
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
      seed: options.seed,
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
      // cmin has no wall-clock flag of its own; normally seconds, so three
      // minutes is a hang, and a killed cmin is a recorded failure below.
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
        seed: options.seed,
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
