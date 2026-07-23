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
//   --runs=N                  iteration cap per target (default 4096)
//   --max-total-time=SECONDS  wall-clock cap per target (default 30)
//   --cmin                    minimize each target's corpus after the runs

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const usage = "usage: bun scripts/fuzz-smoke.ts [--runs=N] [--max-total-time=SECONDS] [--cmin]";

interface Options {
  runs: number;
  maxTotalTime: number;
  cmin: boolean;
}

function parseOptions(argv: string[]): Options {
  const options: Options = { runs: 4096, maxTotalTime: 30, cmin: false };
  for (const arg of argv) {
    if (arg === "--cmin") {
      options.cmin = true;
      continue;
    }
    const match = /^--(runs|max-total-time)=(\d+)$/.exec(arg);
    const value = Number(match?.[2]);
    if (match && Number.isSafeInteger(value) && value > 0) {
      if (match[1] === "runs") options.runs = value;
      else options.maxTotalTime = value;
      continue;
    }
    console.error(`error: invalid argument: ${arg}\n${usage}`);
    process.exit(2);
  }
  return options;
}

const options = parseOptions(process.argv.slice(2));
const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
// cargo-fuzz resolves the fuzz workspace from the crate that contains fuzz/,
// so run from the core package, not the repo root.
const core = resolve(repo, "src/packages/core");

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

function dictionaryFor(target: string): string | undefined {
  if (noDictionary.has(target)) return undefined;
  const dictionary = dictionaryOverrides.get(target) ?? defaultDictionary;
  return existsSync(resolve(core, dictionary)) ? dictionary : undefined;
}

// Run one cargo +nightly fuzz subcommand, propagating failure the way the
// old shell pipeline did: a signal-killed run (e.g. libFuzzer abort) exited
// with 128+signal via `set -e`, so re-raise the signal; any nonzero status
// exits with that status.
function cargoFuzz(args: string[]): void {
  const run = spawnSync("cargo", ["+nightly", "fuzz", ...args], { cwd: core, stdio: "inherit" });
  if (run.error) {
    console.error(`error: failed to run cargo fuzz: ${run.error.message}`);
    process.exit(1);
  }
  if (run.signal) process.kill(process.pid, run.signal);
  if (run.status !== 0) process.exit(run.status ?? 1);
}

const toolchains = spawnSync("rustup", ["toolchain", "list"], {
  cwd: core,
  encoding: "utf8",
});
// Skip when rustup is missing, fails, or lists no nightly toolchain (the old
// shell pipeline's `rustup ... | grep -q nightly` under pipefail skipped on a
// rustup failure too, even if partial output mentioned nightly).
if (toolchains.error || toolchains.status !== 0 || !toolchains.stdout?.includes("nightly")) {
  console.log(
    "[fuzz-smoke] SKIP: no nightly toolchain (install with: rustup toolchain install nightly)",
  );
  process.exit(0);
}
const cargoFuzzProbe = spawnSync("cargo", ["+nightly", "fuzz", "--help"], {
  cwd: core,
  stdio: "ignore",
});
if (cargoFuzzProbe.error || cargoFuzzProbe.status !== 0) {
  console.log(
    "[fuzz-smoke] SKIP: cargo-fuzz not installed (install with: cargo install cargo-fuzz)",
  );
  process.exit(0);
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
  process.exit(1);
}

// The target list comes from cargo-fuzz itself so it cannot silently drift
// from fuzz/Cargo.toml; an empty list means the fuzz workspace is broken.
const list = spawnSync("cargo", ["+nightly", "fuzz", "list"], { cwd: core, encoding: "utf8" });
if (list.error || list.status !== 0) {
  console.error("error: `cargo +nightly fuzz list` failed");
  process.exit(1);
}
const targets = (list.stdout ?? "")
  .split("\n")
  .map((line) => line.trim())
  .filter((line) => line.length > 0);
if (targets.length === 0) {
  console.error("error: `cargo +nightly fuzz list` returned no targets");
  process.exit(1);
}

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
  const dictionary = dictionaryFor(target);
  if (dictionary) runArgs.push(`-dict=${dictionary}`);
  cargoFuzz(runArgs);
}
console.log(`[fuzz-smoke] all targets survived ${options.runs} runs each`);

if (options.cmin) {
  for (const target of targets) {
    console.log(`[fuzz-smoke] ${target}: minimizing corpus`);
    cargoFuzz(["cmin", "--target", host, target]);
  }
}
