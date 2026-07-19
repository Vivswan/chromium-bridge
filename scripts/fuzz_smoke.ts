#!/usr/bin/env bun

// Fuzz smoke test for the wire parsers (chromium-bridge).
//
// Builds every cargo-fuzz target and runs each for a short, bounded number of
// iterations, purely to prove the harnesses build and survive a quick blast of
// random input. This is a smoke check, NOT a real fuzzing campaign: continuous
// fuzzing (long runs, corpus, OSS-Fuzz) is a separate, nightly/CI concern.
//
// Requirements: a nightly toolchain and cargo-fuzz (libFuzzer). If either is
// missing the script SKIPS (exit 0) rather than failing, so it can sit in a
// stable-only gate harmlessly; wire it into a nightly job to make it load-bearing.
//
// Deliberately self-contained (node builtins only, no lib.ts import) so it
// runs without a `bun install`.
//
// Usage: bun scripts/fuzz_smoke.ts [runs]   (default 4096 iterations per target)

import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const runs = process.argv[2] ?? "4096";
const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
// cargo-fuzz resolves the fuzz workspace from the crate that contains fuzz/,
// so run from the core package, not the repo root.
const core = resolve(repo, "src/packages/core");

const toolchains = spawnSync("rustup", ["toolchain", "list"], {
  cwd: core,
  encoding: "utf8",
});
if (toolchains.error || !toolchains.stdout?.includes("nightly")) {
  console.log(
    "[fuzz-smoke] SKIP: no nightly toolchain (install with: rustup toolchain install nightly)",
  );
  process.exit(0);
}
const cargoFuzz = spawnSync("cargo", ["+nightly", "fuzz", "--help"], {
  cwd: core,
  stdio: "ignore",
});
if (cargoFuzz.error || cargoFuzz.status !== 0) {
  console.log(
    "[fuzz-smoke] SKIP: cargo-fuzz not installed (install with: cargo install cargo-fuzz)",
  );
  process.exit(0);
}

const targets = ["nm_frame", "mcp_jsonrpc", "bridge_envelope", "handshake", "attach"];
for (const target of targets) {
  console.log(`[fuzz-smoke] ${target}: ${runs} runs`);
  const run = spawnSync(
    "cargo",
    ["+nightly", "fuzz", "run", target, "--", `-runs=${runs}`, "-max_total_time=30"],
    { cwd: core, stdio: "inherit" },
  );
  if (run.error) {
    console.error(`error: failed to run cargo fuzz: ${run.error.message}`);
    process.exit(1);
  }
  if (run.status !== 0) process.exit(run.status ?? 1);
}
console.log(`[fuzz-smoke] all targets survived ${runs} runs each`);
