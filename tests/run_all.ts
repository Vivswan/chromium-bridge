#!/usr/bin/env bun
// Run all chromium-bridge tests: protocol layer (e2e.py) + DOM layer (dom_test.ts).
// Exits 0 only if ALL tests pass.
//
// Requirements:
//   - Rust toolchain (cargo) for building the release binary
//   - Python 3 for tests/e2e.py
//   - bun + Chrome for tests/dom_test.ts and tests/ext_test.ts
//     (set CHROME_BIN to override the path)
//
// Each layer is independent; failures in one still let the others run so you
// see all problems in one pass - hence failures are collected, not fatal.

import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..");
let failed = false;

// Locate cargo: PATH first, then the common Homebrew / rustup install spots
// (same candidate order as the old scripts/lib.sh helper).
function findCargo(): string {
  for (const candidate of [
    "cargo",
    "/opt/homebrew/bin/cargo",
    join(process.env.HOME ?? "", ".cargo/bin/cargo"),
  ]) {
    const resolved = Bun.which(candidate);
    if (resolved) return resolved;
  }
  console.error("error: cargo not found. Install Rust (https://rustup.rs) or fix PATH.");
  process.exit(2);
}

function run(cmd: string[], env?: Record<string, string>): boolean {
  const proc = Bun.spawnSync(cmd, {
    cwd: repo,
    stdout: "inherit",
    stderr: "inherit",
    env: { ...process.env, ...env },
  });
  return proc.exitCode === 0;
}

const cargo = findCargo();
// Put cargo's directory on PATH so the rustc it shells out to is discoverable.
const cargoDir = dirname(cargo);
if (!(process.env.PATH ?? "").split(":").includes(cargoDir)) {
  process.env.PATH = `${cargoDir}:${process.env.PATH}`;
}

console.log("=== chromium-bridge test suite ===");
console.log("(1/4) build release binary");
if (!run([cargo, "build", "--release", "--manifest-path", join(repo, "Cargo.toml")])) {
  console.error("BUILD FAILED");
  process.exit(1);
}

console.log("");
console.log("(2/4) build extension bundle (esbuild)");
// The DOM + smoke tests exercise the BUILT extension/dist/, so build it first.
if (!existsSync(join(repo, "node_modules"))) {
  run(["bun", "install"]);
}
if (!run(["bun", "run", "--cwd", join(repo, "extension"), "build"])) {
  console.error("EXTENSION BUILD FAILED");
  failed = true;
}

console.log("");
console.log("(3/4) protocol-layer tests (tests/e2e.py)");
if (!run(["python3", join(here, "e2e.py")])) {
  console.error("PROTOCOL TESTS FAILED");
  failed = true;
}

console.log("");
console.log("(4/4) DOM-layer + smoke tests");
// SAFETY: browser tests must run against an ISOLATED browser (Chrome for
// Testing / Chromium via CHROME_BIN), never your daily Chrome - a non-headless
// --load-extension launch can capture and close your real session. We do NOT
// default CHROME_BIN to the system Chrome; if it's unset, skip the browser suite.
const chromeBin = process.env.CHROME_BIN;
if (!existsSync(join(repo, "extension/dist"))) {
  console.log("  SKIP  extension/dist missing (build step above did not run)");
} else if (!chromeBin) {
  console.log("  SKIP  browser tests: set CHROME_BIN to an isolated Chrome for Testing /");
  console.log("        Chromium binary (NOT your daily Chrome). See tests/README.md -> Safety.");
} else if (!Bun.which(chromeBin)) {
  console.log(`  SKIP  CHROME_BIN not executable: ${chromeBin}`);
} else {
  if (!run(["bun", join(here, "dom_test.ts")], { CHROME_BIN: chromeBin })) {
    console.error("DOM TESTS FAILED");
    failed = true;
  }
  if (!run(["bun", join(here, "ext_test.ts")], { CHROME_BIN: chromeBin })) {
    console.error("SMOKE TEST FAILED");
    failed = true;
  }
}

console.log("");
console.log(failed ? "=== SOME TESTS FAILED ===" : "=== ALL TESTS PASSED ===");
process.exit(failed ? 1 : 0);
