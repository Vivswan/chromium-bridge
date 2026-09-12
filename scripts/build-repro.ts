#!/usr/bin/env bun

// Deterministic release build of the chromium-bridge binary: byte-identical across clean rebuilds and checkout
// paths on one machine. Matching a hash built elsewhere also needs the rust-toolchain.toml toolchain via rustup
// (a distro/Homebrew rustc embeds different std paths) and the same platform SDK/linker; the release workflow
// builds with this script. See .github/SECURITY.md "Release artifact integrity".
//
//   --remap-path-prefix  -> the checkout, CARGO_HOME, and home paths rustc embeds become fixed placeholders
//   SOURCE_DATE_EPOCH    -> the last commit's timestamp unless the caller set it; nothing derives from the wall clock
//   --locked             -> refuses to build if Cargo.lock would change
//
// The arm64 macOS ad-hoc signature is linker-derived from the identical content, so the whole file still matches;
// signing with a real Apple identity would break byte equality and move macOS verification to comparing cdhashes.
//
// Self-contained (node builtins + Bun, no lib.ts import): the release workflow runs it before `bun install`.

import { spawnSync } from "node:child_process";
import { accessSync, constants } from "node:fs";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Repo root, derived from this file's location (scripts/ is a direct child).
const bbRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function bbDie(message: string, exitCode = 1): never {
  console.error(`error: ${message}`);
  process.exit(exitCode);
}

const env: Record<string, string | undefined> = { ...process.env };

// $HOME is both a cargo-location candidate and a remap prefix; refuse to guess if it is missing.
const home = env.HOME;
if (!home) bbDie("HOME is not set");

// Locate a cargo binary (PATH, then the common Homebrew / rustup spots) and
// prepend its directory to PATH so the rustc it shells out to is discoverable.
function findCargo(): string {
  for (const candidate of [
    "cargo",
    "/opt/homebrew/bin/cargo",
    join(home ?? "", ".cargo/bin/cargo"),
  ]) {
    if (candidate.includes("/") || candidate.includes("\\")) {
      try {
        accessSync(candidate, constants.X_OK);
        return candidate;
      } catch {
        // not there; try the next candidate
      }
    } else {
      const found = Bun.which(candidate);
      if (found) return found;
    }
  }
  bbDie("cargo not found. Install Rust (https://rustup.rs) or fix PATH.", 2);
}

const bbCargo = findCargo();
env.BB_CARGO = bbCargo;
const cargoDir = dirname(bbCargo);
const pathEntries = (env.PATH ?? "").split(delimiter);
if (!pathEntries.includes(cargoDir)) {
  env.PATH = `${cargoDir}${delimiter}${env.PATH ?? ""}`;
}

if (!env.SOURCE_DATE_EPOCH) {
  const git = spawnSync("git", ["-C", bbRoot, "log", "-1", "--pretty=%ct"], {
    encoding: "utf8",
  });
  if (git.error || git.status !== 0 || !git.stdout.trim()) {
    bbDie("not a git checkout and SOURCE_DATE_EPOCH is unset");
  }
  env.SOURCE_DATE_EPOCH = git.stdout.trim();
}

// Order matters: remap the most specific prefixes first, then $HOME as a
// catch-all so no user-identifying absolute path survives in the binary.
const cargoHomeDir = env.CARGO_HOME || join(home, ".cargo");
let rustflags = `${env.RUSTFLAGS ?? ""} --remap-path-prefix=${bbRoot}=/build`;
rustflags += ` --remap-path-prefix=${cargoHomeDir}=/cargo-home`;
rustflags += ` --remap-path-prefix=${home}=/home`;
env.RUSTFLAGS = rustflags;

// Printing the repro inputs IS this script's job: a commit timestamp and the
// path-remap flags built above, so two builders can diff them - not secrets.
console.error(`[build-repro] SOURCE_DATE_EPOCH=${env.SOURCE_DATE_EPOCH}`); // codeql[js/clear-text-logging]
console.error(`[build-repro] RUSTFLAGS=${env.RUSTFLAGS}`); // codeql[js/clear-text-logging]
const result = spawnSync(
  bbCargo,
  [
    "build",
    "--release",
    "--locked",
    "--manifest-path",
    join(bbRoot, "Cargo.toml"),
    ...process.argv.slice(2),
  ],
  { stdio: "inherit", env },
);
if (result.error) bbDie(`failed to run cargo: ${result.error.message}`);
// Re-raise a signal death so the caller sees a signal, not an exit code.
if (result.signal) process.kill(process.pid, result.signal);
process.exit(result.status ?? 1);
