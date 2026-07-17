#!/usr/bin/env bun
// Propagate the crate version (Cargo.toml, the source of truth) into the
// extension manifest and package files, then verify consistency.
//
// Usage: bump the version in Cargo.toml, then run `just sync-version`
// (or `bun scripts/sync-version.ts`) and commit the result.

import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { cargoVersion, die, repoRoot } from "./lib.ts";

const cargo = cargoVersion();
console.log(`Cargo.toml version: ${cargo}`);

// Replace the "version": "..." string in place, preserving the file's exact
// formatting. ("manifest_version" is a distinct key and is not matched.)
function setJsonVersion(relativePath: string) {
  const path = join(repoRoot, relativePath);
  const source = readFileSync(path, "utf8");
  const updated = source.replace(/("version"\s*:\s*")[^"]+(")/, `$1${cargo}$2`);
  if (updated === source && !source.includes(`"version": "${cargo}"`)) {
    die(`no "version" field found in ${relativePath}`);
  }
  writeFileSync(path, updated);
  console.log(`updated ${relativePath}`);
}

setJsonVersion("extension/manifest.json");
setJsonVersion("extension/package.json");

// Refresh bun.lock so the workspace lockfile records the new version.
const install = spawnSync("bun", ["install"], { cwd: repoRoot, stdio: "inherit" });
if (install.status !== 0) die("bun install failed while refreshing bun.lock");

const check = spawnSync("bun", [join(repoRoot, "scripts/check-version.ts")], {
  cwd: repoRoot,
  stdio: "inherit",
});
process.exit(check.status ?? 1);
