#!/usr/bin/env bun
// Verify the version is consistent across the crate and the extension.
//
// Cargo.toml is the single source of truth. This checks that
// src/apps/extension/package.json (which the WXT-generated manifest takes its version
// from) agrees with it, and fails (exit 1) on any mismatch.
// `scripts/sync-version.ts` propagates the Cargo version.

import { join } from "node:path";
import { cargoVersion, jsonVersion, repoRoot } from "./lib.ts";

const cargo = cargoVersion();
const pkg = jsonVersion(join(repoRoot, "src/apps/extension/package.json"));

console.log(`Cargo.toml               ${cargo}`);
console.log(`src/apps/extension/package.json   ${pkg}`);

let failed = false;
if (pkg !== cargo) {
  console.error(`MISMATCH: package.json (${pkg}) != Cargo.toml (${cargo})`);
  failed = true;
}

if (!failed) console.log("versions consistent");
process.exit(failed ? 1 : 0);
