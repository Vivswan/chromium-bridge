#!/usr/bin/env bun
// Verify the version is consistent across the crate and the extension.
//
// Cargo.toml is the single source of truth. This checks that
// extension/manifest.json and extension/package.json agree with it, and fails
// (exit 1) on any mismatch. `scripts/sync-version.ts` propagates the Cargo
// version to the others.

import { join } from "node:path";
import { cargoVersion, jsonVersion, repoRoot } from "./lib.ts";

const cargo = cargoVersion();
const manifest = jsonVersion(join(repoRoot, "extension/manifest.json"));
const pkg = jsonVersion(join(repoRoot, "extension/package.json"));

console.log(`Cargo.toml               ${cargo}`);
console.log(`extension/manifest.json  ${manifest}`);
console.log(`extension/package.json   ${pkg}`);

let failed = false;
if (manifest !== cargo) {
  console.error(`MISMATCH: manifest.json (${manifest}) != Cargo.toml (${cargo})`);
  failed = true;
}
if (pkg !== cargo) {
  console.error(`MISMATCH: package.json (${pkg}) != Cargo.toml (${cargo})`);
  failed = true;
}

if (!failed) console.log("versions consistent");
process.exit(failed ? 1 : 0);
