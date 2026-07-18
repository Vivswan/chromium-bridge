#!/usr/bin/env bun
// Verify the version is consistent across the crate and the JS packages that
// surface it.
//
// Cargo.toml is the single source of truth. This checks that
// src/apps/extension/package.json (which the WXT-generated manifest takes its
// version from) and src/apps/desktop/ui/package.json (the control panel)
// agree with it, and fails (exit 1) on any mismatch.
// `scripts/sync-version.ts` propagates the Cargo version. The bundled host's
// helper Info.plist is stamped at bundle time (scripts/desktop-bundle.ts), so
// it cannot go stale and is not checked here.

import { join } from "node:path";
import { cargoVersion, jsonVersion, repoRoot } from "./lib.ts";

const cargo = cargoVersion();

let failed = false;
console.log(`Cargo.toml               ${cargo}`);
for (const relativePath of [
  "src/apps/extension/package.json",
  "src/apps/desktop/ui/package.json",
]) {
  const pkg = jsonVersion(join(repoRoot, relativePath));
  console.log(`${relativePath}   ${pkg}`);
  if (pkg !== cargo) {
    console.error(`MISMATCH: ${relativePath} (${pkg}) != Cargo.toml (${cargo})`);
    failed = true;
  }
}

if (!failed) console.log("versions consistent");
process.exit(failed ? 1 : 0);
