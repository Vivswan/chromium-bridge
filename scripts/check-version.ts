#!/usr/bin/env bun
// Verify the version is consistent across the crate, the JS packages that surface it, and the
// release-please bookkeeping. Cargo.toml is the single source of truth (scripts/sync-version.ts
// propagates it); the bundled host's helper Info.plist is stamped at bundle time
// (scripts/desktop-bundle.ts), so it cannot go stale and is not checked here.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { cargoVersion, jsonVersion, repoRoot, versionedJsonFiles } from "./lib.ts";

const cargo = cargoVersion();

let failed = false;
console.log(`Cargo.toml               ${cargo}`);
for (const relativePath of versionedJsonFiles) {
  const pkg = jsonVersion(join(repoRoot, relativePath));
  console.log(`${relativePath}   ${pkg}`);
  if (pkg !== cargo) {
    console.error(`MISMATCH: ${relativePath} (${pkg}) != Cargo.toml (${cargo})`);
    failed = true;
  }
}

// Parsed once: the bootstrap tie below reads initial-version, the coverage
// check below reads extra-files.
const configPath = "release-please-config.json";
const config = JSON.parse(readFileSync(join(repoRoot, configPath), "utf8")) as {
  "initial-version"?: unknown;
  packages?: Record<
    string,
    { "extra-files"?: (string | { path?: unknown; type?: unknown; jsonpath?: unknown })[] }
  >;
};

// Before the first release the manifest deliberately holds 0.0.0 (the first release PR computes
// 0.0.0 -> initial-version); from then on it must track Cargo.toml. No offline marker in a checkout
// says whether that first release has happened (tags may be absent, and CHANGELOG.md predates
// release-please with its own 0.1.0 heading), so the 0.0.0 exemption never expires and, as an
// accepted residual, a post-release revert of the manifest to 0.0.0 passes here.
const bootstrapVersion = "0.0.0";
const manifestPath = ".release-please-manifest.json";
const manifest = JSON.parse(readFileSync(join(repoRoot, manifestPath), "utf8")) as Record<
  string,
  unknown
>;
const manifestVersion = manifest["."];
if (manifestVersion === undefined) {
  console.error(`MISSING: ${manifestPath} has no "." entry`);
  failed = true;
} else {
  console.log(`${manifestPath}   ${String(manifestVersion)}`);
  if (manifestVersion === bootstrapVersion) {
    const initial = config["initial-version"];
    if (initial !== cargo) {
      console.error(
        `MISMATCH: Cargo.toml (${cargo}) != ${configPath} initial-version (${String(initial)}) - ` +
          `while ${manifestPath} holds the ${bootstrapVersion} bootstrap, the first release PR stamps ` +
          "initial-version into every version copy, silently rewriting the Cargo version",
      );
      failed = true;
    }
  } else if (manifestVersion !== cargo) {
    console.error(
      `MISMATCH: ${manifestPath} ["."] (${String(manifestVersion)}) != Cargo.toml (${cargo}) ` +
        `and is not the ${bootstrapVersion} pre-first-release bootstrap`,
    );
    failed = true;
  }
}

// The release PR bumps only the files listed in extra-files, and
// release-please fails soft on a wrong updater (a bad type or jsonpath logs
// "No entries modified" and leaves the file unchanged), so each expected
// entry must both be present and carry the exact updater shape that hits its
// version field. Every entry matching an expected path is validated, and
// duplicates are rejected outright.
const extraFiles = config.packages?.["."]?.["extra-files"] ?? [];
const expectedUpdaters: [string, { type: string; jsonpath: string }][] = [
  ["Cargo.toml", { type: "toml", jsonpath: "$.workspace.package.version" }],
  ...versionedJsonFiles.map((path): [string, { type: string; jsonpath: string }] => [
    path,
    { type: "json", jsonpath: "$.version" },
  ]),
];
for (const [path, want] of expectedUpdaters) {
  const matches = extraFiles.filter((e) => (typeof e === "string" ? e : e.path) === path);
  if (matches.length === 0) {
    console.error(
      `MISSING: ${path} is not in ${configPath} extra-files (the release PR would not bump it)`,
    );
    failed = true;
    continue;
  }
  if (matches.length > 1) {
    console.error(
      `DUPLICATE: ${path} appears ${matches.length} times in ${configPath} extra-files`,
    );
    failed = true;
  }
  for (const entry of matches) {
    const got = typeof entry === "string" ? {} : entry;
    if (got.type !== want.type || got.jsonpath !== want.jsonpath) {
      console.error(
        `BAD UPDATER: ${path} in ${configPath} extra-files must be ` +
          `{ "type": "${want.type}", "jsonpath": "${want.jsonpath}" } ` +
          "(release-please fails soft on a wrong updater and silently skips the bump)",
      );
      failed = true;
    }
  }
}

if (!failed) console.log("versions consistent");
process.exit(failed ? 1 : 0);
